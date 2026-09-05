"""Inspect, validate, and compare the Gate 01 kernel RPM set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
from typing import Any, Sequence


SCHEMA_VERSION = 1
KERNEL_VERSION = "6.18.48"
KERNEL_RELEASE = "6.18.48-1.openmythos.fc44.x86_64"
RPM_RELEASE = "1.openmythos.fc44"
MODULE_SIGNER = "OpenMythos Gate 01 Development Module Key"
EXPECTED_BINARY_NAMES = (
    "kernel-openmythos",
    "kernel-openmythos-core",
    "kernel-openmythos-modules",
)
EXPECTED_SOURCE_NEVRA = "kernel-openmythos-6.18.48-1.openmythos.fc44.src"
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODE_RE = re.compile(r"^[0-7]{4}$")
COMPRESSED_MODULE_RE = re.compile(r"\.ko\.(?:bz2|gz|lz4|lzo|xz|zst)$")
PRIVATE_KEY_SUFFIXES = (".key", ".p12", ".pfx", ".pk8", ".pkey", ".priv", ".private")
PRIVATE_KEY_MARKER = b"PRIVATE KEY"
FIELD_SEPARATOR = "\x1f"
RECORD_SEPARATOR = "\x1e"

MANIFEST_FIELDS = {
    "schema_version",
    "kernel_release",
    "source_rpms",
    "binary_rpms",
}
SOURCE_PACKAGE_FIELDS = {
    "name",
    "epoch",
    "version",
    "release",
    "architecture",
    "nevra",
    "sha256",
}
BINARY_PACKAGE_FIELDS = SOURCE_PACKAGE_FIELDS | {"files"}
REGULAR_FILE_FIELDS = {
    "path",
    "type",
    "mode",
    "size",
    "user",
    "group",
    "sha256",
    "private_key_marker",
}
MODULE_FILE_FIELDS = REGULAR_FILE_FIELDS | {"signer", "sig_id", "vermagic"}
SYMLINK_FIELDS = {
    "path",
    "type",
    "mode",
    "size",
    "user",
    "group",
    "link_target",
}


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_exact_fields(
    value: dict[str, Any], expected: set[str], description: str
) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown or missing:
        raise ValueError(
            f"{description} unknown fields={sorted(unknown)} "
            f"missing={sorted(missing)}"
        )


def load_rpm_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
    )
    if not isinstance(value, dict):
        raise ValueError("RPM manifest root must be an object")
    return value


def _validate_absolute_payload_path(path: str) -> PurePosixPath:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("RPM payload path must be absolute")
    pure = PurePosixPath(path)
    if "." in pure.parts or ".." in pure.parts or pure.as_posix() != path:
        raise ValueError(
            f"RPM payload path is not normalized or escapes its release tree: {path!r}"
        )
    return pure


def _inside_release_tree(path: PurePosixPath) -> bool:
    release_root = PurePosixPath("/usr/lib/modules") / KERNEL_RELEASE
    try:
        path.relative_to(release_root)
    except ValueError:
        return False
    return path != release_root


def _validate_symlink_target(path: PurePosixPath, target: str) -> None:
    if not isinstance(target, str) or not target or "\x00" in target:
        raise ValueError(f"invalid symlink target for {path}")
    if target.startswith("/"):
        combined = PurePosixPath(target)
    else:
        combined = path.parent / target
    normalized_parts: list[str] = []
    for part in combined.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            if not normalized_parts:
                raise ValueError(f"symlink target escapes release tree: {path}")
            normalized_parts.pop()
        else:
            normalized_parts.append(part)
    normalized = PurePosixPath("/", *normalized_parts)
    if not _inside_release_tree(normalized):
        raise ValueError(f"symlink target escapes release tree: {path}")


def _validate_file_record(record: Any, package_name: str) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{package_name} file record must be an object")
    path_value = record.get("path")
    path = _validate_absolute_payload_path(path_value)
    if package_name in EXPECTED_BINARY_NAMES[1:] and not _inside_release_tree(path):
        raise ValueError(f"{package_name} file is outside kernel release tree: {path}")
    if path.as_posix().lower().endswith(PRIVATE_KEY_SUFFIXES):
        raise ValueError(f"private-key suffix is forbidden in RPM payload: {path}")
    if COMPRESSED_MODULE_RE.search(path.as_posix()):
        raise ValueError(f"compressed module is forbidden: {path}")

    record_type = record.get("type")
    is_module = path.as_posix().endswith(".ko")
    if record_type == "file":
        expected_fields = MODULE_FILE_FIELDS if is_module else REGULAR_FILE_FIELDS
    elif record_type == "symlink":
        expected_fields = SYMLINK_FIELDS
    else:
        raise ValueError(f"unsupported RPM payload type for {path}: {record_type!r}")
    _require_exact_fields(record, expected_fields, f"file record {path}")

    if not isinstance(record["mode"], str) or not MODE_RE.fullmatch(record["mode"]):
        raise ValueError(f"invalid mode for {path}")
    if type(record["size"]) is not int or record["size"] < 0:
        raise ValueError(f"invalid size for {path}")
    for field in ("user", "group"):
        if not isinstance(record[field], str) or not record[field]:
            raise ValueError(f"invalid {field} for {path}")

    if record_type == "symlink":
        _validate_symlink_target(path, record["link_target"])
        return

    if not isinstance(record["sha256"], str) or not RAW_SHA256_RE.fullmatch(
        record["sha256"]
    ):
        raise ValueError(f"invalid file SHA-256 for {path}")
    if type(record["private_key_marker"]) is not bool:
        raise ValueError(f"private_key_marker must be boolean for {path}")
    if record["private_key_marker"]:
        raise ValueError(f"PRIVATE KEY marker found in RPM payload: {path}")

    if is_module:
        if record["signer"] != MODULE_SIGNER:
            raise ValueError(f"module signer mismatch for {path}")
        if record["sig_id"] != "PKCS#7":
            raise ValueError(f"module sig_id mismatch for {path}")
        vermagic = record["vermagic"]
        if not isinstance(vermagic, str) or not vermagic.startswith(KERNEL_RELEASE):
            raise ValueError(f"module vermagic mismatch for {path}")


def _expected_nevra(name: str, architecture: str) -> str:
    return f"{name}-{KERNEL_VERSION}-{RPM_RELEASE}.{architecture}"


def normalize_source_package_identity(package: dict[str, Any]) -> dict[str, Any]:
    """Normalize an SRPM's build-architecture header to its source identity."""
    normalized = dict(package)
    normalized["architecture"] = "src"
    normalized["nevra"] = (
        f"{package['name']}-{package['version']}-{package['release']}.src"
    )
    return normalized


def _validate_package(
    package: Any, *, source: bool, expected_name: str | None = None
) -> None:
    description = "source RPM" if source else "binary RPM"
    if not isinstance(package, dict):
        raise ValueError(f"{description} record must be an object")
    _require_exact_fields(
        package,
        SOURCE_PACKAGE_FIELDS if source else BINARY_PACKAGE_FIELDS,
        description,
    )
    if source:
        if package["name"] != "kernel-openmythos":
            raise ValueError("unexpected source RPM name")
        if package["architecture"] != "src":
            raise ValueError("source RPM architecture must be src")
    else:
        if package["name"] != expected_name:
            raise ValueError("binary RPM names must be exact and sorted")
        if package["architecture"] != "x86_64":
            raise ValueError("binary RPM architecture must be x86_64")
    if package["epoch"] != "0":
        raise ValueError(f"{description} epoch must be 0")
    if package["version"] != KERNEL_VERSION or package["release"] != RPM_RELEASE:
        raise ValueError(f"{description} version/release mismatch")
    expected_nevra = _expected_nevra(package["name"], package["architecture"])
    if package["nevra"] != expected_nevra:
        raise ValueError(f"{description} NEVRA mismatch")
    if not isinstance(package["sha256"], str) or not RAW_SHA256_RE.fullmatch(
        package["sha256"]
    ):
        raise ValueError(f"{description} SHA-256 is invalid")

    if source:
        return
    files = package["files"]
    if not isinstance(files, list):
        raise ValueError(f"{description} files must be an array")
    paths = [file.get("path") if isinstance(file, dict) else None for file in files]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError(f"{description} file paths must be sorted and unique")
    for record in files:
        _validate_file_record(record, package["name"])
    if package["name"] == "kernel-openmythos" and files:
        raise ValueError("kernel-openmythos meta package must own no files")


def validate_rpm_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("RPM manifest must be an object")
    _require_exact_fields(manifest, MANIFEST_FIELDS, "RPM manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("RPM manifest schema_version must be 1")
    if manifest["kernel_release"] != KERNEL_RELEASE:
        raise ValueError("unexpected kernel release")
    sources = manifest["source_rpms"]
    binaries = manifest["binary_rpms"]
    if not isinstance(sources, list) or len(sources) != 1:
        raise ValueError("RPM manifest must contain exactly one source RPM")
    if not isinstance(binaries, list):
        raise ValueError("binary_rpms must be an array")

    package_records = [*sources, *binaries]
    nevras = [
        package.get("nevra") if isinstance(package, dict) else None
        for package in package_records
    ]
    if len(nevras) != len(set(nevras)):
        raise ValueError("duplicate NEVRA in RPM manifest")

    _validate_package(sources[0], source=True)
    if sources[0]["nevra"] != EXPECTED_SOURCE_NEVRA:
        raise ValueError("unexpected source RPM NEVRA")
    names = [
        package.get("name") if isinstance(package, dict) else None
        for package in binaries
    ]
    if names != list(EXPECTED_BINARY_NAMES):
        raise ValueError("binary RPM names must be exact and sorted")
    for package, expected_name in zip(binaries, EXPECTED_BINARY_NAMES, strict=True):
        _validate_package(package, source=False, expected_name=expected_name)


def _installed_file_view(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"nevra": package["nevra"], "files": package["files"]}
        for package in manifest["binary_rpms"]
    ]


def _module_signature_view(manifest: dict[str, Any]) -> list[dict[str, str]]:
    signatures: list[dict[str, str]] = []
    for package in manifest["binary_rpms"]:
        for record in package["files"]:
            if record["type"] == "file" and record["path"].endswith(".ko"):
                signatures.append(
                    {
                        "path": record["path"],
                        "sig_id": record["sig_id"],
                        "signer": record["signer"],
                        "vermagic": record["vermagic"],
                    }
                )
    return signatures


def compare_rpm_manifests(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    validate_rpm_manifest(left)
    validate_rpm_manifest(right)
    source_rpm = "pass" if left["source_rpms"] == right["source_rpms"] else "fail"
    left_nevras = [
        package["nevra"] for package in [*left["source_rpms"], *left["binary_rpms"]]
    ]
    right_nevras = [
        package["nevra"]
        for package in [*right["source_rpms"], *right["binary_rpms"]]
    ]
    package_nevras = "pass" if left_nevras == right_nevras else "fail"
    installed_files = (
        "pass"
        if _installed_file_view(left) == _installed_file_view(right)
        else "fail"
    )
    module_signatures = (
        "pass"
        if _module_signature_view(left) == _module_signature_view(right)
        else "fail"
    )
    advisory: list[dict[str, str]] = []
    for left_package, right_package in zip(
        left["binary_rpms"], right["binary_rpms"], strict=True
    ):
        if left_package["sha256"] != right_package["sha256"]:
            advisory.append(
                {
                    "nevra": left_package["nevra"],
                    "left_sha256": left_package["sha256"],
                    "right_sha256": right_package["sha256"],
                }
            )
    hard_results = (source_rpm, package_nevras, installed_files, module_signatures)
    return {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "source_rpm": source_rpm,
        "package_nevras": package_nevras,
        "installed_files": installed_files,
        "module_signatures": module_signatures,
        "advisory_binary_rpm_hash_differences": advisory,
        "verdict": "pass" if all(result == "pass" for result in hard_results) else "fail",
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contains_private_key_marker(path: Path) -> bool:
    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            combined = carry + chunk
            if PRIVATE_KEY_MARKER in combined:
                return True
            carry = combined[-(len(PRIVATE_KEY_MARKER) - 1) :]
    return False


def _run_text(arguments: Sequence[str], *, cwd: Path | None = None) -> str:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _query_package(path: Path) -> dict[str, str]:
    query = FIELD_SEPARATOR.join(
        (
            "%{NAME}",
            "%{EPOCH}",
            "%{VERSION}",
            "%{RELEASE}",
            "%{ARCH}",
            "%{NEVRA}",
        )
    )
    fields = _run_text(("rpm", "-qp", "--qf", query, os.fspath(path))).split(
        FIELD_SEPARATOR
    )
    if len(fields) != 6:
        raise ValueError(f"unexpected RPM package query output for {path}")
    name, epoch, version, release, architecture, nevra = fields
    if epoch in ("", "(none)"):
        epoch = "0"
    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "architecture": architecture,
        "nevra": nevra,
        "sha256": _sha256_file(path),
    }


def _query_file_headers(path: Path) -> list[dict[str, Any]]:
    query = "[" + FIELD_SEPARATOR.join(
        (
            "%{FILENAMES}",
            "%{FILEMODES}",
            "%{FILESIZES}",
            "%{FILEUSERNAME}",
            "%{FILEGROUPNAME}",
            "%{FILELINKTOS}",
        )
    ) + RECORD_SEPARATOR + "]"
    output = _run_text(("rpm", "-qp", "--qf", query, os.fspath(path)))
    headers: list[dict[str, Any]] = []
    for raw_record in output.split(RECORD_SEPARATOR):
        if not raw_record:
            continue
        fields = raw_record.split(FIELD_SEPARATOR)
        if len(fields) != 6:
            raise ValueError(f"unexpected RPM file query output for {path}")
        filename, raw_mode, raw_size, user, group, link_target = fields
        try:
            mode = int(raw_mode, 10)
            size = int(raw_size, 10)
        except ValueError as error:
            raise ValueError(f"invalid RPM file metadata for {filename}") from error
        headers.append(
            {
                "path": filename,
                "raw_mode": mode,
                "size": size,
                "user": user,
                "group": group,
                "link_target": link_target,
            }
        )
    return headers


def _validate_pre_extraction_paths(
    rpm_path: Path, headers: list[dict[str, Any]]
) -> None:
    listing = _run_text(("rpm", "-qpl", os.fspath(rpm_path))).splitlines()
    if listing == ["(contains no files)"]:
        listing = []
    for listed_path in listing:
        _validate_absolute_payload_path(listed_path)
    header_paths = [header["path"] for header in headers]
    normalized_header_paths: list[PurePosixPath] = []
    symlink_paths: list[PurePosixPath] = []
    for header in headers:
        header_path = _validate_absolute_payload_path(header["path"])
        normalized_header_paths.append(header_path)
        file_type = stat.S_IFMT(header["raw_mode"])
        if file_type not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK):
            raise ValueError(
                f"unsupported special RPM payload file before extraction: {header_path}"
            )
        if file_type == stat.S_IFLNK:
            _validate_symlink_target(header_path, header["link_target"])
            symlink_paths.append(header_path)
    if listing != header_paths:
        raise ValueError(f"RPM path listing/header mismatch for {rpm_path}")
    if len(header_paths) != len(set(header_paths)):
        raise ValueError(f"duplicate RPM payload path in {rpm_path}")
    for header_path in normalized_header_paths:
        if any(symlink in header_path.parents for symlink in symlink_paths):
            raise ValueError(
                f"RPM payload path is below payload symlink before extraction: "
                f"{header_path}"
            )


def _extract_rpm(rpm_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    with tempfile.TemporaryFile() as rpm_stderr:
        rpm2cpio = subprocess.Popen(
            ["rpm2cpio", os.fspath(rpm_path)],
            stdout=subprocess.PIPE,
            stderr=rpm_stderr,
        )
        assert rpm2cpio.stdout is not None
        try:
            cpio = subprocess.run(
                [
                    "cpio",
                    "--extract",
                    "--make-directories",
                    "--preserve-modification-time",
                ],
                cwd=destination,
                stdin=rpm2cpio.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        finally:
            rpm2cpio.stdout.close()
        rpm_returncode = rpm2cpio.wait()
        if rpm_returncode != 0:
            rpm_stderr.seek(0)
            message = rpm_stderr.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"rpm2cpio failed for {rpm_path}: {message}")
    if cpio.returncode != 0:
        message = cpio.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"cpio failed for {rpm_path}: {message}")


def _extracted_non_directories(root: Path) -> set[str]:
    paths: set[str] = set()
    for current, directory_names, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in directory_names:
            candidate = current_path / name
            if candidate.is_symlink():
                paths.add("/" + candidate.relative_to(root).as_posix())
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in filenames:
            paths.add("/" + (current_path / name).relative_to(root).as_posix())
    return paths


def _inspect_payload_file(header: dict[str, Any], extract_root: Path) -> dict[str, Any] | None:
    path = _validate_absolute_payload_path(header["path"])
    raw_mode = header["raw_mode"]
    file_type = stat.S_IFMT(raw_mode)
    if file_type == stat.S_IFDIR:
        return None
    if file_type not in (stat.S_IFREG, stat.S_IFLNK):
        raise ValueError(f"unsupported special RPM payload file: {path}")
    extracted = extract_root.joinpath(*path.parts[1:])
    observed = extracted.lstat()
    if stat.S_IFMT(observed.st_mode) != file_type:
        raise ValueError(f"extracted file type differs from RPM header: {path}")
    mode = f"{stat.S_IMODE(raw_mode):04o}"
    if stat.S_IMODE(observed.st_mode) != stat.S_IMODE(raw_mode):
        raise ValueError(f"extracted file mode differs from RPM header: {path}")
    record: dict[str, Any] = {
        "path": path.as_posix(),
        "type": "symlink" if file_type == stat.S_IFLNK else "file",
        "mode": mode,
        "size": header["size"],
        "user": header["user"],
        "group": header["group"],
    }
    if file_type == stat.S_IFLNK:
        target = os.readlink(extracted)
        if target != header["link_target"]:
            raise ValueError(f"extracted symlink target differs from RPM header: {path}")
        record["link_target"] = target
        return record
    if observed.st_size != header["size"]:
        raise ValueError(f"extracted file size differs from RPM header: {path}")
    record["sha256"] = _sha256_file(extracted)
    record["private_key_marker"] = _contains_private_key_marker(extracted)
    if path.as_posix().endswith(".ko"):
        record.update(
            {
                "signer": _run_text(("modinfo", "-F", "signer", os.fspath(extracted))).strip(),
                "sig_id": _run_text(("modinfo", "-F", "sig_id", os.fspath(extracted))).strip(),
                "vermagic": _run_text(("modinfo", "-F", "vermagic", os.fspath(extracted))).strip(),
            }
        )
    return record


def inspect_rpm_set(
    rpm_dir: Path, srpm_dir: Path, output: Path, extract_root: Path
) -> dict[str, Any]:
    binary_paths = sorted(rpm_dir.glob("*.rpm"))
    source_paths = sorted(srpm_dir.glob("*.rpm"))
    if extract_root.exists():
        if not extract_root.is_dir() or any(extract_root.iterdir()):
            raise ValueError("extract root must be an absent or empty directory")
    else:
        extract_root.mkdir(mode=0o755, parents=True)

    sources = [
        normalize_source_package_identity(_query_package(path))
        for path in source_paths
    ]
    binaries: list[dict[str, Any]] = []
    for rpm_path in binary_paths:
        package = _query_package(rpm_path)
        headers = _query_file_headers(rpm_path)
        _validate_pre_extraction_paths(rpm_path, headers)
        package_extract_root = extract_root / package["name"]
        _extract_rpm(rpm_path, package_extract_root)
        expected_non_directories = {
            header["path"]
            for header in headers
            if stat.S_IFMT(header["raw_mode"]) != stat.S_IFDIR
        }
        observed_non_directories = _extracted_non_directories(package_extract_root)
        if expected_non_directories != observed_non_directories:
            raise ValueError(f"extracted RPM payload differs from header: {rpm_path}")
        records = [
            record
            for header in headers
            if (record := _inspect_payload_file(header, package_extract_root)) is not None
        ]
        package["files"] = sorted(records, key=lambda record: record["path"])
        binaries.append(package)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "source_rpms": sorted(sources, key=lambda package: package["nevra"]),
        "binary_rpms": sorted(binaries, key=lambda package: package["name"]),
    }
    validate_rpm_manifest(manifest)
    installed_files = {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "packages": _installed_file_view(manifest),
    }
    _atomic_write_json(output.with_name("installed-files.json"), installed_files)
    _atomic_write_json(output, manifest)
    return manifest


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _inspect_command(arguments: argparse.Namespace) -> int:
    inspect_rpm_set(
        arguments.rpm_dir,
        arguments.srpm_dir,
        arguments.output,
        arguments.extract_root,
    )
    return 0


def _validate_command(arguments: argparse.Namespace) -> int:
    validate_rpm_manifest(load_rpm_manifest(arguments.manifest))
    return 0


def _compare_command(arguments: argparse.Namespace) -> int:
    comparison = compare_rpm_manifests(
        load_rpm_manifest(arguments.left), load_rpm_manifest(arguments.right)
    )
    _atomic_write_json(arguments.output, comparison)
    return 0 if comparison["verdict"] == "pass" else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--rpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--srpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--output", required=True, type=Path)
    inspect_parser.add_argument("--extract-root", required=True, type=Path)
    inspect_parser.set_defaults(handler=_inspect_command)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.set_defaults(handler=_validate_command)

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--left", required=True, type=Path)
    compare_parser.add_argument("--right", required=True, type=Path)
    compare_parser.add_argument("--output", required=True, type=Path)
    compare_parser.set_defaults(handler=_compare_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
