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
RELEASE_ROOT = PurePosixPath("/usr/lib/modules") / KERNEL_RELEASE
EXPECTED_SOURCE_FILENAME = (
    "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
)
EXPECTED_BINARY_NAMES = (
    "kernel-openmythos",
    "kernel-openmythos-core",
    "kernel-openmythos-modules",
)
EXPECTED_SOURCE_NEVRA = "kernel-openmythos-6.18.48-1.openmythos.fc44.src"
REQUIRED_CORE_PATHS = frozenset(
    (RELEASE_ROOT / name).as_posix()
    for name in (
        "System.map",
        "config",
        "modules.builtin",
        "modules.builtin.alias.bin",
        "modules.builtin.bin",
        "modules.builtin.modinfo",
        "vmlinuz",
    )
)
REQUIRED_MODULE_METADATA_PATHS = frozenset(
    (RELEASE_ROOT / name).as_posix()
    for name in (
        "modules.alias",
        "modules.alias.bin",
        "modules.dep",
        "modules.dep.bin",
        "modules.devname",
        "modules.order",
        "modules.softdep",
        "modules.symbols",
        "modules.symbols.bin",
        "modules.weakdep",
    )
)
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MODE_RE = re.compile(r"^[0-7]{4}$")
COMPRESSED_MODULE_RE = re.compile(r"\.ko\.(?:bz2|gz|lz4|lzo|xz|zst)$")
PRIVATE_KEY_SUFFIXES = (".key", ".p12", ".pfx", ".pk8", ".pkey", ".priv", ".private")
PRIVATE_KEY_MARKER = b"PRIVATE KEY"
MODULE_SIGNATURE_MARKER = b"~Module signature appended~\n"
MODULE_SIGNATURE_HEADER_SIZE = 12
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
ISOLATION_PLAN_FIELDS = {
    "repository_root",
    "output",
    "build_store",
    "inspection_store",
    "signing_environment",
    "probe_mounts",
    "build_mounts",
    "inspection_mounts",
}
MOUNT_FIELDS = {"source", "target", "read_only"}


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
    try:
        path.relative_to(RELEASE_ROOT)
    except ValueError:
        return False
    return path != RELEASE_ROOT


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
    if is_module and record_type == "symlink":
        raise ValueError(f"module symlink is forbidden: {path}")
    if record_type == "file":
        expected_fields = MODULE_FILE_FIELDS if is_module else REGULAR_FILE_FIELDS
    elif record_type == "symlink":
        expected_fields = SYMLINK_FIELDS
    else:
        raise ValueError(f"unsupported RPM payload type for {path}: {record_type!r}")
    _require_exact_fields(record, expected_fields, f"file record {path}")

    if not isinstance(record["mode"], str) or not MODE_RE.fullmatch(record["mode"]):
        raise ValueError(f"invalid mode for {path}")
    expected_mode = "0644" if record_type == "file" else "0777"
    if record["mode"] != expected_mode:
        raise ValueError(f"unsafe or unexpected mode for {path}")
    if type(record["size"]) is not int or record["size"] < 0:
        raise ValueError(f"invalid size for {path}")
    if record["user"] != "root" or record["group"] != "root":
        raise ValueError(f"RPM payload ownership must be root:root: {path}")

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
        if (
            not isinstance(vermagic, str)
            or not vermagic.split()
            or vermagic.split()[0] != KERNEL_RELEASE
        ):
            raise ValueError(f"module vermagic mismatch for {path}")


def _expected_nevra(name: str, architecture: str) -> str:
    return f"{name}-{KERNEL_VERSION}-{RPM_RELEASE}.{architecture}"


def normalize_source_package_identity(
    package: dict[str, Any], artifact_filename: str
) -> dict[str, Any]:
    """Normalize an SRPM's build-architecture header to its source identity."""
    if (
        artifact_filename != EXPECTED_SOURCE_FILENAME
        or package.get("source_package") != "1"
        or package.get("source_rpm") != "(none)"
    ):
        raise ValueError("artifact is not the exact expected genuine source RPM")
    normalized = {field: package[field] for field in SOURCE_PACKAGE_FIELDS}
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
    if package["name"] == "kernel-openmythos-core":
        if set(paths) != REQUIRED_CORE_PATHS or any(
            record["type"] != "file" for record in files
        ):
            raise ValueError("kernel-openmythos core payload is not exact")
    if package["name"] == "kernel-openmythos-modules":
        metadata_paths = {path for path in paths if path in REQUIRED_MODULE_METADATA_PATHS}
        module_records = [
            record
            for record in files
            if isinstance(record.get("path"), str) and record["path"].endswith(".ko")
        ]
        module_root = (RELEASE_ROOT / "kernel").as_posix() + "/"
        allowed_paths = REQUIRED_MODULE_METADATA_PATHS | {
            record["path"] for record in module_records
        }
        if metadata_paths != REQUIRED_MODULE_METADATA_PATHS or set(paths) != allowed_paths:
            raise ValueError("kernel-openmythos modules metadata/payload is not exact")
        if not module_records:
            raise ValueError("kernel-openmythos requires a non-empty module set")
        if any(
            record["type"] != "file" or not record["path"].startswith(module_root)
            for record in module_records
        ):
            raise ValueError("kernel-openmythos module payload is invalid")


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


def _absolute_plan_path(value: Any, description: str) -> PurePosixPath:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{description} must be an absolute path")
    path = PurePosixPath(value)
    if "." in path.parts or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"{description} must be normalized")
    return path


def validate_builder_isolation_plan(plan: dict[str, Any]) -> None:
    """Fail closed if a container can see stores, repository, or excess secrets."""
    if not isinstance(plan, dict):
        raise ValueError("builder isolation plan must be an object")
    _require_exact_fields(plan, ISOLATION_PLAN_FIELDS, "builder isolation plan")
    repository = _absolute_plan_path(plan["repository_root"], "repository root")
    output = _absolute_plan_path(plan["output"], "builder output")
    build_store = _absolute_plan_path(plan["build_store"], "build store")
    inspection_store = _absolute_plan_path(
        plan["inspection_store"], "inspection store"
    )
    if build_store == inspection_store:
        raise ValueError("build and inspection stores must be distinct")
    for store in (build_store, inspection_store):
        if store == output or output in store.parents:
            raise ValueError("Podman store must be outside builder output")

    signing = plan["signing_environment"]
    if not isinstance(signing, dict):
        raise ValueError("signing_environment must be an object")
    _require_exact_fields(signing, {"probe", "build", "inspection"}, "signing environment")
    if signing != {"probe": False, "build": True, "inspection": False}:
        raise ValueError("signing environment must be limited to the build container")

    parsed_mounts: dict[str, list[tuple[PurePosixPath, PurePosixPath, bool]]] = {}
    for role in ("probe", "build", "inspection"):
        raw_mounts = plan[f"{role}_mounts"]
        if not isinstance(raw_mounts, list):
            raise ValueError(f"{role} mounts must be an array")
        mounts: list[tuple[PurePosixPath, PurePosixPath, bool]] = []
        targets: set[PurePosixPath] = set()
        for raw_mount in raw_mounts:
            if not isinstance(raw_mount, dict):
                raise ValueError(f"{role} mount must be an object")
            _require_exact_fields(raw_mount, MOUNT_FIELDS, f"{role} mount")
            source = _absolute_plan_path(raw_mount["source"], f"{role} mount source")
            target = _absolute_plan_path(raw_mount["target"], f"{role} mount target")
            if type(raw_mount["read_only"]) is not bool:
                raise ValueError(f"{role} mount read_only must be boolean")
            if target in targets:
                raise ValueError(f"{role} mount targets must be unique")
            targets.add(target)
            if source == repository or target == PurePosixPath("/repo"):
                raise ValueError(f"recursive repository mount is forbidden for {role}")
            for store in (build_store, inspection_store):
                if source == store or source in store.parents:
                    raise ValueError(f"Podman store would be visible to {role}")
            mounts.append((source, target, raw_mount["read_only"]))
        parsed_mounts[role] = mounts

    private_target = PurePosixPath("/run/secrets/module-signing.key")
    public_target = PurePosixPath("/public/module-signing.pem")
    if parsed_mounts["probe"]:
        raise ValueError("probe must have no host mounts")
    build_key_mounts = [mount for mount in parsed_mounts["build"] if mount[1] == private_target]
    if len(build_key_mounts) != 1 or not build_key_mounts[0][2]:
        raise ValueError("build must receive one read-only private-key mount")
    for role in ("probe", "inspection"):
        if any(
            target == private_target or source.name.endswith(PRIVATE_KEY_SUFFIXES)
            for source, target, _ in parsed_mounts[role]
        ):
            raise ValueError(f"{role} must not receive the private key")
    inspection_public_mounts = [
        mount for mount in parsed_mounts["inspection"] if mount[1] == public_target
    ]
    if len(inspection_public_mounts) != 1 or not inspection_public_mounts[0][2]:
        raise ValueError("inspection must receive one read-only public certificate")


def validate_imported_image_identity(
    observed_config_id: str,
    observed_manifest_digest: str,
    expected_config_id: str,
    expected_manifest_digest: str,
) -> None:
    if (
        not isinstance(expected_config_id, str)
        or not SHA256_DIGEST_RE.fullmatch(expected_config_id)
        or not isinstance(expected_manifest_digest, str)
        or not SHA256_DIGEST_RE.fullmatch(expected_manifest_digest)
    ):
        raise ValueError("locked image identity is malformed")
    normalized_config_id = (
        observed_config_id
        if observed_config_id.startswith("sha256:")
        else f"sha256:{observed_config_id}"
    )
    if (
        not SHA256_DIGEST_RE.fullmatch(normalized_config_id)
        or normalized_config_id != expected_config_id
        or observed_manifest_digest != expected_manifest_digest
    ):
        raise ValueError("imported image identity does not match both locked digests")


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


def _snapshot_rpm(source: Path, destination: Path) -> str:
    """Copy one stable, non-symlink RPM identity for every later operation."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as error:
        raise ValueError(f"RPM input must be a readable regular non-symlink: {source}") from error
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        path_before = source.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino)
        ):
            raise ValueError(f"RPM input must be a regular non-symlink: {source}")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        digest = hashlib.sha256()
        with os.fdopen(source_descriptor, "rb", closefd=False) as input_stream, os.fdopen(
            destination_descriptor, "wb", closefd=False
        ) as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                digest.update(chunk)
                output_stream.write(chunk)
            output_stream.flush()
            os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        try:
            path_after = source.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"RPM input changed while being snapshotted: {source}") from error
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            identity_before != identity_after
            or (after.st_dev, after.st_ino) != (path_after.st_dev, path_after.st_ino)
            or stat.S_ISLNK(path_after.st_mode)
        ):
            raise ValueError(f"RPM input changed while being snapshotted: {source}")
        os.fchmod(destination_descriptor, 0o444)
        os.fsync(destination_descriptor)
        return digest.hexdigest()
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)


def _contains_private_key_marker(path: Path) -> bool:
    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            combined = carry + chunk
            if PRIVATE_KEY_MARKER in combined:
                return True
            carry = combined[-(len(PRIVATE_KEY_MARKER) - 1) :]
    return False


def _verify_module_signature(module: Path, public_certificate: Path) -> None:
    """Cryptographically verify the appended Linux module PKCS#7 signature."""
    certificate_status = public_certificate.lstat()
    if not stat.S_ISREG(certificate_status.st_mode) or public_certificate.is_symlink():
        raise ValueError("public certificate must be a regular non-symlink")
    module_status = module.lstat()
    if not stat.S_ISREG(module_status.st_mode) or module.is_symlink():
        raise ValueError(f"module must be a regular non-symlink: {module}")
    suffix_size = len(MODULE_SIGNATURE_MARKER) + MODULE_SIGNATURE_HEADER_SIZE
    if module_status.st_size <= suffix_size:
        raise ValueError(f"module cryptographic signature is missing: {module}")
    with module.open("rb") as stream:
        stream.seek(-suffix_size, os.SEEK_END)
        raw_header = _read_exact(
            stream, MODULE_SIGNATURE_HEADER_SIZE, "module signature header"
        )
        marker = _read_exact(stream, len(MODULE_SIGNATURE_MARKER), "module marker")
    if marker != MODULE_SIGNATURE_MARKER:
        raise ValueError(f"module cryptographic signature marker mismatch: {module}")
    algorithm, hash_algorithm, identifier, signer_length, key_id_length = raw_header[:5]
    if (
        algorithm != 0
        or hash_algorithm != 0
        or identifier != 2
        or signer_length != 0
        or key_id_length != 0
        or raw_header[5:8] != b"\0\0\0"
    ):
        raise ValueError(f"module cryptographic signature header is invalid: {module}")
    signature_size = int.from_bytes(raw_header[8:12], "big")
    content_size = module_status.st_size - suffix_size - signature_size
    if signature_size == 0 or content_size <= 0:
        raise ValueError(f"module cryptographic signature length is invalid: {module}")

    with tempfile.TemporaryDirectory(prefix="openmythos-module-signature-") as directory:
        temporary_root = Path(directory)
        content_path = temporary_root / "content"
        signature_path = temporary_root / "signature.der"
        with module.open("rb") as source, content_path.open("wb") as content:
            remaining = content_size
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError(f"module changed while verifying signature: {module}")
                content.write(chunk)
                remaining -= len(chunk)
            signature = source.read(signature_size)
            if len(signature) != signature_size:
                raise ValueError(f"module changed while verifying signature: {module}")
            signature_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "cms",
                "-verify",
                "-verify_retcode",
                "-binary",
                "-inform",
                "DER",
                "-in",
                os.fspath(signature_path),
                "-content",
                os.fspath(content_path),
                "-nointern",
                "-certfile",
                os.fspath(public_certificate),
                "-noverify",
                "-out",
                os.devnull,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if result.returncode != 0:
        raise ValueError(f"module cryptographic signature verification failed: {module}")


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
            "%{SOURCEPACKAGE}",
            "%{SOURCERPM}",
        )
    )
    fields = _run_text(("rpm", "-qp", "--qf", query, os.fspath(path))).split(
        FIELD_SEPARATOR
    )
    if len(fields) != 8:
        raise ValueError(f"unexpected RPM package query output for {path}")
    name, epoch, version, release, architecture, nevra, source_package, source_rpm = (
        fields
    )
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
        "source_package": source_package,
        "source_rpm": source_rpm,
    }


def _normalize_binary_package_identity(package: dict[str, str]) -> dict[str, str]:
    if package.get("source_package") == "1":
        raise ValueError("source RPM cannot be accepted as a binary RPM")
    if package.get("source_rpm") != EXPECTED_SOURCE_FILENAME:
        raise ValueError("binary RPM source identity is not exact")
    return {field: package[field] for field in SOURCE_PACKAGE_FIELDS}


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
        if header["user"] != "root" or header["group"] != "root":
            raise ValueError(
                f"RPM payload header ownership must be root:root: {header_path}"
            )
        permission_mode = stat.S_IMODE(header["raw_mode"])
        expected_mode = 0o755 if file_type == stat.S_IFDIR else (
            0o777 if file_type == stat.S_IFLNK else 0o644
        )
        if permission_mode != expected_mode:
            description = "directory mode" if file_type == stat.S_IFDIR else "file mode"
            raise ValueError(f"unsafe or unexpected RPM {description}: {header_path}")
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


def _cpio_payload_path(raw_name: str) -> PurePosixPath:
    if not raw_name or raw_name.startswith("/") or "\x00" in raw_name:
        raise ValueError(f"unsafe CPIO path: {raw_name!r}")
    name = raw_name[2:] if raw_name.startswith("./") else raw_name
    pure = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "." in pure.parts
        or ".." in pure.parts
        or pure.as_posix() != name
    ):
        raise ValueError(f"unsafe CPIO path: {raw_name!r}")
    return PurePosixPath("/") / pure


def _read_exact(stream: Any, size: int, description: str) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise ValueError(f"truncated CPIO {description}")
    return value


def _read_newc_number(header: bytes, offset: int, description: str) -> int:
    try:
        return int(header[offset : offset + 8], 16)
    except ValueError as error:
        raise ValueError(f"invalid CPIO {description}") from error


def _validate_cpio_archive(
    spool: Path, headers: list[dict[str, Any]]
) -> None:
    """Validate the exact rpm2cpio stream before any extraction occurs."""
    expected = {header["path"]: header for header in headers}
    if len(expected) != len(headers):
        raise ValueError("duplicate RPM payload path")
    observed: dict[str, dict[str, Any]] = {}
    symlinks: set[PurePosixPath] = set()
    with spool.open("rb") as stream:
        while True:
            raw_header = _read_exact(stream, 110, "header")
            if raw_header[:6] != b"070701":
                raise ValueError("unsupported CPIO format")
            mode = _read_newc_number(raw_header, 14, "mode")
            uid = _read_newc_number(raw_header, 22, "uid")
            gid = _read_newc_number(raw_header, 30, "gid")
            links = _read_newc_number(raw_header, 38, "link count")
            size = _read_newc_number(raw_header, 54, "file size")
            name_size = _read_newc_number(raw_header, 94, "name size")
            if name_size < 1 or name_size > 1024 * 1024:
                raise ValueError("invalid CPIO name size")
            raw_name = _read_exact(stream, name_size, "name")
            if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
                raise ValueError("invalid CPIO name terminator")
            try:
                name = raw_name[:-1].decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("CPIO name is not UTF-8") from error
            name_padding = (-(110 + name_size)) % 4
            if any(_read_exact(stream, name_padding, "name padding")):
                raise ValueError("nonzero CPIO name padding")
            if name == "TRAILER!!!":
                if size != 0:
                    raise ValueError("invalid CPIO trailer")
                break

            path = _cpio_payload_path(name)
            path_value = path.as_posix()
            if path_value in observed:
                raise ValueError(f"duplicate CPIO payload path: {path}")
            file_type = stat.S_IFMT(mode)
            if file_type not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK):
                raise ValueError(f"unsupported special CPIO payload file: {path}")
            if uid != 0 or gid != 0:
                raise ValueError(f"CPIO payload ownership is not root:root: {path}")
            if file_type in (stat.S_IFREG, stat.S_IFLNK) and links != 1:
                raise ValueError(f"CPIO hardlink is forbidden: {path}")

            link_target = ""
            if file_type == stat.S_IFLNK:
                raw_target = _read_exact(stream, size, "symlink target")
                try:
                    link_target = raw_target.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ValueError(f"CPIO symlink target is not UTF-8: {path}") from error
                _validate_symlink_target(path, link_target)
                symlinks.add(path)
            else:
                remaining = size
                while remaining:
                    chunk = _read_exact(
                        stream, min(remaining, 1024 * 1024), "file data"
                    )
                    remaining -= len(chunk)
            data_padding = (-size) % 4
            if any(_read_exact(stream, data_padding, "data padding")):
                raise ValueError("nonzero CPIO data padding")
            observed[path_value] = {
                "raw_mode": mode,
                "size": size,
                "link_target": link_target,
            }

        while chunk := stream.read(1024 * 1024):
            if any(chunk):
                raise ValueError("nonzero data follows CPIO trailer")

    for path_value in observed:
        path = PurePosixPath(path_value)
        if any(symlink in path.parents for symlink in symlinks):
            raise ValueError(f"CPIO payload path is below CPIO symlink: {path}")
    if set(observed) != set(expected):
        raise ValueError("CPIO payload/header path mismatch")
    for path_value, actual in observed.items():
        header = expected[path_value]
        if actual["raw_mode"] != header["raw_mode"]:
            raise ValueError(f"CPIO payload/header mode mismatch: {path_value}")
        if actual["size"] != header["size"]:
            raise ValueError(f"CPIO payload/header size mismatch: {path_value}")
        if actual["link_target"] != header["link_target"]:
            raise ValueError(f"CPIO payload/header symlink mismatch: {path_value}")


def _spool_rpm_cpio(rpm_path: Path, spool: Path) -> None:
    with spool.open("xb") as output:
        result = subprocess.run(
            ["rpm2cpio", os.fspath(rpm_path)],
            check=False,
            stdout=output,
            stderr=subprocess.PIPE,
        )
        output.flush()
        os.fsync(output.fileno())
    if result.returncode != 0:
        spool.unlink(missing_ok=True)
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"rpm2cpio failed for {rpm_path}: {message}")
    os.chmod(spool, 0o444)


def _extract_validated_cpio(spool: Path, destination: Path) -> None:
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    with spool.open("rb") as input_stream:
        result = subprocess.run(
            [
                "cpio",
                "--extract",
                "--make-directories",
                "--preserve-modification-time",
                "--no-absolute-filenames",
            ],
            cwd=destination,
            stdin=input_stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"cpio failed for validated spool {spool}: {message}")


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


def _validate_modules_order(extract_root: Path, headers: list[dict[str, Any]]) -> None:
    module_prefix = RELEASE_ROOT.as_posix() + "/"
    packaged_modules = {
        header["path"].removeprefix(module_prefix)
        for header in headers
        if header["path"].endswith(".ko")
        and stat.S_IFMT(header["raw_mode"]) == stat.S_IFREG
    }
    if not packaged_modules:
        raise ValueError("modules.order cannot describe an empty module set")
    order_path = extract_root.joinpath(
        *RELEASE_ROOT.parts[1:], "modules.order"
    )
    try:
        lines = order_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("modules.order is missing or invalid") from error
    if not lines or len(lines) != len(set(lines)):
        raise ValueError("modules.order must be non-empty and unique")
    for line in lines:
        pure = PurePosixPath(line)
        if (
            not line
            or line.startswith("/")
            or "." in pure.parts
            or ".." in pure.parts
            or pure.as_posix() != line
            or not line.startswith("kernel/")
            or not line.endswith(".ko")
        ):
            raise ValueError("modules.order contains an unsafe module path")
    if set(lines) != packaged_modules:
        raise ValueError("modules.order does not exactly cover packaged modules")


def _inspect_payload_file(
    header: dict[str, Any], extract_root: Path, public_certificate: Path
) -> dict[str, Any] | None:
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
        _verify_module_signature(extracted, public_certificate)
        record.update(
            {
                "signer": _run_text(("modinfo", "-F", "signer", os.fspath(extracted))).strip(),
                "sig_id": _run_text(("modinfo", "-F", "sig_id", os.fspath(extracted))).strip(),
                "vermagic": _run_text(("modinfo", "-F", "vermagic", os.fspath(extracted))).strip(),
            }
        )
    return record


def inspect_rpm_set(
    rpm_dir: Path,
    srpm_dir: Path,
    output: Path,
    extract_root: Path,
    public_certificate: Path,
) -> dict[str, Any]:
    binary_paths = sorted(rpm_dir.glob("*.rpm"))
    source_paths = sorted(srpm_dir.glob("*.rpm"))
    if extract_root.exists():
        if not extract_root.is_dir() or any(extract_root.iterdir()):
            raise ValueError("extract root must be an absent or empty directory")
    else:
        extract_root.mkdir(mode=0o755, parents=True)

    certificate_status = public_certificate.lstat()
    if public_certificate.is_symlink() or not stat.S_ISREG(certificate_status.st_mode):
        raise ValueError("public certificate must be a regular non-symlink")
    with tempfile.TemporaryDirectory(
        dir=extract_root.parent, prefix=".rpm-inputs-"
    ) as snapshot_directory:
        snapshot_root = Path(snapshot_directory)
        source_snapshots: list[tuple[Path, Path, str]] = []
        binary_snapshots: list[tuple[Path, Path, str]] = []
        for index, original in enumerate(source_paths):
            snapshot = snapshot_root / f"source-{index}.rpm"
            source_snapshots.append((original, snapshot, _snapshot_rpm(original, snapshot)))
        for index, original in enumerate(binary_paths):
            snapshot = snapshot_root / f"binary-{index}.rpm"
            binary_snapshots.append((original, snapshot, _snapshot_rpm(original, snapshot)))

        sources = []
        for original, snapshot, identity in source_snapshots:
            package = _query_package(snapshot)
            if package["sha256"] != identity or _sha256_file(snapshot) != identity:
                raise ValueError(f"source RPM snapshot identity changed: {original}")
            sources.append(normalize_source_package_identity(package, original.name))

        binaries: list[dict[str, Any]] = []
        for index, (original, snapshot, identity) in enumerate(binary_snapshots):
            package = _normalize_binary_package_identity(_query_package(snapshot))
            headers = _query_file_headers(snapshot)
            _validate_pre_extraction_paths(snapshot, headers)
            cpio_spool = snapshot_root / f"binary-{index}.cpio"
            _spool_rpm_cpio(snapshot, cpio_spool)
            _validate_cpio_archive(cpio_spool, headers)
            if package["sha256"] != identity or _sha256_file(snapshot) != identity:
                raise ValueError(f"binary RPM snapshot identity changed: {original}")
            package_extract_root = extract_root / package["name"]
            _extract_validated_cpio(cpio_spool, package_extract_root)
            expected_non_directories = {
                header["path"]
                for header in headers
                if stat.S_IFMT(header["raw_mode"]) != stat.S_IFDIR
            }
            observed_non_directories = _extracted_non_directories(package_extract_root)
            if expected_non_directories != observed_non_directories:
                raise ValueError(f"extracted RPM payload differs from header: {original}")
            if package["name"] == "kernel-openmythos-modules":
                _validate_modules_order(package_extract_root, headers)
            records = [
                record
                for header in headers
                if (
                    record := _inspect_payload_file(
                        header, package_extract_root, public_certificate
                    )
                )
                is not None
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
        arguments.public_certificate,
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


def _audit_isolation_command(arguments: argparse.Namespace) -> int:
    value = json.loads(
        arguments.plan.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_pairs,
    )
    validate_builder_isolation_plan(value)
    return 0


def _audit_image_command(arguments: argparse.Namespace) -> int:
    validate_imported_image_identity(
        arguments.observed_config_id,
        arguments.observed_manifest_digest,
        arguments.expected_config_id,
        arguments.expected_manifest_digest,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--rpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--srpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--output", required=True, type=Path)
    inspect_parser.add_argument("--extract-root", required=True, type=Path)
    inspect_parser.add_argument("--public-certificate", required=True, type=Path)
    inspect_parser.set_defaults(handler=_inspect_command)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.set_defaults(handler=_validate_command)

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--left", required=True, type=Path)
    compare_parser.add_argument("--right", required=True, type=Path)
    compare_parser.add_argument("--output", required=True, type=Path)
    compare_parser.set_defaults(handler=_compare_command)

    isolation_parser = subparsers.add_parser("audit-isolation")
    isolation_parser.add_argument("--plan", required=True, type=Path)
    isolation_parser.set_defaults(handler=_audit_isolation_command)

    image_parser = subparsers.add_parser("audit-image")
    image_parser.add_argument("--observed-config-id", required=True)
    image_parser.add_argument("--observed-manifest-digest", required=True)
    image_parser.add_argument("--expected-config-id", required=True)
    image_parser.add_argument("--expected-manifest-digest", required=True)
    image_parser.set_defaults(handler=_audit_image_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
