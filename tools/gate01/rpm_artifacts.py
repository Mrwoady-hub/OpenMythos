"""Inspect, validate, and compare the Gate 01 kernel RPM set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess
import sys
import sysconfig
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
FROZEN_HELPER_PATHS = (
    "tools/__init__.py",
    "tools/gate01/__init__.py",
    "tools/gate01/inputs.py",
    "tools/gate01/kernel_config.py",
    "tools/gate01/module_key.py",
    "tools/gate01/rpm_artifacts.py",
    "tools/gate01/toolchain.py",
)
PROOF_SOURCE_PATHS = (
    "scripts/gate01/build-kernel.sh",
    "os/kernel/packaging/kernel-openmythos.spec",
    *FROZEN_HELPER_PATHS,
)
BOOTSTRAP_MODULES = frozenset(
    {
        "tools.gate01.kernel_config",
        "tools.gate01.module_key",
        "tools.gate01.rpm_artifacts",
        "tools.gate01.toolchain",
    }
)
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
    "private_key_source",
    "public_certificate_source",
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
            record["type"] != "file" or record["size"] <= 0 for record in files
        ):
            raise ValueError(
                "kernel-openmythos core payload must be an exact nonempty regular file set"
            )
    if package["name"] == "kernel-openmythos-modules":
        metadata_paths = {path for path in paths if path in REQUIRED_MODULE_METADATA_PATHS}
        metadata_records = [
            record for record in files if record.get("path") in REQUIRED_MODULE_METADATA_PATHS
        ]
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
        if any(
            record["type"] != "file" or record["size"] <= 0
            for record in metadata_records
        ):
            raise ValueError(
                "kernel-openmythos modules metadata must be nonempty regular files"
            )
        if not module_records:
            raise ValueError("kernel-openmythos requires a non-empty module set")
        if any(
            record["type"] != "file"
            or record["size"] <= 0
            or not record["path"].startswith(module_root)
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
    if ":" in value or "\0" in value:
        raise ValueError(f"{description} cannot be encoded as a volume path")
    path = PurePosixPath(value)
    if "." in path.parts or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"{description} must be normalized")
    return path


def _paths_overlap(left: PurePosixPath, right: PurePosixPath) -> bool:
    return left == right or left in right.parents or right in left.parents


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
    private_key = _absolute_plan_path(plan["private_key_source"], "private key")
    public_certificate = _absolute_plan_path(
        plan["public_certificate_source"], "public certificate"
    )
    if _paths_overlap(private_key, public_certificate):
        raise ValueError("private key and public certificate must be distinct")
    if _paths_overlap(build_store, inspection_store):
        raise ValueError("build and inspection stores must not overlap")
    for store in (build_store, inspection_store):
        if _paths_overlap(store, output):
            raise ValueError("Podman store and builder output must not overlap")

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
            if (
                source == repository
                or source in repository.parents
                or target == PurePosixPath("/repo")
            ):
                raise ValueError(f"recursive repository mount is forbidden for {role}")
            for store in (build_store, inspection_store):
                if _paths_overlap(source, store):
                    raise ValueError(f"Podman store would be visible to {role}")
            mounts.append((source, target, raw_mount["read_only"]))
        parsed_mounts[role] = mounts

    private_target = PurePosixPath("/run/secrets/module-signing.key")
    public_target = PurePosixPath("/public/module-signing.pem")
    if parsed_mounts["probe"]:
        raise ValueError("probe must have no host mounts")
    build_key_mounts = [
        mount for mount in parsed_mounts["build"] if mount[1] == private_target
    ]
    if build_key_mounts != [(private_key, private_target, True)]:
        raise ValueError("build must receive the exact private key read-only")
    inspection_public_mounts = [
        mount for mount in parsed_mounts["inspection"] if mount[1] == public_target
    ]
    if inspection_public_mounts != [(public_certificate, public_target, True)]:
        raise ValueError("inspection must receive the exact public certificate read-only")

    allowed_private_mount = ("build", private_key, private_target, True)
    allowed_public_mount = (
        "inspection",
        public_certificate,
        public_target,
        True,
    )
    for role, mounts in parsed_mounts.items():
        for source, target, read_only in mounts:
            candidate = (role, source, target, read_only)
            if _paths_overlap(source, private_key) and candidate != allowed_private_mount:
                raise ValueError(f"{role} must not receive private-key material")
            if (
                _paths_overlap(source, public_certificate)
                and candidate != allowed_public_mount
            ):
                raise ValueError(f"{role} has an excess public-certificate mount")
            if source.name.lower().endswith(PRIVATE_KEY_SUFFIXES) and (
                candidate != allowed_private_mount
            ):
                raise ValueError(f"{role} has an excess secret-like mount")


def _isolation_volume_specs(plan: dict[str, Any], role: str) -> list[str]:
    """Return the canonical Podman volume arguments represented by one plan."""
    return [
        f"{mount['source']}:{mount['target']}:"
        f"{'ro' if mount['read_only'] else 'rw'}"
        for mount in plan[f"{role}_mounts"]
    ]


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


def isolated_runtime_record(expected_root: Path) -> dict[str, Any]:
    """Describe and validate the frozen interpreter boundary used by proof code."""
    expected_root = _absolute_lexical_path(expected_root)
    root_status = expected_root.lstat()
    if expected_root.is_symlink() or not stat.S_ISDIR(root_status.st_mode):
        raise ValueError("frozen helper root must be a non-symlink directory")
    root = expected_root.resolve(strict=True)
    module_file = Path(__file__).resolve(strict=True)
    flags = {
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "ignore_environment": sys.flags.ignore_environment,
        "isolated": sys.flags.isolated,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
        "safe_path": sys.flags.safe_path,
    }
    expected_flags = {
        "dont_write_bytecode": 1,
        "ignore_environment": 1,
        "isolated": 1,
        "no_site": 1,
        "no_user_site": 1,
        "safe_path": True,
    }
    if flags != expected_flags:
        raise ValueError("Python proof runtime is not fully isolated")
    if module_file != root / "tools/gate01/rpm_artifacts.py":
        raise ValueError("Python proof runtime did not load the frozen verifier")
    normalized_path = [os.fspath(Path(entry).resolve()) for entry in sys.path]
    if not normalized_path or normalized_path[0] != os.fspath(root):
        raise ValueError("frozen helper root is not the sole explicit import root")
    return {
        "schema_version": SCHEMA_VERSION,
        "flags": flags,
        "frozen_root": os.fspath(root),
        "module_file": os.fspath(module_file),
        "sys_path": normalized_path,
    }


def bootstrap_frozen_module(root: Path, python_arguments: list[str]) -> int:
    """Run one allowlisted frozen module under an already isolated interpreter."""
    root = _absolute_lexical_path(root)
    root_status = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_status.st_mode):
        raise ValueError("bootstrap root must be a non-symlink directory")
    frozen_root = root.resolve(strict=True)
    if Path(__file__).resolve(strict=True) != (
        frozen_root / "tools/gate01/rpm_artifacts.py"
    ):
        raise ValueError("bootstrap verifier is not inside the declared frozen root")
    expected_flags = (
        sys.flags.isolated,
        sys.flags.ignore_environment,
        sys.flags.no_user_site,
        sys.flags.no_site,
        sys.flags.safe_path,
        sys.flags.dont_write_bytecode,
    )
    if expected_flags != (1, 1, 1, 1, True, 1):
        raise ValueError("frozen Python bootstrap requires -I -S -B")
    arguments = list(python_arguments)
    if arguments and arguments[0] == "--":
        arguments.pop(0)
    if len(arguments) < 2 or arguments[0] != "-m":
        raise ValueError("frozen Python bootstrap accepts only an allowlisted -m module")
    module = arguments[1]
    if module not in BOOTSTRAP_MODULES:
        raise ValueError(f"Python proof module is not allowlisted: {module}")
    stdlib_roots = {
        Path(sysconfig.get_path(name)).resolve()
        for name in ("stdlib", "platstdlib")
    }
    isolated_stdlib: list[str] = []
    for raw_entry in tuple(sys.path):
        if not raw_entry:
            raise ValueError("isolated Python path contains the current directory")
        entry = Path(raw_entry).resolve()
        is_stdlib = any(entry == root or root in entry.parents for root in stdlib_roots)
        is_stdlib_zip = any(
            entry.parent == root.parent
            and entry.name.startswith("python")
            and entry.suffix == ".zip"
            for root in stdlib_roots
        )
        if not (is_stdlib or is_stdlib_zip):
            raise ValueError(f"isolated Python path has an undeclared entry: {entry}")
        isolated_stdlib.append(os.fspath(entry))
    # Replace, rather than extend, the import path.  -I/-S made the retained
    # entries interpreter-owned stdlib paths; the one explicit root is frozen.
    sys.path[:] = [os.fspath(frozen_root), *isolated_stdlib]
    sys.argv = [module, *arguments[2:]]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
    return 0


def validate_frozen_helper_tree(source_root: Path, snapshot_root: Path) -> None:
    """Validate the exact read-only local-Python closure and its live identity."""
    expected_files = set(FROZEN_HELPER_PATHS)
    expected_directories = {"tools", "tools/gate01"}
    try:
        snapshot_status = snapshot_root.lstat()
    except OSError as error:
        raise ValueError("frozen helper snapshot is missing") from error
    if (
        not stat.S_ISDIR(snapshot_status.st_mode)
        or snapshot_root.is_symlink()
        or stat.S_IMODE(snapshot_status.st_mode) != 0o555
    ):
        raise ValueError("frozen helper snapshot root must be a 0555 directory")

    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in snapshot_root.rglob("*"):
        relative = path.relative_to(snapshot_root).as_posix()
        status = path.lstat()
        if stat.S_ISDIR(status.st_mode):
            if path.is_symlink() or stat.S_IMODE(status.st_mode) != 0o555:
                raise ValueError(f"frozen helper directory is unsafe: {relative}")
            observed_directories.add(relative)
        elif stat.S_ISREG(status.st_mode):
            if status.st_nlink != 1 or stat.S_IMODE(status.st_mode) != 0o444:
                raise ValueError(f"frozen helper file is unsafe: {relative}")
            observed_files.add(relative)
        else:
            raise ValueError(f"frozen helper tree contains a special entry: {relative}")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ValueError("frozen helper tree is not the exact import closure")

    for relative in FROZEN_HELPER_PATHS:
        source = source_root / relative
        frozen = snapshot_root / relative
        try:
            source_before = source.lstat()
            frozen_before = frozen.lstat()
        except OSError as error:
            raise ValueError(f"frozen helper is missing: {relative}") from error
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source.is_symlink()
            or not stat.S_ISREG(frozen_before.st_mode)
            or frozen.is_symlink()
        ):
            raise ValueError(f"frozen helper must be a regular non-symlink: {relative}")
        source_digest = _sha256_file(source)
        frozen_digest = _sha256_file(frozen)
        source_after = source.lstat()
        frozen_after = frozen.lstat()
        source_identity_before = (
            source_before.st_dev,
            source_before.st_ino,
            source_before.st_size,
            source_before.st_mtime_ns,
            source_before.st_ctime_ns,
        )
        source_identity_after = (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_mtime_ns,
            source_after.st_ctime_ns,
        )
        frozen_identity_before = (
            frozen_before.st_dev,
            frozen_before.st_ino,
            frozen_before.st_size,
            frozen_before.st_mtime_ns,
            frozen_before.st_ctime_ns,
        )
        frozen_identity_after = (
            frozen_after.st_dev,
            frozen_after.st_ino,
            frozen_after.st_size,
            frozen_after.st_mtime_ns,
            frozen_after.st_ctime_ns,
        )
        if (
            source_identity_before != source_identity_after
            or frozen_identity_before != frozen_identity_after
            or source_digest != frozen_digest
        ):
            raise ValueError(f"frozen helper identity differs from source: {relative}")


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


def _status_identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _absolute_lexical_path(path: Path) -> Path:
    """Make a path absolute without following a final symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def _open_bound_directory(
    directory: Path, description: str, *, expected_mode: int | None = None
) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(directory, flags)
        opened = os.fstat(descriptor)
        path_status = directory.lstat()
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ValueError(f"{description} is missing or unsafe: {directory}") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(path_status.st_mode)
        or (opened.st_dev, opened.st_ino)
        != (path_status.st_dev, path_status.st_ino)
        or (
            expected_mode is not None
            and stat.S_IMODE(opened.st_mode) != expected_mode
        )
    ):
        os.close(descriptor)
        raise ValueError(f"{description} is not stable: {directory}")
    return {
        "descriptor": descriptor,
        "path": directory,
        "before": opened,
        "names": sorted(os.listdir(descriptor)),
        "description": description,
    }


def _verify_bound_directory(record: dict[str, Any]) -> None:
    descriptor = record["descriptor"]
    directory = record["path"]
    try:
        after = os.fstat(descriptor)
        path_after = directory.lstat()
    except OSError as error:
        raise ValueError(f"{record['description']} changed: {directory}") from error
    if (
        sorted(os.listdir(descriptor)) != record["names"]
        or _status_identity(record["before"]) != _status_identity(after)
        or (after.st_dev, after.st_ino)
        != (path_after.st_dev, path_after.st_ino)
        or stat.S_ISLNK(path_after.st_mode)
    ):
        raise ValueError(f"{record['description']} changed: {directory}")


def _open_bound_regular(
    path: Path,
    description: str,
    *,
    directory_descriptor: int | None = None,
    name: str | None = None,
    expected_mode: int | None = None,
) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        if directory_descriptor is None:
            descriptor = os.open(path, flags)
            path_status = path.lstat()
        else:
            if name is None:
                raise ValueError("bound relative file requires a name")
            descriptor = os.open(name, flags, dir_fd=directory_descriptor)
            path_status = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
        opened = os.fstat(descriptor)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ValueError(f"{description} is missing or unsafe: {path}") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or stat.S_ISLNK(path_status.st_mode)
        or (opened.st_dev, opened.st_ino)
        != (path_status.st_dev, path_status.st_ino)
        or (
            expected_mode is not None
            and stat.S_IMODE(opened.st_mode) != expected_mode
        )
    ):
        os.close(descriptor)
        raise ValueError(f"{description} must be one safe regular file: {path}")
    return {
        "descriptor": descriptor,
        "path": path,
        "before": opened,
        "description": description,
    }


def _hash_bound_file(record: dict[str, Any]) -> str:
    descriptor = record["descriptor"]
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _read_bound_file(record: dict[str, Any], maximum_bytes: int) -> bytes:
    if record["before"].st_size > maximum_bytes:
        raise ValueError(f"{record['description']} exceeds its size limit")
    descriptor = record["descriptor"]
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining and (chunk := os.read(descriptor, min(remaining, 1024 * 1024))):
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum_bytes:
        raise ValueError(f"{record['description']} exceeds its size limit")
    return value


def _verify_bound_file(record: dict[str, Any]) -> None:
    try:
        after = os.fstat(record["descriptor"])
        path_after = record["path"].lstat()
    except OSError as error:
        raise ValueError(
            f"{record['description']} changed: {record['path']}"
        ) from error
    if (
        _status_identity(record["before"]) != _status_identity(after)
        or not stat.S_ISREG(path_after.st_mode)
        or after.st_nlink != 1
        or (after.st_dev, after.st_ino)
        != (path_after.st_dev, path_after.st_ino)
    ):
        raise ValueError(f"{record['description']} changed: {record['path']}")


def _close_bound_records(records: list[dict[str, Any]]) -> None:
    for record in reversed(records):
        os.close(record["descriptor"])


def _two_pass_hash_and_sweep(
    files: list[dict[str, Any]], directories: list[dict[str, Any]]
) -> list[str]:
    first = [_hash_bound_file(record) for record in files]
    second = [_hash_bound_file(record) for record in files]
    if first != second:
        raise ValueError("bound proof file bytes changed between hash passes")
    for record in files:
        _verify_bound_file(record)
    for record in directories:
        _verify_bound_directory(record)
    return first


def _open_retained_rpm_set(
    rpm_dir: Path, srpm_dir: Path, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    validate_rpm_manifest(manifest)
    if rpm_dir.name != "x86_64":
        raise ValueError("retained RPM root must contain the exact x86_64 leaf")
    source_expected = {
        EXPECTED_SOURCE_FILENAME: manifest["source_rpms"][0]["sha256"]
    }
    binary_expected = {
        f"{package['nevra']}.rpm": package["sha256"]
        for package in manifest["binary_rpms"]
    }
    directories: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    expected: dict[str, str] = {}
    try:
        root_record = _open_bound_directory(rpm_dir.parent, "retained RPM root")
        directories.append(root_record)
        if root_record["names"] != ["x86_64"]:
            raise ValueError("retained RPM root must contain only x86_64")
        rpm_record = _open_bound_directory(rpm_dir, "retained RPM set")
        directories.append(rpm_record)
        leaf_status = os.stat(
            "x86_64",
            dir_fd=root_record["descriptor"],
            follow_symlinks=False,
        )
        if (leaf_status.st_dev, leaf_status.st_ino) != (
            rpm_record["before"].st_dev,
            rpm_record["before"].st_ino,
        ):
            raise ValueError("retained RPM x86_64 directory is not stable")
        srpm_record = _open_bound_directory(srpm_dir, "retained SRPM set")
        directories.append(srpm_record)
        source_names = sorted(source_expected)
        binary_names = sorted(binary_expected)
        if srpm_record["names"] != source_names:
            raise ValueError(f"retained RPM set is not exact: {srpm_dir}")
        if rpm_record["names"] != binary_names:
            raise ValueError(f"retained RPM set is not exact: {rpm_dir}")
        for directory_record, names, digests in (
            (srpm_record, source_names, source_expected),
            (rpm_record, binary_names, binary_expected),
        ):
            for name in names:
                path = directory_record["path"] / name
                file_record = _open_bound_regular(
                    path,
                    "retained RPM",
                    directory_descriptor=directory_record["descriptor"],
                    name=name,
                )
                file_record["kind"] = "rpm"
                files.append(file_record)
                expected[os.fspath(path)] = digests[name]
    except BaseException:
        _close_bound_records(files)
        _close_bound_records(directories)
        raise
    return files, directories, expected


def _retained_file_digest(directory_descriptor: int, name: str) -> str:
    """Hash one exact retained regular entry without blocking on special files."""
    path = Path(f"/proc/self/fd/{directory_descriptor}") / name
    record = _open_bound_regular(
        path,
        "retained RPM",
        directory_descriptor=directory_descriptor,
        name=name,
    )
    try:
        return _two_pass_hash_and_sweep([record], [])[0]
    finally:
        os.close(record["descriptor"])


def validate_retained_rpm_set(
    rpm_dir: Path, srpm_dir: Path, manifest: dict[str, Any]
) -> None:
    """Bind a two-pass, simultaneously open exact retained RPM topology."""
    rpm_dir = _absolute_lexical_path(rpm_dir)
    srpm_dir = _absolute_lexical_path(srpm_dir)
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    try:
        files, directories, expected = _open_retained_rpm_set(
            rpm_dir, srpm_dir, manifest
        )
        digests = _two_pass_hash_and_sweep(files, directories)
        for record, digest in zip(files, digests, strict=True):
            if digest != expected[os.fspath(record["path"])]:
                raise ValueError(
                    f"retained RPM hash differs from inspected manifest: "
                    f"{record['path'].name}"
                )
    finally:
        _close_bound_records(files)
        _close_bound_records(directories)


def _parse_proof_source_manifest(value: bytes, description: str) -> dict[str, str]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{description} is not ASCII") from error
    if not text.endswith("\n") or "\r" in text:
        raise ValueError(f"{description} is not canonical")
    lines = text.splitlines()
    if len(lines) != len(PROOF_SOURCE_PATHS):
        raise ValueError(f"{description} does not contain the exact proof source set")
    parsed: dict[str, str] = {}
    for expected_path, line in zip(PROOF_SOURCE_PATHS, lines, strict=True):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0\r\n]+)", line)
        if match is None or match.group(2) != expected_path:
            raise ValueError(f"{description} is not canonical")
        parsed[expected_path] = match.group(1)
    canonical = "".join(
        f"{parsed[relative]}  {relative}\n" for relative in PROOF_SOURCE_PATHS
    ).encode("ascii")
    if canonical != value:
        raise ValueError(f"{description} is not canonical")
    return parsed


def _parse_bound_rpm_manifest(value: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(
            value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bound RPM manifest is invalid") from error
    validate_rpm_manifest(manifest)
    return manifest


def _open_exact_frozen_tree(
    snapshot_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Path]]:
    directories: list[dict[str, Any]] = []
    try:
        directories.append(
            _open_bound_directory(
                snapshot_root, "frozen helper root", expected_mode=0o555
            )
        )
        directories.append(
            _open_bound_directory(
                snapshot_root / "tools",
                "frozen tools package",
                expected_mode=0o555,
            )
        )
        directories.append(
            _open_bound_directory(
                snapshot_root / "tools/gate01",
                "frozen Gate 01 package",
                expected_mode=0o555,
            )
        )
        expected_names = (
            ["tools"],
            ["__init__.py", "gate01"],
            sorted(Path(relative).name for relative in FROZEN_HELPER_PATHS[1:]),
        )
        for record, names in zip(directories, expected_names, strict=True):
            if record["names"] != names:
                raise ValueError("frozen helper tree is not the exact import closure")
        return directories, {
            relative: snapshot_root / relative for relative in FROZEN_HELPER_PATHS
        }
    except BaseException:
        _close_bound_records(directories)
        raise


def validate_final_proof_boundary(
    *,
    rpm_dir: Path,
    srpm_dir: Path,
    rpm_manifest_path: Path,
    expected_rpm_manifest_sha256: str,
    source_root: Path,
    snapshot_root: Path,
    spec_snapshot: Path,
    driver_snapshot: Path,
    expected_source_manifest: Path,
    final_source_manifest: Path,
) -> None:
    """Bind proof sources, frozen copies, manifests, and RPMs in one interval.

    Every proof-relevant file descriptor remains open across two complete hash
    passes and one final global identity/path/topology sweep.  This establishes
    one mutually consistent observation interval; a caller that needs to resist
    a hostile same-UID writer after return must publish on an immutable medium.
    """
    if not RAW_SHA256_RE.fullmatch(expected_rpm_manifest_sha256):
        raise ValueError("inspected RPM manifest SHA-256 is malformed")
    source_root = _absolute_lexical_path(source_root)
    snapshot_root = _absolute_lexical_path(snapshot_root)
    rpm_dir = _absolute_lexical_path(rpm_dir)
    srpm_dir = _absolute_lexical_path(srpm_dir)
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    try:
        early_record = _open_bound_regular(
            _absolute_lexical_path(expected_source_manifest),
            "early proof source manifest",
        )
        early_record["kind"] = "source-manifest"
        files.append(early_record)
        final_record = _open_bound_regular(
            _absolute_lexical_path(final_source_manifest),
            "final proof source manifest",
        )
        final_record["kind"] = "source-manifest"
        files.append(final_record)
        rpm_manifest_record = _open_bound_regular(
            _absolute_lexical_path(rpm_manifest_path), "RPM artifact manifest"
        )
        rpm_manifest_record["kind"] = "rpm-manifest"
        files.append(rpm_manifest_record)

        early_bytes = _read_bound_file(early_record, 64 * 1024)
        final_bytes = _read_bound_file(final_record, 64 * 1024)
        rpm_manifest_bytes = _read_bound_file(rpm_manifest_record, 64 * 1024 * 1024)
        early_hashes = _parse_proof_source_manifest(
            early_bytes, "early proof source manifest"
        )
        final_hashes = _parse_proof_source_manifest(
            final_bytes, "final proof source manifest"
        )
        if early_bytes != final_bytes or early_hashes != final_hashes:
            raise ValueError("proof source manifests differ")
        rpm_manifest = _parse_bound_rpm_manifest(rpm_manifest_bytes)

        frozen_directories, frozen_paths = _open_exact_frozen_tree(snapshot_root)
        directories.extend(frozen_directories)
        live_records: dict[str, dict[str, Any]] = {}
        snapshot_records: dict[str, dict[str, Any]] = {}
        for relative in PROOF_SOURCE_PATHS:
            live_record = _open_bound_regular(
                source_root / relative, f"live proof source {relative}"
            )
            live_record["kind"] = "proof-source"
            live_record["relative"] = relative
            files.append(live_record)
            live_records[relative] = live_record

            if relative == "scripts/gate01/build-kernel.sh":
                snapshot_path = _absolute_lexical_path(driver_snapshot)
                expected_mode = 0o555
            elif relative == "os/kernel/packaging/kernel-openmythos.spec":
                snapshot_path = _absolute_lexical_path(spec_snapshot)
                expected_mode = 0o444
            else:
                snapshot_path = frozen_paths[relative]
                expected_mode = 0o444
            snapshot_record = _open_bound_regular(
                snapshot_path,
                f"frozen proof source {relative}",
                expected_mode=expected_mode,
            )
            snapshot_record["kind"] = "proof-snapshot"
            snapshot_record["relative"] = relative
            files.append(snapshot_record)
            snapshot_records[relative] = snapshot_record

        rpm_files, rpm_directories, rpm_expected = _open_retained_rpm_set(
            rpm_dir, srpm_dir, rpm_manifest
        )
        files.extend(rpm_files)
        directories.extend(rpm_directories)

        digests = _two_pass_hash_and_sweep(files, directories)
        digest_by_descriptor = {
            record["descriptor"]: digest
            for record, digest in zip(files, digests, strict=True)
        }
        initial_bytes = {
            early_record["descriptor"]: early_bytes,
            final_record["descriptor"]: final_bytes,
            rpm_manifest_record["descriptor"]: rpm_manifest_bytes,
        }
        for descriptor, value in initial_bytes.items():
            if hashlib.sha256(value).hexdigest() != digest_by_descriptor[descriptor]:
                raise ValueError("bound proof manifest changed after it was parsed")
        if (
            digest_by_descriptor[rpm_manifest_record["descriptor"]]
            != expected_rpm_manifest_sha256
        ):
            raise ValueError("RPM manifest differs from its inspected identity")

        for relative in PROOF_SOURCE_PATHS:
            live_digest = digest_by_descriptor[live_records[relative]["descriptor"]]
            snapshot_digest = digest_by_descriptor[
                snapshot_records[relative]["descriptor"]
            ]
            if (
                live_digest != early_hashes[relative]
                or live_digest != snapshot_digest
            ):
                raise ValueError(f"proof source changed or differs: {relative}")
        for record in rpm_files:
            digest = digest_by_descriptor[record["descriptor"]]
            if digest != rpm_expected[os.fspath(record["path"])]:
                raise ValueError(
                    "retained RPM hash differs from inspected manifest: "
                    f"{record['path'].name}"
                )
    finally:
        _close_bound_records(files)
        _close_bound_records(directories)


def _snapshot_rpm(source: Path, destination: Path) -> str:
    """Copy one stable, non-symlink RPM identity for every later operation."""
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
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

    module_root = RELEASE_ROOT / "kernel"
    expected_directories: set[PurePosixPath] = set()
    for header, header_path in zip(headers, normalized_header_paths, strict=True):
        if (
            stat.S_IFMT(header["raw_mode"]) == stat.S_IFREG
            and header_path.as_posix().endswith(".ko")
            and (header_path.parent == module_root or module_root in header_path.parents)
        ):
            parent = header_path.parent
            while parent == module_root or module_root in parent.parents:
                expected_directories.add(parent)
                if parent == module_root:
                    break
                parent = parent.parent
    explicit_directories = {
        header_path
        for header, header_path in zip(headers, normalized_header_paths, strict=True)
        if stat.S_IFMT(header["raw_mode"]) == stat.S_IFDIR
    }
    if explicit_directories != expected_directories:
        raise ValueError(f"RPM explicit directory topology is not exact for {rpm_path}")

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


def _validate_extracted_tree(root: Path, headers: list[dict[str, Any]]) -> None:
    """Require exact extracted entries/types, including all implicit directories."""
    expected_types: dict[str, int] = {}
    header_modes: dict[str, int] = {}
    for header in headers:
        path = PurePosixPath(header["path"])
        expected_types[path.as_posix()] = stat.S_IFMT(header["raw_mode"])
        header_modes[path.as_posix()] = stat.S_IMODE(header["raw_mode"])
        for parent in path.parents:
            if parent == PurePosixPath("/"):
                break
            expected_types.setdefault(parent.as_posix(), stat.S_IFDIR)

    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(root, flags)
    except OSError as error:
        raise ValueError("extracted RPM tree root is missing or unsafe") from error
    observed: dict[str, tuple[int, int]] = {}

    def walk(directory_descriptor: int, relative: PurePosixPath) -> None:
        names_before = sorted(os.listdir(directory_descriptor))
        for name in names_before:
            if name in ("", ".", "..") or "/" in name:
                raise ValueError("extracted RPM tree contains an unsafe name")
            status = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
            path = relative / name
            absolute = (PurePosixPath("/") / path).as_posix()
            file_type = stat.S_IFMT(status.st_mode)
            observed[absolute] = (file_type, stat.S_IMODE(status.st_mode))
            if file_type == stat.S_IFDIR:
                child = os.open(name, flags, dir_fd=directory_descriptor)
                try:
                    child_status = os.fstat(child)
                    if (status.st_dev, status.st_ino) != (
                        child_status.st_dev,
                        child_status.st_ino,
                    ):
                        raise ValueError("extracted RPM tree changed while walking")
                    walk(child, path)
                finally:
                    os.close(child)
        if sorted(os.listdir(directory_descriptor)) != names_before:
            raise ValueError("extracted RPM tree changed while walking")

    try:
        walk(root_descriptor, PurePosixPath())
    finally:
        os.close(root_descriptor)

    if set(observed) != set(expected_types):
        raise ValueError("extracted RPM tree does not exactly match payload and ancestors")
    for path, expected_type in expected_types.items():
        observed_type, observed_mode = observed[path]
        if observed_type != expected_type:
            raise ValueError(f"extracted RPM tree type mismatch: {path}")
        if path in header_modes and observed_mode != header_modes[path]:
            raise ValueError(f"extracted RPM tree mode mismatch: {path}")


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
            _validate_extracted_tree(package_extract_root, headers)
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
    validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)
    installed_files = {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "packages": _installed_file_view(manifest),
    }
    _atomic_write_json(output.with_name("installed-files.json"), installed_files)
    _atomic_write_json(output, manifest)
    return manifest


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    serialized = _canonical_json_bytes(value)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _inspect_command(arguments: argparse.Namespace) -> int:
    manifest = inspect_rpm_set(
        arguments.rpm_dir,
        arguments.srpm_dir,
        arguments.output,
        arguments.extract_root,
        arguments.public_certificate,
    )
    if arguments.print_manifest_sha256:
        print(hashlib.sha256(_canonical_json_bytes(manifest)).hexdigest())
    return 0


def _validate_command(arguments: argparse.Namespace) -> int:
    validate_rpm_manifest(load_rpm_manifest(arguments.manifest))
    return 0


def _rebind_command(arguments: argparse.Namespace) -> int:
    validate_retained_rpm_set(
        arguments.rpm_dir,
        arguments.srpm_dir,
        load_rpm_manifest(arguments.manifest),
    )
    return 0


def _bind_final_command(arguments: argparse.Namespace) -> int:
    validate_final_proof_boundary(
        rpm_dir=arguments.rpm_dir,
        srpm_dir=arguments.srpm_dir,
        rpm_manifest_path=arguments.rpm_manifest,
        expected_rpm_manifest_sha256=arguments.expected_rpm_manifest_sha256,
        source_root=arguments.source_root,
        snapshot_root=arguments.snapshot_root,
        spec_snapshot=arguments.spec_snapshot,
        driver_snapshot=arguments.driver_snapshot,
        expected_source_manifest=arguments.expected_source_manifest,
        final_source_manifest=arguments.final_source_manifest,
    )
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
    if arguments.build_volume != _isolation_volume_specs(value, "build"):
        raise ValueError("audited build mounts differ from actual volume arguments")
    if arguments.inspection_volume != _isolation_volume_specs(value, "inspection"):
        raise ValueError(
            "audited inspection mounts differ from actual volume arguments"
        )
    return 0


def _audit_image_command(arguments: argparse.Namespace) -> int:
    validate_imported_image_identity(
        arguments.observed_config_id,
        arguments.observed_manifest_digest,
        arguments.expected_config_id,
        arguments.expected_manifest_digest,
    )
    return 0


def _audit_freeze_command(arguments: argparse.Namespace) -> int:
    validate_frozen_helper_tree(arguments.source_root, arguments.snapshot_root)
    return 0


def _audit_runtime_command(arguments: argparse.Namespace) -> int:
    _atomic_write_json(
        arguments.output, isolated_runtime_record(arguments.expected_root)
    )
    return 0


def _audit_source_lock_command(arguments: argparse.Namespace) -> int:
    from tools.gate01.inputs import load_source_lock, validate_source_lock

    validate_source_lock(load_source_lock(arguments.source_lock))
    return 0


def _bootstrap_command(arguments: argparse.Namespace) -> int:
    return bootstrap_frozen_module(arguments.root, arguments.python_arguments)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--rpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--srpm-dir", required=True, type=Path)
    inspect_parser.add_argument("--output", required=True, type=Path)
    inspect_parser.add_argument("--extract-root", required=True, type=Path)
    inspect_parser.add_argument("--public-certificate", required=True, type=Path)
    inspect_parser.add_argument("--print-manifest-sha256", action="store_true")
    inspect_parser.set_defaults(handler=_inspect_command)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.set_defaults(handler=_validate_command)

    rebind_parser = subparsers.add_parser("rebind")
    rebind_parser.add_argument("--rpm-dir", required=True, type=Path)
    rebind_parser.add_argument("--srpm-dir", required=True, type=Path)
    rebind_parser.add_argument("--manifest", required=True, type=Path)
    rebind_parser.set_defaults(handler=_rebind_command)

    bind_final_parser = subparsers.add_parser("bind-final")
    bind_final_parser.add_argument("--rpm-dir", required=True, type=Path)
    bind_final_parser.add_argument("--srpm-dir", required=True, type=Path)
    bind_final_parser.add_argument("--rpm-manifest", required=True, type=Path)
    bind_final_parser.add_argument("--expected-rpm-manifest-sha256", required=True)
    bind_final_parser.add_argument("--source-root", required=True, type=Path)
    bind_final_parser.add_argument("--snapshot-root", required=True, type=Path)
    bind_final_parser.add_argument("--spec-snapshot", required=True, type=Path)
    bind_final_parser.add_argument("--driver-snapshot", required=True, type=Path)
    bind_final_parser.add_argument(
        "--expected-source-manifest", required=True, type=Path
    )
    bind_final_parser.add_argument("--final-source-manifest", required=True, type=Path)
    bind_final_parser.set_defaults(handler=_bind_final_command)

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--left", required=True, type=Path)
    compare_parser.add_argument("--right", required=True, type=Path)
    compare_parser.add_argument("--output", required=True, type=Path)
    compare_parser.set_defaults(handler=_compare_command)

    isolation_parser = subparsers.add_parser("audit-isolation")
    isolation_parser.add_argument("--plan", required=True, type=Path)
    isolation_parser.add_argument("--build-volume", action="append", default=[])
    isolation_parser.add_argument("--inspection-volume", action="append", default=[])
    isolation_parser.set_defaults(handler=_audit_isolation_command)

    image_parser = subparsers.add_parser("audit-image")
    image_parser.add_argument("--observed-config-id", required=True)
    image_parser.add_argument("--observed-manifest-digest", required=True)
    image_parser.add_argument("--expected-config-id", required=True)
    image_parser.add_argument("--expected-manifest-digest", required=True)
    image_parser.set_defaults(handler=_audit_image_command)

    freeze_parser = subparsers.add_parser("audit-freeze")
    freeze_parser.add_argument("--source-root", required=True, type=Path)
    freeze_parser.add_argument("--snapshot-root", required=True, type=Path)
    freeze_parser.set_defaults(handler=_audit_freeze_command)

    runtime_parser = subparsers.add_parser("audit-runtime")
    runtime_parser.add_argument("--expected-root", required=True, type=Path)
    runtime_parser.add_argument("--output", required=True, type=Path)
    runtime_parser.set_defaults(handler=_audit_runtime_command)

    source_lock_parser = subparsers.add_parser("audit-source-lock")
    source_lock_parser.add_argument("source_lock", type=Path)
    source_lock_parser.set_defaults(handler=_audit_source_lock_command)

    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument("--root", required=True, type=Path)
    bootstrap_parser.add_argument(
        "python_arguments", nargs=argparse.REMAINDER
    )
    bootstrap_parser.set_defaults(handler=_bootstrap_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
