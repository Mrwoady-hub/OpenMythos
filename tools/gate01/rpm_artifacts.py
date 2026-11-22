"""Inspect, validate, and compare the Gate 01 kernel RPM set."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
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

def _write_all(descriptor: int, value: bytes | memoryview) -> None:
    # The standalone bootstrap must load only the standard library until its
    # frozen import path has been established.
    from tools.gate01.proof_io import _write_all as write
    write(descriptor, value)


def _release_all(actions: Any) -> None:
    from tools.gate01.proof_io import _release_all as release
    release(actions)


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    try:
        BaseException.add_note(primary, note)
    except BaseException:
        pass


def _close_payload_owner(tree: Any, primary: BaseException | None) -> None:
    """Standalone concrete payload drain; no import or bound fallback lookup."""
    try:
        tree.close()
    except BaseException as cleanup:
        remaining = 2
        while remaining:
            remaining -= 1
            try:
                _drain_bound_payload_tree(tree)
                break
            except BaseException:
                _add_cleanup_note(cleanup, "additional concrete descriptor drain failed")
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_descriptors(first: int, second: int = -1, third: int = -1, fourth: int = -1, *, primary: BaseException | None = None) -> None:
    """Small local-owner drain: no cleanup tuple, iterator, or callback allocation."""
    failure = None
    while first >= 0 or second >= 0 or third >= 0 or fourth >= 0:
        if first >= 0:
            descriptor, first = first, -1
        elif second >= 0:
            descriptor, second = second, -1
        elif third >= 0:
            descriptor, third = third, -1
        else:
            descriptor, fourth = fourth, -1
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise RuntimeError("bound descriptor release failed") from failure
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _release_preserving_primary(actions: Any, primary: BaseException | None) -> None:
    from tools.gate01.proof_io import _release_preserving_primary as release
    release(actions, primary)


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
    "tools/gate01/container_runtime.py",
    "tools/gate01/inputs.py",
    "tools/gate01/kernel_bootstrap.py",
    "tools/gate01/kernel_build.py",
    "tools/gate01/kernel_config.py",
    "tools/gate01/module_key.py",
    "tools/gate01/oci_rootfs.py",
    "tools/gate01/proof_io.py",
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
        "tools.gate01.container_runtime",
        "tools.gate01.kernel_config",
        "tools.gate01.kernel_build",
        "tools.gate01.module_key",
        "tools.gate01.oci_rootfs",
        "tools.gate01.proof_io",
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
    "security_metadata",
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

SECURITY_DEPENDENCY_PREFIXES = {
    "requires": "REQUIRE", "provides": "PROVIDE", "conflicts": "CONFLICT",
    "obsoletes": "OBSOLETE", "recommends": "RECOMMEND", "suggests": "SUGGEST",
    "supplements": "SUPPLEMENT", "enhances": "ENHANCE", "order": "ORDER",
}
SECURITY_SCRIPT_NAMES = (
    "PREIN", "POSTIN", "PREUN", "POSTUN", "PRETRANS", "POSTTRANS",
    "PREUNTRANS", "POSTUNTRANS", "VERIFYSCRIPT",
)
SECURITY_FORBIDDEN_TAGS = (
    "OLDSUGGESTSNAME", "OLDSUGGESTSFLAGS", "OLDSUGGESTSVERSION",
    "OLDENHANCESNAME", "OLDENHANCESFLAGS", "OLDENHANCESVERSION",
    "TRIGGERSCRIPTS", "TRIGGERSCRIPTPROG", "TRIGGERSCRIPTFLAGS", "TRIGGERNAME",
    "TRIGGERVERSION", "TRIGGERFLAGS", "TRIGGERINDEX",
    "FILETRIGGERSCRIPTS", "FILETRIGGERSCRIPTPROG", "FILETRIGGERSCRIPTFLAGS",
    "FILETRIGGERNAME", "FILETRIGGERVERSION", "FILETRIGGERFLAGS", "FILETRIGGERINDEX", "FILETRIGGERPRIORITIES",
    "TRANSFILETRIGGERSCRIPTS", "TRANSFILETRIGGERSCRIPTPROG", "TRANSFILETRIGGERSCRIPTFLAGS",
    "TRANSFILETRIGGERNAME", "TRANSFILETRIGGERVERSION", "TRANSFILETRIGGERFLAGS", "TRANSFILETRIGGERINDEX", "TRANSFILETRIGGERPRIORITIES",
    "PREFIXES", "FILECAPS", "FILECONTEXTS", "FSCONTEXTS", "RECONTEXTS",
    "POLICIES", "POLICYNAMES", "POLICYTYPES", "POLICYTYPESINDEXES", "POLICYFLAGS",
    "FILESIGNATURES", "FILESIGNATURELENGTH", "VERITYSIGNATURES", "VERITYSIGNATUREALGO",
    "PAYLOADSHA512", "PAYLOADSHA512ALT", "PAYLOADSHA3_256", "PAYLOADSHA3_256ALT",
    "PAYLOADSIZE", "PAYLOADSIZEALT",
)
SECURITY_FORBIDDEN_RAW_TAG_IDS = frozenset((1177, 1186, 1187))
SECURITY_FILE_TAGS = {
    "path": "FILENAMES", "raw_mode": "FILEMODES", "size": "LONGFILESIZES",
    "user": "FILEUSERNAME", "group": "FILEGROUPNAME", "link_target": "FILELINKTOS",
    "flags": "FILEFLAGS", "verify_flags": "FILEVERIFYFLAGS", "rdev": "FILERDEVS",
    "device": "FILEDEVICES", "inode": "FILEINODES", "digest": "FILEDIGESTS",
}
SECURITY_PAYLOAD_TAGS = {
    "file_digest_algorithm": "FILEDIGESTALGO", "format": "PAYLOADFORMAT",
    "compressor": "PAYLOADCOMPRESSOR", "flags": "PAYLOADFLAGS",
    "sha256_algorithm": "PAYLOADSHA256ALGO", "compressed_sha256": "PAYLOADSHA256",
    "uncompressed_sha256": "PAYLOADSHA256ALT",
}
SECURITY_QUERY_TAGS = tuple(dict.fromkeys((
    *(prefix + suffix for prefix in SECURITY_DEPENDENCY_PREFIXES.values() for suffix in ("NAME", "FLAGS", "VERSION")),
    *(name + suffix for name in SECURITY_SCRIPT_NAMES for suffix in ("", "PROG", "FLAGS")),
    *SECURITY_FORBIDDEN_TAGS, *SECURITY_FILE_TAGS.values(), *SECURITY_PAYLOAD_TAGS.values(),
)))


def _security_dependencies(role: str) -> dict[str, list[dict[str, Any]]]:
    def dependency(name: str, flags: int, version: str) -> dict[str, Any]:
        return {"name": name, "flags": flags, "version": version}
    rpmlib = [dependency(f"rpmlib({name})", 16777226, version) for name, version in (
        ("CompressedFileNames", "3.0.4-1"), ("FileDigests", "4.6.0-1"),
        ("PayloadFilesHavePrefix", "4.0-1"), ("PayloadIsZstd", "5.4.18-1"),
    ) if role != "srpm" or name != "PayloadFilesHavePrefix"]
    result = {family: [] for family in SECURITY_DEPENDENCY_PREFIXES}
    if role == "srpm":
        requires = [dependency(name, 0, "") for name in (
            "bc", "binutils", "bison", "dwarves", "elfutils-libelf-devel", "flex",
            "gcc", "kmod", "make", "openssl", "openssl-devel", "perl-interpreter", "python3", "rsync",
        )]
        provides = [dependency(name, 8, f"{KERNEL_VERSION}-{RPM_RELEASE}") for name in EXPECTED_BINARY_NAMES]
    else:
        name = {"meta": "kernel-openmythos", "core": "kernel-openmythos-core", "modules": "kernel-openmythos-modules"}[role]
        provides = [dependency(item, 8, f"{KERNEL_VERSION}-{RPM_RELEASE}") for item in (name, name + "(x86-64)")]
        if role == "meta":
            requires = [dependency(f"kernel-openmythos-{part}-uname-r", 8, KERNEL_RELEASE) for part in ("core", "modules")]
            provides += [dependency("installonlypkg(kernel)", 0, ""), dependency("kernel", 8, f"{KERNEL_VERSION}-{RPM_RELEASE}")]
        else:
            requires = ([dependency("/bin/sh", 288, ""), dependency("/bin/sh", 2304, "")] if role == "core" else [dependency("kernel-openmythos-core-uname-r", 8, KERNEL_RELEASE)])
            provides += [dependency(f"{prefix}-{role}-uname-r", 8, KERNEL_RELEASE) for prefix in ("kernel", "kernel-openmythos")]
    result["requires"] = sorted([*rpmlib, *requires], key=lambda item: (item["name"], item["flags"], item["version"]))
    result["provides"] = sorted(provides, key=lambda item: (item["name"], item["flags"], item["version"]))
    return result


def _security_scripts(role: str) -> dict[str, Any]:
    if role != "core":
        return {}
    return {
        "POSTTRANS": {"body": 'if [[ ${OPENMYTHOS_IMAGE_BUILD:-0} != 1 ]]; then\n  /usr/bin/kernel-install add "6.18.48-1.openmythos.fc44.x86_64" \\\n    "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64/vmlinuz"\nfi', "argv": ["/bin/sh"], "flags": None},
        "PREUN": {"body": 'if [[ $1 -eq 0 && ${OPENMYTHOS_IMAGE_BUILD:-0} != 1 ]]; then\n  /usr/bin/kernel-install remove "6.18.48-1.openmythos.fc44.x86_64"\nfi', "argv": ["/bin/sh"], "flags": None},
    }


def _validate_security_metadata(value: Any, role: str, package_files: list[dict[str, Any]] | None = None) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version", "dependencies", "scripts", "forbidden_tags", "files", "payload"} or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("RPM security_metadata schema is not exact")
    if value["dependencies"] != _security_dependencies(role):
        raise ValueError("RPM security_metadata dependency tuples are not exact")
    # Equality alone must not admit bool-as-int aliases for dependency flags.
    for records in value["dependencies"].values():
        if any(type(record.get("flags")) is not int for record in records):
            raise ValueError("RPM security_metadata dependency flags are invalid")
    if value["scripts"] != _security_scripts(role) or value["forbidden_tags"] != []:
        raise ValueError("RPM security_metadata scripts or forbidden tags are not exact")
    payload = value["payload"]
    if not isinstance(payload, dict) or set(payload) != set(SECURITY_PAYLOAD_TAGS):
        raise ValueError("RPM security_metadata payload schema is not exact")
    for key, expected in {"format": "cpio", "compressor": "zstd", "flags": "19", "file_digest_algorithm": 8, "sha256_algorithm": 8}.items():
        if type(payload[key]) is not type(expected) or payload[key] != expected:
            raise ValueError("RPM security_metadata payload policy differs")
    for key in ("compressed_sha256", "uncompressed_sha256"):
        if not isinstance(payload[key], str) or RAW_SHA256_RE.fullmatch(payload[key]) is None:
            raise ValueError("RPM security_metadata payload digest is invalid")
    files = value["files"]
    if not isinstance(files, list):
        raise ValueError("RPM security_metadata files must be an array")
    paths, identities, observed = [], set(), {}
    for record in files:
        if not isinstance(record, dict) or set(record) != set(SECURITY_FILE_TAGS):
            raise ValueError("RPM security_metadata file schema is not exact")
        path = _validate_absolute_payload_path(record["path"])
        paths.append(path.as_posix())
        for key in ("raw_mode", "size", "flags", "verify_flags", "rdev", "device", "inode"):
            if type(record[key]) is not int or record[key] < 0:
                raise ValueError("RPM security_metadata numeric file field is invalid")
        kind = stat.S_IFMT(record["raw_mode"])
        if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) or record["raw_mode"] != kind | {stat.S_IFREG: 0o644, stat.S_IFDIR: 0o755, stat.S_IFLNK: 0o777}[kind]:
            raise ValueError("RPM security_metadata file mode is unsafe")
        if record["user"] != "root" or record["group"] != "root" or record["flags"] != (32 if role == "srpm" and path.as_posix() == "/kernel-openmythos.spec" else 0) or record["verify_flags"] != 0xffffffff or record["rdev"] != 0 or record["device"] != 1 or record["inode"] <= 0:
            raise ValueError("RPM security_metadata file installation policy differs")
        identity = (record["device"], record["inode"])
        if identity in identities:
            raise ValueError("RPM security_metadata file hardlink alias is forbidden")
        identities.add(identity)
        if kind == stat.S_IFREG:
            if record["link_target"] != "" or not isinstance(record["digest"], str) or RAW_SHA256_RE.fullmatch(record["digest"]) is None:
                raise ValueError("RPM security_metadata regular digest or link differs")
        elif kind == stat.S_IFDIR:
            if record["size"] != 0 or record["link_target"] != "" or record["digest"] != "":
                raise ValueError("RPM security_metadata directory fields differ")
        else:
            _validate_symlink_target(path, record["link_target"])
            if record["digest"] != "" or record["size"] != len(os.fsencode(record["link_target"])):
                raise ValueError("RPM security_metadata symlink fields differ")
        if kind != stat.S_IFDIR:
            observed[path.as_posix()] = record
    if paths != sorted(set(paths)):
        raise ValueError("RPM security_metadata file paths are not sorted and unique")
    if role == "srpm":
        if set(paths) != {"/kernel-openmythos.spec", "/linux-6.18.48.tar.xz", "/6.18.48-x86_64.config", "/module-signing.pem"} or len(observed) != 4 or any(stat.S_IFMT(record["raw_mode"]) != stat.S_IFREG for record in files):
            raise ValueError("RPM security_metadata source payload is not exact")
    else:
        _validate_pre_extraction_paths(Path("<security-metadata>"), [{key: record[key] for key in ("path", "raw_mode", "size", "user", "group", "link_target")} for record in files], listing_override=paths)
    if package_files is not None:
        if set(observed) != {record["path"] for record in package_files}:
            raise ValueError("RPM security_metadata differs from installed paths")
        for record in package_files:
            security = observed[record["path"]]
            if any(security[key] != record[key] for key in ("size", "user", "group")) or f"{stat.S_IMODE(security['raw_mode']):04o}" != record["mode"] or (record["type"] == "file" and security["digest"] != record["sha256"]) or (record["type"] == "symlink" and security["link_target"] != record["link_target"]):
                raise ValueError("RPM security_metadata differs from installed content")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: <redacted>")
        result[key] = value
    return result


def _require_exact_fields(
    value: dict[str, Any], expected: set[str], description: str
) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown or missing:
        raise ValueError(
            f"{description} unknown fields=<redacted> "
            f"missing=<redacted>"
        )


def load_rpm_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
    )
    if not isinstance(value, dict):
        raise ValueError("RPM manifest root must be an object")
    validate_rpm_manifest(value)
    return value


def _validate_absolute_payload_path(path: str) -> PurePosixPath:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("RPM payload path must be absolute")
    pure = PurePosixPath(path)
    if "." in pure.parts or ".." in pure.parts or pure.as_posix() != path:
        raise ValueError(
            f"RPM payload path is not normalized or escapes its release tree: <redacted>"
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
        raise ValueError(f"invalid symlink target for <redacted>")
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
                raise ValueError(f"symlink target escapes release tree: <redacted>")
            normalized_parts.pop()
        else:
            normalized_parts.append(part)
    normalized = PurePosixPath("/", *normalized_parts)
    if not _inside_release_tree(normalized):
        raise ValueError(f"symlink target escapes release tree: <redacted>")


def _validate_file_record(record: Any, package_name: str) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{package_name} file record must be an object")
    path_value = record.get("path")
    path = _validate_absolute_payload_path(path_value)
    if package_name in EXPECTED_BINARY_NAMES[1:] and not _inside_release_tree(path):
        raise ValueError(f"{package_name} file is outside kernel release tree: <redacted>")
    if path.as_posix().lower().endswith(PRIVATE_KEY_SUFFIXES):
        raise ValueError(f"private-key suffix is forbidden in RPM payload: <redacted>")
    if COMPRESSED_MODULE_RE.search(path.as_posix()):
        raise ValueError(f"compressed module is forbidden: <redacted>")

    record_type = record.get("type")
    is_module = path.as_posix().endswith(".ko")
    if is_module and record_type == "symlink":
        raise ValueError(f"module symlink is forbidden: <redacted>")
    if record_type == "file":
        expected_fields = MODULE_FILE_FIELDS if is_module else REGULAR_FILE_FIELDS
    elif record_type == "symlink":
        expected_fields = SYMLINK_FIELDS
    else:
        raise ValueError(f"unsupported RPM payload type for <redacted>: <redacted>")
    _require_exact_fields(record, expected_fields, f"file record {path}")

    if not isinstance(record["mode"], str) or not MODE_RE.fullmatch(record["mode"]):
        raise ValueError(f"invalid mode for <redacted>")
    expected_mode = "0644" if record_type == "file" else "0777"
    if record["mode"] != expected_mode:
        raise ValueError(f"unsafe or unexpected mode for <redacted>")
    if type(record["size"]) is not int or record["size"] < 0:
        raise ValueError(f"invalid size for <redacted>")
    if record["user"] != "root" or record["group"] != "root":
        raise ValueError(f"RPM payload ownership must be root:root: <redacted>")

    if record_type == "symlink":
        _validate_symlink_target(path, record["link_target"])
        return

    if not isinstance(record["sha256"], str) or not RAW_SHA256_RE.fullmatch(
        record["sha256"]
    ):
        raise ValueError(f"invalid file SHA-256 for <redacted>")
    if type(record["private_key_marker"]) is not bool:
        raise ValueError(f"private_key_marker must be boolean for <redacted>")
    if record["private_key_marker"]:
        raise ValueError(f"PRIVATE KEY marker found in RPM payload: <redacted>")

    if is_module:
        if record["signer"] != MODULE_SIGNER:
            raise ValueError(f"module signer mismatch for <redacted>")
        if record["sig_id"] != "PKCS#7":
            raise ValueError(f"module sig_id mismatch for <redacted>")
        vermagic = record["vermagic"]
        if (
            not isinstance(vermagic, str)
            or not vermagic.split()
            or vermagic.split()[0] != KERNEL_RELEASE
        ):
            raise ValueError(f"module vermagic mismatch for <redacted>")


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
    normalized = {field: package[field] for field in SOURCE_PACKAGE_FIELDS if field in package}
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
    role = "srpm" if source else {"kernel-openmythos": "meta", "kernel-openmythos-core": "core", "kernel-openmythos-modules": "modules"}[package["name"]]
    if source:
        _validate_security_metadata(package["security_metadata"], role)
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
    _validate_security_metadata(package["security_metadata"], role, files)


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
        raise ValueError(f"Python proof module is not allowlisted: <redacted>")
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
            raise ValueError(f"isolated Python path has an undeclared entry: <redacted>")
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
                raise ValueError(f"frozen helper directory is unsafe: <redacted>")
            observed_directories.add(relative)
        elif stat.S_ISREG(status.st_mode):
            if status.st_nlink != 1 or stat.S_IMODE(status.st_mode) != 0o444:
                raise ValueError(f"frozen helper file is unsafe: <redacted>")
            observed_files.add(relative)
        else:
            raise ValueError(f"frozen helper tree contains a special entry: <redacted>")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ValueError("frozen helper tree is not the exact import closure")

    for relative in FROZEN_HELPER_PATHS:
        source = source_root / relative
        frozen = snapshot_root / relative
        try:
            source_before = source.lstat()
            frozen_before = frozen.lstat()
        except OSError as error:
            raise ValueError(f"frozen helper is missing: <redacted>") from error
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source.is_symlink()
            or not stat.S_ISREG(frozen_before.st_mode)
            or frozen.is_symlink()
        ):
            raise ValueError(f"frozen helper must be a regular non-symlink: <redacted>")
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
            raise ValueError(f"frozen helper identity differs from source: <redacted>")


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
    rpm_security_metadata = "pass" if [package["security_metadata"] for package in [*left["source_rpms"], *left["binary_rpms"]]] == [package["security_metadata"] for package in [*right["source_rpms"], *right["binary_rpms"]]] else "fail"
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
    hard_results = (source_rpm, package_nevras, installed_files, module_signatures, rpm_security_metadata)
    return {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "source_rpm": source_rpm,
        "package_nevras": package_nevras,
        "installed_files": installed_files,
        "module_signatures": module_signatures,
        "rpm_security_metadata": rpm_security_metadata,
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
    descriptor = -1
    try:
        try:
            descriptor = os.open(directory, flags)
            opened = os.fstat(descriptor)
            path_status = directory.lstat()
        except OSError as error:
            raise ValueError(f"{description} is missing or unsafe: <redacted>") from error
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
            raise ValueError(f"{description} is not stable: <redacted>")
        result = {
            "descriptor": descriptor,
            "path": directory,
            "before": opened,
            "names": sorted(os.listdir(descriptor)),
            "description": description,
        }
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _verify_bound_directory(record: dict[str, Any]) -> None:
    descriptor = record["descriptor"]
    directory = record["path"]
    try:
        after = os.fstat(descriptor)
        path_after = directory.lstat()
    except OSError as error:
        raise ValueError(f"{record['description']} changed: <redacted>") from error
    if (
        sorted(os.listdir(descriptor)) != record["names"]
        or _status_identity(record["before"]) != _status_identity(after)
        or (after.st_dev, after.st_ino)
        != (path_after.st_dev, path_after.st_ino)
        or stat.S_ISLNK(path_after.st_mode)
    ):
        raise ValueError(f"{record['description']} changed: <redacted>")


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
    descriptor = -1
    try:
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
            raise ValueError(f"{description} is missing or unsafe: <redacted>") from error
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
            raise ValueError(f"{description} must be one safe regular file: <redacted>")
        result = {
            "descriptor": descriptor,
            "path": path,
            "before": opened,
            "description": description,
        }
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


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
            f"{record['description']} changed: <redacted>"
        ) from error
    if (
        _status_identity(record["before"]) != _status_identity(after)
        or not stat.S_ISREG(path_after.st_mode)
        or after.st_nlink != 1
        or (after.st_dev, after.st_ino)
        != (path_after.st_dev, path_after.st_ino)
    ):
        raise ValueError(f"{record['description']} changed: <redacted>")


def _close_bound_records(records: list[dict[str, Any]]) -> None:
    failure = None
    while records:
        try:
            record = records.pop()
        except BaseException as error:
            if failure is None:
                failure = error
            record = list.pop(records)
        descriptor = record["descriptor"]
        record["descriptor"] = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
    if failure is not None:
        raise RuntimeError("bound record cleanup failed") from failure


def _close_bound_record(record: dict[str, Any]) -> None:
    descriptor, record["descriptor"] = record["descriptor"], -1
    if descriptor >= 0:
        os.close(descriptor)


def _close_bound_record_pair(files: list[dict[str, Any]], directories: list[dict[str, Any]], primary: BaseException | None) -> None:
    failure = None
    try:
        _close_bound_records(files)
    except BaseException as error:
        failure = error
        if primary is not None:
            _add_cleanup_note(primary, "additional final proof files cleanup failed")
    finally:
        try:
            _close_bound_records(directories)
        except BaseException as error:
            if failure is None:
                failure = error
            if primary is not None:
                _add_cleanup_note(primary, "additional final proof directories cleanup failed")
    if failure is not None and primary is None:
        raise RuntimeError("final proof boundary cleanup failed") from failure


def _transfer_bound_records(destination: list[dict[str, Any]], source: list[dict[str, Any]]) -> None:
    try:
        while source:
            destination.append(source[0])
            source.pop(0)
    except BaseException as primary:
        _release_primary = primary
        try:
            _close_bound_records(source)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


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
        try:
            directories.append(root_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(root_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        if root_record["names"] != ["x86_64"]:
            raise ValueError("retained RPM root must contain only x86_64")
        rpm_record = _open_bound_directory(rpm_dir, "retained RPM set")
        try:
            directories.append(rpm_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(rpm_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
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
        try:
            directories.append(srpm_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(srpm_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        source_names = sorted(source_expected)
        binary_names = sorted(binary_expected)
        if srpm_record["names"] != source_names:
            raise ValueError(f"retained RPM set is not exact: <redacted>")
        if rpm_record["names"] != binary_names:
            raise ValueError(f"retained RPM set is not exact: <redacted>")
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
                try:
                    files.append(file_record)
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        _close_bound_record(file_record)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                file_record["kind"] = "rpm"
                expected[os.fspath(path)] = digests[name]
        return files, directories, expected
    except BaseException:
        _close_bound_record_pair(files, directories, sys.exception())
        raise


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
        _release_primary = sys.exception()
        try:
            os.close(record['descriptor'])
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


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
        _close_bound_record_pair(files, directories, sys.exception())


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
        for path, description in ((snapshot_root, "frozen helper root"), (snapshot_root / "tools", "frozen tools package"), (snapshot_root / "tools/gate01", "frozen Gate 01 package")):
            record = _open_bound_directory(path, description, expected_mode=0o555)
            try:
                directories.append(record)
            except BaseException as primary:
                _release_primary = primary
                try:
                    _close_bound_record(record)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
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
        _release_primary = sys.exception()
        try:
            _close_bound_records(directories)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
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
        try:
            files.append(early_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(early_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        early_record["kind"] = "source-manifest"
        final_record = _open_bound_regular(
            _absolute_lexical_path(final_source_manifest),
            "final proof source manifest",
        )
        try:
            files.append(final_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(final_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        final_record["kind"] = "source-manifest"
        rpm_manifest_record = _open_bound_regular(
            _absolute_lexical_path(rpm_manifest_path), "RPM artifact manifest"
        )
        try:
            files.append(rpm_manifest_record)
        except BaseException as primary:
            _release_primary = primary
            try:
                _close_bound_record(rpm_manifest_record)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        rpm_manifest_record["kind"] = "rpm-manifest"

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
        _transfer_bound_records(directories, frozen_directories)
        live_records: dict[str, dict[str, Any]] = {}
        snapshot_records: dict[str, dict[str, Any]] = {}
        for relative in PROOF_SOURCE_PATHS:
            live_record = _open_bound_regular(
                source_root / relative, f"live proof source {relative}"
            )
            try:
                files.append(live_record)
            except BaseException as primary:
                _release_primary = primary
                try:
                    _close_bound_record(live_record)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            live_record["kind"] = "proof-source"
            live_record["relative"] = relative
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
            try:
                files.append(snapshot_record)
            except BaseException as primary:
                _release_primary = primary
                try:
                    _close_bound_record(snapshot_record)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            snapshot_record["kind"] = "proof-snapshot"
            snapshot_record["relative"] = relative
            snapshot_records[relative] = snapshot_record

        rpm_files, rpm_directories, rpm_expected = _open_retained_rpm_set(
            rpm_dir, srpm_dir, rpm_manifest
        )
        try:
            _transfer_bound_records(files, rpm_files)
            _transfer_bound_records(directories, rpm_directories)
        finally:
            _close_bound_record_pair(rpm_files, rpm_directories, sys.exception())

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
                raise ValueError(f"proof source changed or differs: <redacted>")
        for record in files:
            if record.get("kind") != "rpm":
                continue
            digest = digest_by_descriptor[record["descriptor"]]
            if digest != rpm_expected[os.fspath(record["path"])]:
                raise ValueError(
                    "retained RPM hash differs from inspected manifest: "
                    f"{record['path'].name}"
                )
    finally:
        _close_bound_record_pair(files, directories, sys.exception())


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
        raise ValueError(f"RPM input must be a readable regular non-symlink: <redacted>") from error
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        path_before = source.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino)
        ):
            raise ValueError(f"RPM input must be a regular non-symlink: <redacted>")
        destination_descriptor = os.open(
            destination,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        digest = hashlib.sha256()
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
            _write_all(destination_descriptor, chunk)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        try:
            path_after = source.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"RPM input changed while being snapshotted: <redacted>") from error
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
            raise ValueError(f"RPM input changed while being snapshotted: <redacted>")
        os.fchmod(destination_descriptor, 0o444)
        os.fsync(destination_descriptor)
        from tools.gate01.proof_io import _verify_written_output
        _verify_written_output(destination_descriptor, before.st_size, digest.hexdigest())
        return digest.hexdigest()
    except BaseException:
        _release_primary = sys.exception()
        try:
            destination.unlink(missing_ok=True)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    finally:
        _close_descriptors(source_descriptor, destination_descriptor, primary=sys.exception())


def _contains_private_key_marker_descriptor(descriptor: int) -> bool:
    carry = b""
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 64 * 1024):
        combined = carry + chunk
        if PRIVATE_KEY_MARKER in combined:
            return True
        carry = combined[-(len(PRIVATE_KEY_MARKER) - 1) :]
    if _status_identity(before) != _status_identity(os.fstat(descriptor)):
        raise ValueError("payload changed while scanning for private key markers")
    return False


def _contains_private_key_marker(path: Path) -> bool:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return _contains_private_key_marker_descriptor(descriptor)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _sealed_bytes_descriptor(name: str, value: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
        from tools.gate01.proof_io import _verify_written_output
        _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())
        import fcntl

        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def _validate_module_cms_profile(signature: bytes) -> None:
    """Require the exact detached, no-attributes, no-certs sign-file profile."""
    from tools.gate01.module_key import _der_elements

    sha256 = bytes.fromhex("608648016503040201")
    rsa_encryption = bytes.fromhex("2a864886f70d010101")

    def children(node: tuple[int, bytes], tag: int) -> list[tuple[int, bytes]]:
        if node[0] != tag:
            raise ValueError("unexpected CMS field")
        return _der_elements(node[1])

    def digest(node: tuple[int, bytes]) -> None:
        if children(node, 0x30) not in ([(6, sha256)], [(6, sha256), (5, b"")]):
            raise ValueError("CMS digest algorithm is not exactly SHA-256")

    try:
        outer = _der_elements(signature)
        if len(outer) != 1:
            raise ValueError("CMS input contains extra DER objects")
        content_info = children(outer[0], 0x30)
        if len(content_info) != 2 or content_info[0] != (6, bytes.fromhex("2a864886f70d010702")):
            raise ValueError("CMS ContentInfo is not signedData")
        explicit = children(content_info[1], 0xa0)
        if len(explicit) != 1:
            raise ValueError("CMS SignedData wrapper is not singular")
        fields = children(explicit[0], 0x30)
        if len(fields) != 4 or fields[0] != (2, b"\x01"):
            raise ValueError("CMS SignedData contains unapproved fields or version")
        algorithms = children(fields[1], 0x31)
        if len(algorithms) != 1:
            raise ValueError("CMS requires exactly one SHA-256 digest algorithm")
        digest(algorithms[0])
        if children(fields[2], 0x30) != [(6, bytes.fromhex("2a864886f70d010701"))]:
            raise ValueError("CMS content must be detached id-data")
        signers = children(fields[3], 0x31)
        if len(signers) != 1:
            raise ValueError("CMS requires exactly one signer")
        signer = children(signers[0], 0x30)
        if len(signer) != 5 or signer[0] != (2, b"\x01"):
            raise ValueError("CMS SignerInfo contains unapproved attributes or version")
        identifier = children(signer[1], 0x30)
        if len(identifier) != 2 or identifier[0][0] != 0x30 or identifier[1][0] != 2 or not identifier[1][1] or identifier[1][1][0] & 0x80:
            raise ValueError("CMS signer must use issuer and nonnegative serial")
        digest(signer[2])
        if children(signer[3], 0x30) != [(6, rsa_encryption), (5, b"")]:
            raise ValueError("CMS signature algorithm must be rsaEncryption with NULL")
        if signer[4][0] != 4 or not signer[4][1]:
            raise ValueError("CMS signature must be one nonempty OCTET STRING")
    except ValueError as error:
        raise ValueError("module CMS is outside the exact SHA-256 sign-file DER profile") from error


@contextmanager
def _borrowed_binary_stream(descriptor: int):
    """Own a duplicate before the fallible stream allocation and body."""
    duplicate = os.dup(descriptor)
    stream = None
    try:
        stream = os.fdopen(duplicate, "rb", closefd=False)
        yield stream
    finally:
        primary = sys.exception()
        failure = None
        try:
            if stream is not None:
                stream.close()
        except BaseException as error:
            failure = error
        finally:
            descriptor, duplicate = duplicate, -1
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            if primary is None:
                raise failure
            from tools.gate01.proof_io import _add_cleanup_note
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _verify_module_signature_descriptors(
    module_descriptor: int,
    certificate_descriptor: int,
    *,
    display: str,
) -> None:
    """Verify one exact module FD against one exact public certificate FD."""
    module_status = os.fstat(module_descriptor)
    certificate_status = os.fstat(certificate_descriptor)
    if not stat.S_ISREG(certificate_status.st_mode):
        raise ValueError("public certificate descriptor must be a regular file")
    if not stat.S_ISREG(module_status.st_mode):
        raise ValueError(f"module descriptor must be a regular file: <redacted>")
    from tools.gate01.module_key import require_single_certificate_descriptor

    require_single_certificate_descriptor(certificate_descriptor)
    suffix_size = len(MODULE_SIGNATURE_MARKER) + MODULE_SIGNATURE_HEADER_SIZE
    if module_status.st_size <= suffix_size:
        raise ValueError(f"module cryptographic signature is missing: <redacted>")
    os.lseek(module_descriptor, -suffix_size, os.SEEK_END)
    with _borrowed_binary_stream(module_descriptor) as stream:
        raw_header = _read_exact(stream, MODULE_SIGNATURE_HEADER_SIZE, "module signature header")
        marker = _read_exact(stream, len(MODULE_SIGNATURE_MARKER), "module marker")
    if marker != MODULE_SIGNATURE_MARKER:
        raise ValueError(f"module cryptographic signature marker mismatch: <redacted>")
    algorithm, hash_algorithm, identifier, signer_length, key_id_length = raw_header[:5]
    if (
        algorithm != 0
        or hash_algorithm != 0
        or identifier != 2
        or signer_length != 0
        or key_id_length != 0
        or raw_header[5:8] != b"\0\0\0"
    ):
        raise ValueError(f"module cryptographic signature header is invalid: <redacted>")
    signature_size = int.from_bytes(raw_header[8:12], "big")
    content_size = module_status.st_size - suffix_size - signature_size
    if signature_size == 0 or content_size <= 0:
        raise ValueError(f"module cryptographic signature length is invalid: <redacted>")

    before = os.fstat(module_descriptor)
    os.lseek(module_descriptor, 0, os.SEEK_SET)
    content = bytearray()
    remaining = content_size
    while remaining:
        chunk = os.read(module_descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            raise ValueError(f"module changed while verifying signature: <redacted>")
        content.extend(chunk)
        remaining -= len(chunk)
    signature = os.read(module_descriptor, signature_size)
    if len(signature) != signature_size:
        raise ValueError(f"module changed while verifying signature: <redacted>")
    if _status_identity(before) != _status_identity(os.fstat(module_descriptor)):
        raise ValueError(f"module changed while verifying signature: <redacted>")
    _validate_module_cms_profile(signature)
    content_descriptor = signature_descriptor = -1
    try:
        content_descriptor = _sealed_bytes_descriptor("module-content", bytes(content))
        signature_descriptor = _sealed_bytes_descriptor("module-signature", signature)
        result = subprocess.run(
            [
                "/usr/bin/openssl",
                "cms",
                "-verify",
                "-verify_retcode",
                "-binary",
                "-inform",
                "DER",
                "-in",
                f"/proc/self/fd/{signature_descriptor}",
                "-content",
                f"/proc/self/fd/{content_descriptor}",
                "-nointern",
                "-certfile",
                f"/proc/self/fd/{certificate_descriptor}",
                "-noverify",
                "-out",
                os.devnull,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(
                signature_descriptor,
                content_descriptor,
                certificate_descriptor,
            ),
        )
    finally:
        first = signature_descriptor
        second = content_descriptor
        signature_descriptor = content_descriptor = -1
        _close_descriptors(first, second, primary=sys.exception())
    if result.returncode != 0:
        raise ValueError(f"module cryptographic signature verification failed: <redacted>")
    if _status_identity(module_status) != _status_identity(os.fstat(module_descriptor)) or _status_identity(certificate_status) != _status_identity(os.fstat(certificate_descriptor)):
        raise ValueError("module or certificate changed during cryptographic verification")


def _verify_module_signature(module: Path, public_certificate: Path) -> None:
    """Path-compatible wrapper that binds both files before verification."""
    module_descriptor = os.open(
        module, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        certificate_descriptor = os.open(
            public_certificate,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            _verify_module_signature_descriptors(
                module_descriptor,
                certificate_descriptor,
                display=os.fspath(module),
            )
        finally:
            _release_primary = sys.exception()
            try:
                os.close(certificate_descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    finally:
        _release_primary = sys.exception()
        try:
            os.close(module_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _run_text(arguments: Sequence[str], *, cwd: Path | None = None) -> str:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _run_text_for_descriptors(
    arguments: tuple[str, ...], descriptors: tuple[int, ...]
) -> str:
    return subprocess.run(
        list(arguments),
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=descriptors,
    ).stdout


def _query_package(path: Path) -> dict[str, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        return _query_package_descriptor(descriptor)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _query_package_descriptor(descriptor: int) -> dict[str, str]:
    tags = ("NAME", "EPOCH", "VERSION", "RELEASE", "ARCH", "NEVRA", "SOURCEPACKAGE", "SOURCERPM")
    values = _query_rpm_tag_values(descriptor, tags)
    fields = {}
    for key, tag in zip(("name", "epoch", "version", "release", "architecture", "nevra", "source_package", "source_rpm"), tags, strict=True):
        raw = values[tag]
        if tag in ("EPOCH", "SOURCEPACKAGE"):
            if not raw:
                fields[key] = "0"
            elif len(raw) == 1 and type(raw[0]) is int and raw[0] >= 0:
                fields[key] = str(raw[0])
            else:
                raise ValueError("held RPM identity integer field is invalid")
        elif tag == "SOURCERPM" and not raw:
            fields[key] = "(none)"
        elif len(raw) == 1 and type(raw[0]) is str:
            fields[key] = raw[0]
        else:
            raise ValueError("held RPM identity text field is invalid")
    fields["sha256"] = _sha256_descriptor(descriptor)
    return fields


def _normalize_binary_package_identity(package: dict[str, str]) -> dict[str, str]:
    if package.get("source_package") == "1":
        raise ValueError("source RPM cannot be accepted as a binary RPM")
    if package.get("source_rpm") != EXPECTED_SOURCE_FILENAME:
        raise ValueError("binary RPM source identity is not exact")
    return {field: package[field] for field in SOURCE_PACKAGE_FIELDS if field in package}


def _query_file_headers(path: Path) -> list[dict[str, Any]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        return _query_file_headers_descriptor(descriptor)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _parse_rpm_tag_values(output: bytes, tags: tuple[str, ...]) -> dict[str, list[Any]]:
    try:
        lines = output.decode("utf-8").split("\n")
        offset = 0
        result = {}
        for tag in tags:
            if lines[offset] != tag or lines[offset + 1] not in ("0", "1") or re.fullmatch(r"0|[1-9][0-9]{0,6}", lines[offset + 2]) is None:
                raise ValueError("invalid RPM tag framing")
            present, count = lines[offset + 1], int(lines[offset + 2])
            offset += 3
            if (present == "0" and count != 0) or (present == "1" and count == 0) or count > len(lines) - offset:
                raise ValueError("invalid RPM tag presence/count")
            values = []
            for line in lines[offset:offset + count]:
                value = json.loads(line, object_pairs_hook=_reject_duplicate_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite RPM tag")))
                if type(value) not in (str, int):
                    raise ValueError("unsupported RPM tag JSON type")
                values.append(value)
            result[tag] = values
            offset += count
        if lines[offset:] != [""]:
            raise ValueError("RPM query contains extra output")
        return result
    except (IndexError, UnicodeError, ValueError) as error:
        raise ValueError("RPM metadata query framing is invalid") from None


def _query_rpm_tag_values(descriptor: int, tags: tuple[str, ...]) -> dict[str, list[Any]]:
    # `tags` is supplied only by frozen policy code, never candidate values.
    if not tags or len(tags) != len(set(tags)) or any(re.fullmatch(r"[A-Z][A-Z0-9_]*", tag) is None for tag in tags):
        raise ValueError("RPM policy query tags are invalid")
    supported = subprocess.run(["/usr/bin/rpm", "--querytags"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if supported.returncode or supported.stderr:
        raise ValueError("RPM supported-tag query failed")
    try:
        names = supported.stdout.decode("ascii").split("\n")
    except UnicodeError:
        raise ValueError("RPM supported-tag inventory is invalid") from None
    if not names or names[-1] != "" or any(re.fullmatch(r"[A-Z][A-Z0-9_]*", name) is None for name in names[:-1]) or len(names[:-1]) != len(set(names[:-1])) or not set(tags) <= set(names[:-1]):
        raise ValueError("RPM policy requires an unsupported query tag")
    query = "".join(tag + "\n%|" + tag + "?{1\n%{" + tag + ":arraysize}\n[%{" + tag + ":json}\n]}:{0\n0\n}|" for tag in tags)
    result = subprocess.run(["/usr/bin/rpm", "--nomanifest", "-qp", "--qf", query, f"/proc/self/fd/{descriptor}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, pass_fds=(descriptor,))
    if result.returncode or result.stderr:
        raise ValueError("held RPM metadata query failed")
    return _parse_rpm_tag_values(result.stdout, tags)


def _parallel_rpm_records(values: dict[str, list[Any]], fields: dict[str, str]) -> list[dict[str, Any]]:
    counts = {len(values[tag]) for tag in fields.values()}
    if len(counts) != 1:
        raise ValueError("RPM parallel metadata arrays differ")
    return [dict(zip(fields, row, strict=True)) for row in zip(*(values[tag] for tag in fields.values()), strict=True)]


def _query_file_headers_descriptor(descriptor: int) -> list[dict[str, Any]]:
    fields = {key: SECURITY_FILE_TAGS[key] for key in ("path", "raw_mode", "size", "user", "group", "link_target")}
    records = _parallel_rpm_records(_query_rpm_tag_values(descriptor, tuple(fields.values())), fields)
    if any(type(record[key]) is not expected for record in records for key, expected in (("path", str), ("raw_mode", int), ("size", int), ("user", str), ("group", str), ("link_target", str))):
        raise ValueError("RPM file header metadata types are invalid")
    return records


def _rpm_payload_location(descriptor: int) -> tuple[int, frozenset[int]]:
    """Parse both v4 RPM header inventories, including unqueryable tag IDs."""
    size = os.fstat(descriptor).st_size
    lead = os.pread(descriptor, 96, 0)
    if len(lead) != 96 or lead[:4] != b"\xed\xab\xee\xdb" or lead[4:6] != b"\x03\x00":
        raise ValueError("held RPM lead is not the pinned format")
    def header(offset: int) -> tuple[int, frozenset[int]]:
        prefix = os.pread(descriptor, 16, offset)
        if len(prefix) != 16 or prefix[:8] != b"\x8e\xad\xe8\x01\0\0\0\0":
            raise ValueError("held RPM header prefix is invalid")
        count, data_size = int.from_bytes(prefix[8:12], "big"), int.from_bytes(prefix[12:16], "big")
        end = offset + 16 + 16 * count + data_size
        if count > 65536 or data_size > 64 * 1024 * 1024 or end > size:
            raise ValueError("held RPM header range is invalid")
        indexes = os.pread(descriptor, count * 16, offset + 16)
        tags = []
        for position in range(0, len(indexes), 16):
            tag, kind, start, elements = (int.from_bytes(indexes[position + field:position + field + 4], "big") for field in (0, 4, 8, 12))
            if kind not in range(1, 10) or elements == 0 or start >= data_size or tag in SECURITY_FORBIDDEN_RAW_TAG_IDS:
                raise ValueError("held RPM contains invalid or forbidden raw header metadata")
            tags.append(tag)
        if len(tags) != count or len(set(tags)) != len(tags):
            raise ValueError("held RPM raw header contains duplicate tags")
        return end, frozenset(tags)
    signature_end, _ = header(96)
    main_start = (signature_end + 7) & ~7
    if os.pread(descriptor, main_start - signature_end, signature_end) != b"\0" * (main_start - signature_end):
        raise ValueError("held RPM signature padding is invalid")
    payload_start, tags = header(main_start)
    if payload_start >= size:
        raise ValueError("held RPM compressed payload is absent")
    return payload_start, tags


def _compressed_payload_sha256(descriptor: int) -> str:
    offset, _ = _rpm_payload_location(descriptor)
    digest = hashlib.sha256()
    while chunk := os.pread(descriptor, 1024 * 1024, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _query_security_metadata(descriptor: int, role: str, headers: list[dict[str, Any]], cpio_records: dict[str, dict[str, Any]], spool_descriptor: int) -> dict[str, Any]:
    values = _query_rpm_tag_values(descriptor, SECURITY_QUERY_TAGS)
    forbidden = [tag for tag in SECURITY_FORBIDDEN_TAGS if values[tag]]
    dependencies = {}
    for family, prefix in SECURITY_DEPENDENCY_PREFIXES.items():
        records = _parallel_rpm_records(values, {"name": prefix + "NAME", "flags": prefix + "FLAGS", "version": prefix + "VERSION"})
        if any(type(record[key]) is not expected for record in records for key, expected in (("name", str), ("flags", int), ("version", str))):
            raise ValueError("RPM dependency metadata types are invalid")
        dependencies[family] = sorted(records, key=lambda item: (item["name"], item["flags"], item["version"]))
    scripts = {}
    for name in SECURITY_SCRIPT_NAMES:
        body, argv, flags = values[name], values[name + "PROG"], values[name + "FLAGS"]
        if body or argv or flags:
            if len(body) != 1 or type(body[0]) is not str or not argv or any(type(value) is not str for value in argv) or flags:
                raise ValueError("RPM scriptlet metadata is not exact")
            scripts[name] = {"body": body[0], "argv": argv, "flags": None}
    payload = {}
    for key, tag in SECURITY_PAYLOAD_TAGS.items():
        if len(values[tag]) != 1:
            raise ValueError("RPM payload scalar metadata is not singular")
        payload[key] = values[tag][0]
    files = _parallel_rpm_records(values, SECURITY_FILE_TAGS)
    if role == "srpm":
        files = _source_headers(files)
    files.sort(key=lambda record: record["path"])
    result = {"schema_version": 1, "dependencies": dependencies, "scripts": scripts, "forbidden_tags": forbidden, "files": files, "payload": payload}
    _validate_security_metadata(result, role)
    if [{key: record[key] for key in ("path", "raw_mode", "size", "user", "group", "link_target")} for record in files] != sorted(headers, key=lambda record: record["path"]):
        raise ValueError("RPM security metadata differs from held file headers")
    if payload["compressed_sha256"] != _compressed_payload_sha256(descriptor) or payload["uncompressed_sha256"] != _sha256_descriptor(spool_descriptor):
        raise ValueError("RPM payload digest differs from held payload bytes")
    for record in files:
        if stat.S_ISREG(record["raw_mode"]) and record["digest"] != cpio_records[record["path"]]["sha256"]:
            raise ValueError("RPM file digest differs from held CPIO bytes")
    return result


def _validate_pre_extraction_paths(
    rpm_path: Path,
    headers: list[dict[str, Any]],
    *,
    listing_override: list[str] | None = None,
) -> None:
    if listing_override is None:
        descriptor = os.open(rpm_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            listing = _query_rpm_tag_values(descriptor, ("FILENAMES",))["FILENAMES"]
        finally:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    else:
        listing = listing_override
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
                f"unsupported special RPM payload file before extraction: <redacted>"
            )
        if file_type == stat.S_IFLNK:
            _validate_symlink_target(header_path, header["link_target"])
            symlink_paths.append(header_path)
        if header["user"] != "root" or header["group"] != "root":
            raise ValueError(
                f"RPM payload header ownership must be root:root: <redacted>"
            )
        permission_mode = stat.S_IMODE(header["raw_mode"])
        expected_mode = 0o755 if file_type == stat.S_IFDIR else (
            0o777 if file_type == stat.S_IFLNK else 0o644
        )
        if permission_mode != expected_mode:
            description = "directory mode" if file_type == stat.S_IFDIR else "file mode"
            raise ValueError(f"unsafe or unexpected RPM {description}: <redacted>")
    if listing != header_paths:
        raise ValueError(f"RPM path listing/header mismatch for <redacted>")
    if len(header_paths) != len(set(header_paths)):
        raise ValueError(f"duplicate RPM payload path in <redacted>")

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
        raise ValueError(f"RPM explicit directory topology is not exact for <redacted>")

    for header_path in normalized_header_paths:
        if any(symlink in header_path.parents for symlink in symlink_paths):
            raise ValueError(
                f"RPM payload path is below payload symlink before extraction: "
                f"<redacted>"
            )


def _validate_pre_extraction_descriptor(
    descriptor: int, headers: list[dict[str, Any]]
) -> None:
    listing = _query_rpm_tag_values(descriptor, ("FILENAMES",))["FILENAMES"]
    _validate_pre_extraction_paths(
        Path("<held-rpm-descriptor>"), headers, listing_override=listing
    )


def _cpio_payload_path(raw_name: str) -> PurePosixPath:
    if not raw_name or raw_name.startswith("/") or "\x00" in raw_name:
        raise ValueError(f"unsafe CPIO path: <redacted>")
    name = raw_name[2:] if raw_name.startswith("./") else raw_name
    pure = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "." in pure.parts
        or ".." in pure.parts
        or pure.as_posix() != name
    ):
        raise ValueError(f"unsafe CPIO path: <redacted>")
    return PurePosixPath("/") / pure


def _read_exact(stream: Any, size: int, description: str) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise ValueError(f"truncated CPIO {description}")
    return value


def _read_newc_number(header: bytes, offset: int, description: str) -> int:
    value = header[offset:offset + 8]
    if re.fullmatch(rb"[0-9a-f]{8}", value) is None:
        raise ValueError(f"invalid CPIO {description}")
    return int(value, 16)


def _validate_cpio_archive_descriptor(
    spool_descriptor: int, headers: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Validate the exact rpm2cpio stream before any extraction occurs."""
    expected = {header["path"]: header for header in headers}
    if len(expected) != len(headers):
        raise ValueError("duplicate RPM payload path")
    observed: dict[str, dict[str, Any]] = {}
    inodes: set[int] = set()
    symlinks: set[PurePosixPath] = set()
    spool_before = os.fstat(spool_descriptor)
    if not stat.S_ISREG(spool_before.st_mode):
        raise ValueError("CPIO spool descriptor must be a regular file")
    os.lseek(spool_descriptor, 0, os.SEEK_SET)
    with _borrowed_binary_stream(spool_descriptor) as stream:
        while True:
            raw_header = _read_exact(stream, 110, "header")
            if raw_header[:6] != b"070701":
                raise ValueError("unsupported CPIO format")
            numeric = [_read_newc_number(raw_header, 6 + index * 8, "numeric field") for index in range(13)]
            inode, mtime = numeric[0], numeric[5]
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
                if numeric != [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0]:
                    raise ValueError("invalid CPIO trailer")
                break
            if inode <= 0 or inode in inodes or mtime != 1787899659 or any(numeric[index] for index in (7, 8, 9, 10, 12)):
                raise ValueError("CPIO inode, timestamp, device, or checksum policy differs")
            inodes.add(inode)

            path = _cpio_payload_path(name)
            path_value = path.as_posix()
            if path_value in observed:
                raise ValueError(f"duplicate CPIO payload path: <redacted>")
            file_type = stat.S_IFMT(mode)
            if file_type not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK):
                raise ValueError(f"unsupported special CPIO payload file: <redacted>")
            if uid != 0 or gid != 0:
                raise ValueError(f"CPIO payload ownership is not root:root: <redacted>")
            if file_type in (stat.S_IFREG, stat.S_IFLNK) and links != 1:
                raise ValueError(f"CPIO hardlink is forbidden: <redacted>")
            if file_type == stat.S_IFDIR and (links != 1 or size != 0):
                raise ValueError("CPIO directory link count or size differs")

            link_target = ""
            content_digest = hashlib.sha256()
            if file_type == stat.S_IFLNK:
                raw_target = _read_exact(stream, size, "symlink target")
                content_digest.update(raw_target)
                try:
                    link_target = raw_target.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ValueError(f"CPIO symlink target is not UTF-8: <redacted>") from error
                _validate_symlink_target(path, link_target)
                symlinks.add(path)
            else:
                remaining = size
                while remaining:
                    chunk = _read_exact(
                        stream, min(remaining, 1024 * 1024), "file data"
                    )
                    content_digest.update(chunk)
                    remaining -= len(chunk)
            data_padding = (-size) % 4
            if any(_read_exact(stream, data_padding, "data padding")):
                raise ValueError("nonzero CPIO data padding")
            observed[path_value] = {
                "raw_mode": mode,
                "size": size,
                "link_target": link_target,
                "sha256": content_digest.hexdigest(),
                "inode": inode,
                "mtime": mtime,
                "nlink": links,
                "uid": uid,
                "gid": gid,
                "dev": [numeric[7], numeric[8]],
                "rdev": [numeric[9], numeric[10]],
                "check": numeric[12],
            }

        while chunk := stream.read(1024 * 1024):
            if any(chunk):
                raise ValueError("nonzero data follows CPIO trailer")

    for path_value in observed:
        path = PurePosixPath(path_value)
        if any(symlink in path.parents for symlink in symlinks):
            raise ValueError(f"CPIO payload path is below CPIO symlink: <redacted>")
    if set(observed) != set(expected):
        raise ValueError("CPIO payload/header path mismatch")
    for path_value, actual in observed.items():
        header = expected[path_value]
        if actual["raw_mode"] != header["raw_mode"]:
            raise ValueError(f"CPIO payload/header mode mismatch: <redacted>")
        if actual["size"] != header["size"]:
            raise ValueError(f"CPIO payload/header size mismatch: <redacted>")
        if actual["link_target"] != header["link_target"]:
            raise ValueError(f"CPIO payload/header symlink mismatch: <redacted>")
    if _status_identity(spool_before) != _status_identity(os.fstat(spool_descriptor)):
        raise ValueError("CPIO spool changed while being validated")
    os.lseek(spool_descriptor, 0, os.SEEK_SET)
    return observed


def _validate_cpio_archive(
    spool: Path, headers: list[dict[str, Any]]
) -> None:
    descriptor = os.open(
        spool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        _validate_cpio_archive_descriptor(descriptor, headers)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _spool_rpm_cpio_descriptor(rpm_descriptor: int, spool_directory: Path | int) -> int:
    spool_descriptor = os.open(
        "." if isinstance(spool_directory, int) else spool_directory,
        os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
        0o600,
        dir_fd=spool_directory if isinstance(spool_directory, int) else None,
    )
    try:
        rpm_before = os.fstat(rpm_descriptor)
        result = subprocess.run(
            ["/usr/bin/rpm2cpio", f"/proc/self/fd/{rpm_descriptor}"],
            check=False,
            stdout=spool_descriptor,
            stderr=subprocess.PIPE,
            pass_fds=(rpm_descriptor,),
        )
        os.fsync(spool_descriptor)
        if result.returncode != 0:
            raise RuntimeError("rpm2cpio failed for held RPM descriptor")
        if _status_identity(rpm_before) != _status_identity(
            os.fstat(rpm_descriptor)
        ):
            raise ValueError("held RPM changed while rpm2cpio was running")
        os.lseek(spool_descriptor, 0, os.SEEK_SET)
        return spool_descriptor
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(spool_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


class BoundPayloadTree:
    """One extracted tree held from creation through the last payload tool."""

    def __init__(self, destination: Path, *, parent_descriptor: int | None = None) -> None:
        from tools.gate01.proof_io import _open_parent_directory
        self.path = destination
        self.parent = -1
        self.root = -1
        self.directories: dict[str, int] = {}
        self.files: dict[str, int] = {}
        self.statuses: dict[str, os.stat_result] = {}
        self.listings: dict[str, tuple[str, ...]] = {}
        self.records: dict[str, dict[str, Any]] = {}
        parent = root = -1
        try:
            parent = os.dup(parent_descriptor) if parent_descriptor is not None else _open_parent_directory(destination)[0]
            self.parent = parent
            os.mkdir(destination.name, 0o755, dir_fd=self.parent)
            root = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            self.root = root
            os.fchmod(self.root, 0o755)
            self.root_identity = os.fstat(self.root)
            self.verify_root()
            parent = root = -1
        finally:
            _release_fd_0 = root
            _release_fd_1 = parent
            root = parent = -1
            _close_descriptors(_release_fd_0, _release_fd_1, primary=sys.exception())

    def verify_root(self) -> None:
        from tools.gate01.proof_io import _open_parent_directory
        parent, status = _open_parent_directory(self.path)
        try:
            if (status.st_dev, status.st_ino) != (os.fstat(self.parent).st_dev, os.fstat(self.parent).st_ino):
                raise ValueError("extraction parent path changed")
        finally:
            _release_primary = sys.exception()
            try:
                os.close(parent)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        expected = self.root_identity
        if (named.st_dev, named.st_ino, named.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
            raise ValueError("extraction root path changed")

    def bind(self, records: dict[str, dict[str, Any]]) -> None:
        self.verify_root()
        self.records = records
        expected = {path: record["raw_mode"] for path, record in records.items()}
        for path in tuple(expected):
            for parent in PurePosixPath(path).parents:
                expected.setdefault(parent.as_posix(), stat.S_IFDIR | 0o755)
        expected.setdefault("/", stat.S_IFDIR | 0o755)
        self.directories["/"] = self.root
        def walk(path: str, descriptor: int) -> None:
            self.statuses[path] = os.fstat(descriptor)
            names = tuple(sorted(os.listdir(descriptor)))
            self.listings[path] = names
            if os.listxattr(descriptor):
                raise ValueError("extracted payload xattrs are forbidden")
            for name in names:
                child_path = str(PurePosixPath(path) / name)
                status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if child_path not in expected or status.st_mode != expected[child_path]:
                    raise ValueError("extracted payload topology or mode differs from CPIO")
                if (status.st_uid, status.st_gid) != (os.geteuid(), os.getegid()):
                    raise ValueError("extracted payload ownership differs")
                self.statuses[child_path] = status
                if stat.S_ISDIR(status.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        self.directories[child_path] = child
                    except BaseException as primary:
                        _release_primary = primary
                        try:
                            os.close(child)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                        raise
                    if _status_identity(status) != _status_identity(os.fstat(child)):
                        raise ValueError("extracted payload directory changed while opening")
                    walk(child_path, child)
                elif stat.S_ISREG(status.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                    try:
                        self.files[child_path] = child
                    except BaseException as primary:
                        _release_primary = primary
                        try:
                            os.close(child)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                        raise
                elif not stat.S_ISLNK(status.st_mode):
                    raise ValueError("extracted payload special node is forbidden")
        walk("/", self.root)
        if set(self.statuses) != set(expected):
            raise ValueError("extracted payload paths differ from CPIO")
        self.verify()
        self.verify()

    def parent_for(self, path: PurePosixPath) -> tuple[int, str]:
        descriptor = os.dup(self.directories[path.parent.as_posix()])
        try:
            return descriptor, path.name
        except BaseException as primary:
            _close_descriptors(descriptor, primary=primary)
            raise

    def verify_one(self, path: str) -> None:
        status = self.statuses[path]
        if path == "/":
            named = os.fstat(self.root)
        else:
            pure = PurePosixPath(path)
            parent = self.directories[pure.parent.as_posix()]
            named = os.stat(pure.name, dir_fd=parent, follow_symlinks=False)
        if _status_identity(status) != _status_identity(named):
            raise ValueError("extracted payload changed after CPIO binding")
        if stat.S_ISDIR(status.st_mode):
            fd = self.directories[path]
            if _status_identity(os.fstat(fd)) != _status_identity(status) or tuple(sorted(os.listdir(fd))) != self.listings[path] or os.listxattr(fd):
                raise ValueError("extracted payload directory changed")
        else:
            record = self.records[path]
            if status.st_nlink != 1 or status.st_size != record["size"]:
                raise ValueError("extracted payload link count or size differs")
            if stat.S_ISREG(status.st_mode):
                fd = self.files[path]
                if _status_identity(os.fstat(fd)) != _status_identity(status) or os.listxattr(fd) or _sha256_descriptor(fd) != record["sha256"]:
                    raise ValueError("extracted payload bytes differ from validated CPIO")
            elif os.readlink(pure.name, dir_fd=parent) != record["link_target"]:
                raise ValueError("extracted payload symlink differs from CPIO")

    def verify(self) -> None:
        self.verify_root()
        for path in self.statuses:
            self.verify_one(path)
        # A final stat sweep catches mutate/restore of an earlier hashed child.
        for path, before in self.statuses.items():
            if path == "/":
                current = os.fstat(self.root)
            else:
                pure = PurePosixPath(path)
                current = os.stat(pure.name, dir_fd=self.directories[pure.parent.as_posix()], follow_symlinks=False)
            if _status_identity(current) != _status_identity(before):
                raise ValueError("extracted payload changed during final sweep")
        self.verify_root()

    def close(self) -> None:
        files = self.files
        directories = self.directories
        root = self.root
        parent = self.parent
        self.root = self.parent = -1
        failure = None
        index = 0
        while index < 2:
            records = files if index == 0 else directories
            index += 1
            while records:
                try:
                    descriptor = records.popitem()[1]
                except BaseException as error:
                    if failure is None:
                        failure = error
                    descriptor = dict.popitem(records)[1]
                # The root's directory-map entry is a borrowed alias of root.
                if descriptor >= 0 and descriptor != root and descriptor != parent:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if failure is None:
                            failure = error
        try:
            _numeric_failure = None
            _numeric_fd = root
            if _numeric_fd >= 0:
                try:
                    os.close(_numeric_fd)
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
            _numeric_fd = parent
            if _numeric_fd >= 0:
                try:
                    os.close(_numeric_fd)
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
            if _numeric_failure is not None:
                raise RuntimeError("bound descriptor release failed") from _numeric_failure
        except BaseException as error:
            if failure is None:
                failure = error
        if failure is not None:
            raise failure


_drain_bound_payload_tree = BoundPayloadTree.close


def _extract_validated_cpio_descriptor(
    spool_descriptor: int,
    destination: Path,
    payload_records: dict[str, dict[str, Any]] | None,
    *, parent_descriptor: int | None = None,
) -> BoundPayloadTree:
    spool_before = os.fstat(spool_descriptor)
    tree = BoundPayloadTree(destination, parent_descriptor=parent_descriptor)
    try:
        os.lseek(spool_descriptor, 0, os.SEEK_SET)
        with _borrowed_binary_stream(spool_descriptor) as input_stream:
            result = subprocess.run(
                [
                    "/usr/bin/cpio",
                    "--extract",
                    "--make-directories",
                    "--preserve-modification-time",
                    "--no-absolute-filenames",
                ],
                cwd=f"/proc/self/fd/{tree.root}",
                pass_fds=(tree.root,),
                umask=0o022,
                stdin=input_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            raise RuntimeError("cpio failed for validated spool descriptor")
        if _status_identity(spool_before) != _status_identity(os.fstat(spool_descriptor)):
            raise ValueError("validated CPIO spool changed during extraction")
        if payload_records is not None:
            tree.bind(payload_records)
        return tree
    except BaseException:
        _release_primary = sys.exception()
        try:
            try:
                _close_payload_owner(tree, None)
            except BaseException as _drain_primary:
                _drain_attempts = 2
                while _drain_attempts:
                    _drain_attempts -= 1
                    try:
                        _drain_bound_payload_tree(tree)
                        break
                    except BaseException:
                        _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                raise
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def _extract_validated_cpio(spool: Path, destination: Path) -> None:
    descriptor = os.open(
        spool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        tree = _extract_validated_cpio_descriptor(descriptor, destination, None)
        try:
            _close_payload_owner(tree, None)
        except BaseException as _drain_primary:
            _drain_attempts = 2
            while _drain_attempts:
                _drain_attempts -= 1
                try:
                    _drain_bound_payload_tree(tree)
                    break
                except BaseException:
                    _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
            raise
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _validate_extracted_tree(root: Path | BoundPayloadTree, headers: list[dict[str, Any]]) -> None:
    """Require exact extracted entries/types, including all implicit directories."""
    if isinstance(root, BoundPayloadTree):
        root.verify()
        return
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
                    _release_primary = sys.exception()
                    try:
                        os.close(child)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        if sorted(os.listdir(directory_descriptor)) != names_before:
            raise ValueError("extracted RPM tree changed while walking")

    try:
        walk(root_descriptor, PurePosixPath())
    finally:
        _release_primary = sys.exception()
        try:
            os.close(root_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    if set(observed) != set(expected_types):
        raise ValueError("extracted RPM tree does not exactly match payload and ancestors")
    for path, expected_type in expected_types.items():
        observed_type, observed_mode = observed[path]
        if observed_type != expected_type:
            raise ValueError(f"extracted RPM tree type mismatch: <redacted>")
        if path in header_modes and observed_mode != header_modes[path]:
            raise ValueError(f"extracted RPM tree mode mismatch: <redacted>")


def _validate_modules_order(extract_root: Path | BoundPayloadTree, headers: list[dict[str, Any]]) -> None:
    module_prefix = RELEASE_ROOT.as_posix() + "/"
    packaged_modules = {
        header["path"].removeprefix(module_prefix)
        for header in headers
        if header["path"].endswith(".ko")
        and stat.S_IFMT(header["raw_mode"]) == stat.S_IFREG
    }
    if not packaged_modules:
        raise ValueError("modules.order cannot describe an empty module set")
    try:
        if isinstance(extract_root, BoundPayloadTree):
            order_path = str(RELEASE_ROOT / "modules.order")
            extract_root.verify_one(order_path)
            descriptor = extract_root.files[order_path]
            lines = os.pread(descriptor, os.fstat(descriptor).st_size, 0).decode("utf-8").splitlines()
            extract_root.verify_one(order_path)
        else:
            lines = extract_root.joinpath(*RELEASE_ROOT.parts[1:], "modules.order").read_text(encoding="utf-8").splitlines()
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


def _sha256_descriptor(descriptor: int) -> str:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    if _status_identity(before) != _status_identity(os.fstat(descriptor)):
        raise ValueError("bound payload file changed while hashing")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_payload_parent(
    extract_root: Path | BoundPayloadTree, path: PurePosixPath
) -> tuple[int, str]:
    if isinstance(extract_root, BoundPayloadTree):
        return extract_root.parent_for(path)
    descriptor = os.open(
        extract_root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for component in path.parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            closing, descriptor = descriptor, child
            os.close(closing)
        return descriptor, path.name
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def _inspect_bound_payload_file(
    header: dict[str, Any],
    extract_root: Path | BoundPayloadTree,
    public_certificate_descriptor: int,
) -> dict[str, Any] | None:
    """Inspect one payload while retaining its exact inode for every tool."""
    path = _validate_absolute_payload_path(header["path"])
    raw_mode = header["raw_mode"]
    file_type = stat.S_IFMT(raw_mode)
    if isinstance(extract_root, BoundPayloadTree):
        extract_root.verify_root()
        extract_root.verify_one(path.as_posix())
        cpio = extract_root.records[path.as_posix()]
        if any(cpio[field] != header[field] for field in ("raw_mode", "size", "link_target")):
            raise ValueError("extracted payload header differs from bound CPIO")
    if file_type == stat.S_IFDIR:
        return None
    if file_type not in (stat.S_IFREG, stat.S_IFLNK):
        raise ValueError(f"unsupported special RPM payload file: <redacted>")
    parent_descriptor, name = _open_payload_parent(extract_root, path)
    descriptor = -1
    try:
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_IFMT(observed.st_mode) != file_type:
            raise ValueError(f"extracted file type differs from RPM header: <redacted>")
        mode = f"{stat.S_IMODE(raw_mode):04o}"
        if stat.S_IMODE(observed.st_mode) != stat.S_IMODE(raw_mode):
            raise ValueError(f"extracted file mode differs from RPM header: <redacted>")
        record: dict[str, Any] = {
            "path": path.as_posix(),
            "type": "symlink" if file_type == stat.S_IFLNK else "file",
            "mode": mode,
            "size": header["size"],
            "user": header["user"],
            "group": header["group"],
        }
        if file_type == stat.S_IFLNK:
            target = os.readlink(name, dir_fd=parent_descriptor)
            if target != header["link_target"]:
                raise ValueError(
                    f"extracted symlink target differs from RPM header: <redacted>"
                )
            after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if _status_identity(after) != _status_identity(observed):
                raise ValueError(f"payload path identity changed: <redacted>")
            record["link_target"] = target
            return record
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if _status_identity(opened) != _status_identity(observed):
            raise ValueError(f"payload path identity changed while opening: <redacted>")
        if opened.st_size != header["size"]:
            raise ValueError(f"extracted file size differs from RPM header: <redacted>")
        record["sha256"] = _sha256_descriptor(descriptor)
        if isinstance(extract_root, BoundPayloadTree) and record["sha256"] != extract_root.records[path.as_posix()]["sha256"]:
            raise ValueError("extracted payload digest differs from bound CPIO")
        record["private_key_marker"] = _contains_private_key_marker_descriptor(
            descriptor
        )
        if path.as_posix().endswith(".ko"):
            _verify_module_signature_descriptors(
                descriptor,
                public_certificate_descriptor,
                display=path.as_posix(),
            )
            module_path = f"/proc/self/fd/{descriptor}"
            inherited = (descriptor,)
            record.update(
                {
                    "signer": _run_text_for_descriptors(
                        ("/usr/bin/modinfo", "-F", "signer", module_path), inherited
                    ).strip(),
                    "sig_id": _run_text_for_descriptors(
                        ("/usr/bin/modinfo", "-F", "sig_id", module_path), inherited
                    ).strip(),
                    "vermagic": _run_text_for_descriptors(
                        ("/usr/bin/modinfo", "-F", "vermagic", module_path), inherited
                    ).strip(),
                }
            )
        after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _status_identity(after) != _status_identity(opened)
            or _status_identity(os.fstat(descriptor)) != _status_identity(opened)
        ):
            raise ValueError(f"payload path identity changed: <redacted>")
        return record
    finally:
        _close_descriptors(descriptor, parent_descriptor, primary=sys.exception())


def _validate_source_rpm_payload(
    records: dict[str, dict[str, Any]], expected_sha256: dict[str, str]
) -> None:
    required = {
        "kernel-openmythos.spec",
        "linux-6.18.48.tar.xz",
        "6.18.48-x86_64.config",
        "module-signing.pem",
    }
    if set(records) != required or set(expected_sha256) != required:
        raise ValueError("source RPM payload is not the exact four-file set")
    for name in sorted(required):
        record = records[name]
        if (
            set(record)
            != {"path", "type", "mode", "user", "group", "size", "sha256"}
            or record["path"] != f"/{name}"
            or record["type"] != "file"
            or record["mode"] != "0644"
            or record["user"] != "root"
            or record["group"] != "root"
            or type(record["size"]) is not int
            or record["size"] <= 0
            or record["sha256"] != expected_sha256[name]
        ):
            raise ValueError(f"source RPM payload identity is invalid: <redacted>")


def _inspect_payload_file(
    header: dict[str, Any], extract_root: Path, public_certificate: Path
) -> dict[str, Any] | None:
    certificate_descriptor = os.open(
        public_certificate,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        return _inspect_bound_payload_file(
            header, extract_root, certificate_descriptor
        )
    finally:
        _release_primary = sys.exception()
        try:
            os.close(certificate_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _source_headers(headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for header in headers:
        raw = header["path"]
        if raw.startswith("./"):
            raw = raw[2:]
        pure = PurePosixPath(raw)
        if (
            not raw
            or raw.startswith("/")
            or pure.as_posix() != raw
            or len(pure.parts) != 1
            or "." in pure.parts
            or ".." in pure.parts
        ):
            raise ValueError(f"source RPM payload path is unsafe: <redacted>")
        value = dict(header)
        value["path"] = "/" + raw
        normalized.append(value)
    return normalized


def _source_payload_records(
    headers: list[dict[str, Any]],
    cpio_records: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for header in headers:
        path = header["path"]
        name = path.removeprefix("/")
        cpio = cpio_records[path]
        file_type = stat.S_IFMT(header["raw_mode"])
        if file_type != stat.S_IFREG:
            record: dict[str, Any] = {
                "path": path,
                "type": "symlink" if file_type == stat.S_IFLNK else "other",
                "mode": f"{stat.S_IMODE(header['raw_mode']):04o}",
                "user": header["user"],
                "group": header["group"],
                "size": header["size"],
            }
            if file_type == stat.S_IFLNK:
                record["link_target"] = cpio["link_target"]
        else:
            record = {
                "path": path,
                "type": "file",
                "mode": f"{stat.S_IMODE(header['raw_mode']):04o}",
                "user": header["user"],
                "group": header["group"],
                "size": header["size"],
                "sha256": cpio["sha256"],
            }
        result[name] = record
    return result


def inspect_rpm_descriptors(
    artifact_descriptors: dict[str, int],
    *,
    extract_root: Path,
    public_certificate_descriptor: int,
    expected_source_payload_sha256: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from tools.gate01.proof_io import _open_parent_directory
    parent, _ = _open_parent_directory(extract_root)
    descriptor = -1
    try:
        try:
            os.mkdir(extract_root.name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        descriptor = os.open(extract_root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        initial = os.fstat(descriptor)
        if os.listdir(descriptor) or os.listxattr(descriptor):
            raise ValueError("extract root must be empty and have no xattrs")
        result = _inspect_rpm_descriptors_in_root(
            artifact_descriptors, extract_root=extract_root,
            extract_root_descriptor=descriptor,
            public_certificate_descriptor=public_certificate_descriptor,
            expected_source_payload_sha256=expected_source_payload_sha256,
        )
        named = os.stat(extract_root.name, dir_fd=parent, follow_symlinks=False)
        reopened_parent, _ = _open_parent_directory(extract_root)
        try:
            if (named.st_dev, named.st_ino, named.st_mode) != (initial.st_dev, initial.st_ino, initial.st_mode) or (os.fstat(reopened_parent).st_dev, os.fstat(reopened_parent).st_ino) != (os.fstat(parent).st_dev, os.fstat(parent).st_ino):
                raise ValueError("extraction root or parent was replaced")
        finally:
            _release_primary = sys.exception()
            try:
                os.close(reopened_parent)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        if set(os.listdir(descriptor)) != set(EXPECTED_BINARY_NAMES) or os.listxattr(descriptor):
            raise ValueError("extraction root topology changed")
        return result
    finally:
        _close_descriptors(descriptor, parent, primary=sys.exception())


def _inspect_rpm_descriptors_in_root(
    artifact_descriptors: dict[str, int], *, extract_root: Path,
    extract_root_descriptor: int, public_certificate_descriptor: int,
    expected_source_payload_sha256: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Inspect the exact held SRPM+three-RPM descriptors without path authority."""
    if set(artifact_descriptors) != {"srpm", "core", "modules", "meta"}:
        raise ValueError("artifact descriptor roles are not the exact SRPM+three set")
    initial_status = {
        role: os.fstat(descriptor)
        for role, descriptor in artifact_descriptors.items()
    }
    initial_hashes = {
        role: _sha256_descriptor(descriptor)
        for role, descriptor in artifact_descriptors.items()
    }
    for role, status in initial_status.items():
        if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
            raise ValueError(f"held RPM descriptor is not nonempty regular data: {role}")
    certificate_status = os.fstat(public_certificate_descriptor)
    if not stat.S_ISREG(certificate_status.st_mode):
        raise ValueError("public certificate descriptor must be a regular file")

    source_descriptor = artifact_descriptors["srpm"]
    source_package = _query_package_descriptor(source_descriptor)
    source_headers = _source_headers(_query_file_headers_descriptor(source_descriptor))
    source_spool = _spool_rpm_cpio_descriptor(source_descriptor, extract_root_descriptor)
    try:
        source_cpio = _validate_cpio_archive_descriptor(source_spool, source_headers)
        source_package["security_metadata"] = _query_security_metadata(source_descriptor, "srpm", source_headers, source_cpio, source_spool)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(source_spool)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    source_records = _source_payload_records(source_headers, source_cpio)
    _validate_source_rpm_payload(source_records, expected_source_payload_sha256)
    sources = [
        normalize_source_package_identity(source_package, EXPECTED_SOURCE_FILENAME)
    ]

    binaries: list[dict[str, Any]] = []
    role_names = {
        "core": "kernel-openmythos-core",
        "modules": "kernel-openmythos-modules",
        "meta": "kernel-openmythos",
    }
    for role in ("meta", "core", "modules"):
        rpm_descriptor = artifact_descriptors[role]
        package = _normalize_binary_package_identity(
            _query_package_descriptor(rpm_descriptor)
        )
        if package["name"] != role_names[role]:
            raise ValueError(f"held RPM descriptor has the wrong fixed role: {role}")
        headers = _query_file_headers_descriptor(rpm_descriptor)
        _validate_pre_extraction_descriptor(rpm_descriptor, headers)
        payload_tree = None
        try:
            cpio_descriptor = _spool_rpm_cpio_descriptor(rpm_descriptor, extract_root_descriptor)
            try:
                cpio_records = _validate_cpio_archive_descriptor(
                    cpio_descriptor, headers
                )
                package["security_metadata"] = _query_security_metadata(rpm_descriptor, role, headers, cpio_records, cpio_descriptor)
                package_extract_root = extract_root / package["name"]
                payload_tree = _extract_validated_cpio_descriptor(
                    cpio_descriptor, package_extract_root, cpio_records,
                    parent_descriptor=extract_root_descriptor,
                )
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(cpio_descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            if package["name"] == "kernel-openmythos-modules":
                _validate_modules_order(payload_tree, headers)
            records = [
                record
                for header in headers
                if (
                    record := _inspect_bound_payload_file(
                        header,
                        payload_tree,
                        public_certificate_descriptor,
                    )
                )
                is not None
            ]
            payload_tree.verify()

        finally:
            if payload_tree is not None:
                _release_primary = sys.exception()
                try:
                    try:
                        _close_payload_owner(payload_tree, None)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_bound_payload_tree(payload_tree)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        package["files"] = sorted(records, key=lambda record: record["path"])
        binaries.append(package)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "source_rpms": sources,
        "binary_rpms": sorted(binaries, key=lambda package: package["name"]),
    }
    validate_rpm_manifest(manifest)
    for role, descriptor in artifact_descriptors.items():
        if (
            _status_identity(os.fstat(descriptor))
            != _status_identity(initial_status[role])
            or _sha256_descriptor(descriptor) != initial_hashes[role]
        ):
            raise ValueError(f"held RPM descriptor changed during inspection: {role}")
    if _status_identity(os.fstat(public_certificate_descriptor)) != _status_identity(
        certificate_status
    ):
        raise ValueError("public certificate descriptor changed during inspection")
    installed_files = {
        "schema_version": SCHEMA_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "packages": _installed_file_view(manifest),
    }
    return manifest, installed_files


def _validate_meta_requirements_descriptor(descriptor: int) -> list[str]:
    fields = {"name": "REQUIRENAME", "flags": "REQUIREFLAGS", "version": "REQUIREVERSION"}
    values = _query_rpm_tag_values(descriptor, tuple(fields.values()))
    records = _parallel_rpm_records(values, fields)
    if any(type(record[key]) is not expected for record in records for key, expected in (("name", str), ("flags", int), ("version", str))):
        raise ValueError("meta-package requirement metadata types are invalid")
    records.sort(key=lambda record: (record["name"], record["flags"], record["version"]))
    if records != _security_dependencies("meta")["requires"]:
        raise ValueError("meta-package uname requirements and rpmlib tuples are not exact")
    expected = sorted(
        (
            f"kernel-openmythos-core-uname-r = {KERNEL_RELEASE}",
            f"kernel-openmythos-modules-uname-r = {KERNEL_RELEASE}",
        )
    )
    return expected


def inspect_rpm_set(
    rpm_dir: Path,
    srpm_dir: Path,
    output: Path,
    extract_root: Path,
    public_certificate: Path,
) -> dict[str, Any]:
    # The retired pathname API lacks source-capsule and held-output authority.
    # Keep an explicit refusal for old callers; only inspect-fixed-fds can
    # produce current evidence through the reviewed sealed supervisor.
    raise ValueError("RPM inspection requires sealed descriptor authority")


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    serialized = _canonical_json_bytes(value)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        temporary = Path(temporary_name)
        _write_all(descriptor, serialized)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        from tools.gate01.proof_io import _verify_written_output
        _verify_written_output(descriptor, len(serialized), hashlib.sha256(serialized).hexdigest())
        closing, descriptor = descriptor, -1
        os.close(closing)
        os.replace(temporary, path)
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.unlink(temporary_name)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    finally:
        if descriptor >= 0:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _write_json_descriptor(descriptor: int, value: dict[str, Any]) -> str:
    encoded = _canonical_json_bytes(value)
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("evidence descriptor short write")
        view = view[written:]
    os.fsync(descriptor)
    from tools.gate01.proof_io import _verify_written_output
    digest = hashlib.sha256(encoded).hexdigest()
    _verify_written_output(descriptor, len(encoded), digest)
    return digest


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


def _inspect_fixed_descriptors_command(arguments: argparse.Namespace) -> int:
    artifact_descriptors = {
        "srpm": 30,
        "core": 31,
        "modules": 32,
        "meta": 33,
    }
    expected_source_payload = {
        "kernel-openmythos.spec": arguments.spec_sha256,
        "linux-6.18.48.tar.xz": arguments.source_sha256,
        "6.18.48-x86_64.config": arguments.config_sha256,
        "module-signing.pem": arguments.certificate_sha256,
    }
    manifest, installed_files = inspect_rpm_descriptors(
        artifact_descriptors,
        extract_root=arguments.extract_root,
        public_certificate_descriptor=21,
        expected_source_payload_sha256=expected_source_payload,
    )
    meta_requirements = _validate_meta_requirements_descriptor(33)
    manifest_sha256 = _write_json_descriptor(40, manifest)
    installed_sha256 = _write_json_descriptor(41, installed_files)
    _write_json_descriptor(
        42,
        {
            "installed_files_sha256": installed_sha256,
            "meta_uname_requirements": meta_requirements,
            "rpm_manifest_sha256": manifest_sha256,
        },
    )
    return 0


def _validate_command(arguments: argparse.Namespace) -> int:
    validate_rpm_manifest(load_rpm_manifest(arguments.manifest))
    return 0


def _validate_meta_rpm_descriptor(descriptor: int) -> list[str]:
    package = _normalize_binary_package_identity(_query_package_descriptor(descriptor))
    headers = _query_file_headers_descriptor(descriptor)
    _validate_pre_extraction_descriptor(descriptor, headers)
    if headers:
        raise ValueError("meta RPM must own no files")
    spool = _spool_rpm_cpio_descriptor(descriptor, Path("/tmp/work"))
    try:
        cpio = _validate_cpio_archive_descriptor(spool, headers)
        package["security_metadata"] = _query_security_metadata(descriptor, "meta", headers, cpio, spool)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(spool)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    package["files"] = []
    _validate_package(package, source=False, expected_name="kernel-openmythos")
    return _validate_meta_requirements_descriptor(descriptor)


def _meta_fixed_descriptor_command(_arguments: argparse.Namespace | None) -> int:
    from tools.gate01.proof_io import _require_sealed_regular_descriptor
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor < 3 or descriptor in (20, 33):
            continue
        try:
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        if not flags & fcntl.FD_CLOEXEC:
            raise ValueError("meta worker received an unexpected inherited descriptor")
    _require_sealed_regular_descriptor(20, "meta verifier")
    before = os.fstat(33)
    flags = fcntl.fcntl(33, fcntl.F_GETFL)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or flags & os.O_ACCMODE != os.O_RDONLY or flags & getattr(os, "O_PATH", 0):
        raise ValueError("meta worker requires read-only nonempty regular RPM data")
    requirements = _validate_meta_rpm_descriptor(33)
    if _status_identity(os.fstat(33)) != _status_identity(before):
        raise ValueError("meta RPM changed during framed query")
    sys.stdout.write(_canonical_json_bytes({"requirements": requirements}).decode("utf-8"))
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

    descriptor_inspect_parser = subparsers.add_parser("inspect-fixed-fds")
    descriptor_inspect_parser.add_argument(
        "--extract-root", required=True, type=Path
    )
    descriptor_inspect_parser.add_argument("--spec-sha256", required=True)
    descriptor_inspect_parser.add_argument("--source-sha256", required=True)
    descriptor_inspect_parser.add_argument("--config-sha256", required=True)
    descriptor_inspect_parser.add_argument("--certificate-sha256", required=True)
    descriptor_inspect_parser.set_defaults(
        handler=_inspect_fixed_descriptors_command
    )

    meta_parser = subparsers.add_parser("meta-fixed-fd")
    meta_parser.set_defaults(handler=_meta_fixed_descriptor_command)

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
    try:
        return arguments.handler(arguments)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("RPM artifact validation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
