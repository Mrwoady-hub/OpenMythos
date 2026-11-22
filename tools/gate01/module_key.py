"""Describe and audit a local module-signing identity without exposing it."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

from tools.gate01.proof_io import _add_cleanup_note, _close_descriptor_preserving_primary, _close_descriptor_sequence, _release_preserving_primary, _write_all, _verify_written_output
import tempfile
from pathlib import Path


SCHEMA_VERSION = 1
SCAN_CHUNK_SIZE = 64 * 1024
MAX_MARKER_CANDIDATE = 4096
PRIVATE_KEY_MARKER_STARTS = (b"-----BEGIN ", b"-----END ")
PRIVATE_KEY_MARKER = re.compile(
    rb"-----(?:BEGIN|END) [^-\r\n]*PRIVATE KEY-----"
)
PARTIAL_PRIVATE_KEY_MARKER = re.compile(rb"[^-\r\n]*PRIVATE KEY-{1,4}$")


def _openssl(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    return subprocess.run(
        ["/usr/bin/openssl", *arguments],
        check=True,
        capture_output=True,
        input=input_bytes,
        pass_fds=pass_fds,
    ).stdout


def _strip_prefix(line: str, prefix: str) -> str:
    if not line.startswith(prefix):
        raise ValueError(f"unexpected openssl output: missing {prefix!r}")
    return line[len(prefix) :]


def _der_elements(data: bytes, *, depth: int = 0) -> list[tuple[int, bytes]]:
    """Read a bounded canonical DER stream, rejecting BER and ignored suffixes."""
    if depth > 32 or len(data) > 1024 * 1024:
        raise ValueError("DER nesting or size exceeds the accepted profile")
    elements = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError("truncated DER element")
        tag, length = data[offset:offset + 2]
        offset += 2
        if tag & 0x1f == 0x1f or tag == 0:
            raise ValueError("unsupported DER tag")
        if length & 0x80:
            count = length & 0x7f
            if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
                raise ValueError("non-canonical DER length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
            if length < 128:
                raise ValueError("non-minimal DER length")
        if length > len(data) - offset:
            raise ValueError("truncated DER content")
        value = data[offset:offset + length]
        offset += length
        if tag & 0x20:
            _der_elements(value, depth=depth + 1)
        elif tag == 2:
            if not value or (len(value) > 1 and ((value[0] == 0 and value[1] < 128) or (value[0] == 255 and value[1] >= 128))):
                raise ValueError("non-canonical DER integer")
        elif tag == 5 and value:
            raise ValueError("non-canonical DER NULL")
        elif tag == 6:
            if not value or value[-1] & 0x80 or any(octet == 0x80 and (index == 0 or not value[index - 1] & 0x80) for index, octet in enumerate(value)):
                raise ValueError("non-canonical DER object identifier")
        elif tag == 3:
            if not value or value[0] > 7 or (len(value) == 1 and value[0]) or (len(value) > 1 and value[-1] & ((1 << value[0]) - 1)):
                raise ValueError("non-canonical DER bit string")
        elements.append((tag, value))
    return elements


def require_single_certificate_descriptor(certificate_descriptor: int) -> bytes:
    """Accept exactly one PEM envelope containing exactly one DER certificate."""
    value = _read_bound_descriptor(certificate_descriptor, "certificate descriptor")
    match = re.fullmatch(rb"[ \t\r\n]*-----BEGIN CERTIFICATE-----[ \t\r\n]+([A-Za-z0-9+/= \t\r\n]+)-----END CERTIFICATE-----[ \t\r\n]*", value)
    if match is None:
        raise ValueError("public certificate must contain exactly one PEM certificate")
    encoded = re.sub(rb"[ \t\r\n]", b"", match.group(1))
    try:
        der = base64.b64decode(encoded, validate=True)
        if base64.b64encode(der) != encoded:
            raise ValueError("non-canonical certificate base64")
        outer = _der_elements(der)
        if len(outer) != 1 or outer[0][0] != 0x30:
            raise ValueError("certificate DER has extra objects")
        fields = _der_elements(outer[0][1])
        if [tag for tag, _ in fields] != [0x30, 0x30, 0x03]:
            raise ValueError("invalid certificate DER structure")
    except (ValueError, binascii.Error) as error:
        raise ValueError("public certificate must contain exactly one canonical DER certificate") from error
    return value


def describe_descriptor(certificate_descriptor: int) -> dict[str, object]:
    """Describe the exact held certificate rather than a mutable pathname."""
    certificate_bytes = require_single_certificate_descriptor(certificate_descriptor)
    certificate_path = f"/proc/self/fd/{certificate_descriptor}"
    public_key_pem = _openssl(
        ["x509", "-in", certificate_path, "-pubkey", "-noout"],
        pass_fds=(certificate_descriptor,),
    )
    public_key_der = _openssl(
        ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key_pem
    )
    details = _openssl(
        [
            "x509",
            "-in",
            certificate_path,
            "-noout",
            "-serial",
            "-subject",
            "-startdate",
            "-enddate",
        ],
        pass_fds=(certificate_descriptor,),
    ).decode("utf-8")
    lines = details.splitlines()
    if len(lines) != 4:
        raise ValueError("unexpected openssl certificate description")
    if _read_bound_descriptor(certificate_descriptor, "certificate descriptor") != certificate_bytes:
        raise ValueError("certificate descriptor changed during description")

    return {
        "schema_version": SCHEMA_VERSION,
        "certificate_sha256": hashlib.sha256(certificate_bytes).hexdigest(),
        "spki_sha256": hashlib.sha256(public_key_der).hexdigest(),
        "serial": _strip_prefix(lines[0], "serial="),
        "subject": _strip_prefix(lines[1], "subject="),
        "not_before": _strip_prefix(lines[2], "notBefore="),
        "not_after": _strip_prefix(lines[3], "notAfter="),
    }


def describe(certificate: Path, output: Path) -> None:
    descriptor = os.open(
        certificate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        manifest = describe_descriptor(descriptor)
    finally:
        owned, descriptor = descriptor, -1
        _close_descriptor_preserving_primary(owned, sys.exception())
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_name: str | None = None
    temporary_descriptor = -1
    try:
        temporary_descriptor, temporary_name = tempfile.mkstemp(
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".part",
        )
        os.fchmod(temporary_descriptor, 0o600)
        _write_all(temporary_descriptor, encoded)
        os.fsync(temporary_descriptor)
        _verify_written_output(temporary_descriptor, len(encoded), hashlib.sha256(encoded).hexdigest())
        descriptor, temporary_descriptor = temporary_descriptor, -1
        os.close(descriptor)
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        primary = sys.exception()
        failure = None
        try:
            if temporary_descriptor >= 0:
                descriptor, temporary_descriptor = temporary_descriptor, -1
                os.close(descriptor)
        except BaseException as error:
            failure = error
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            if primary is None:
                raise failure
            _add_cleanup_note(primary, "additional public certificate manifest cleanup failed")


def _identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _version(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _require_identity(
    expected: os.stat_result,
    observed: os.stat_result,
    kind: str,
    relative_path: Path,
) -> None:
    if _identity(expected) != _identity(observed):
        raise RuntimeError(f"{kind} identity changed during traversal")


def _stat_at(
    name: str, directory_descriptor: int, kind: str, relative_path: Path
) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError(f"{kind} identity changed during traversal") from None


def _marker_carry(data: bytes) -> tuple[bool, bytes]:
    if PRIVATE_KEY_MARKER.search(data) is not None:
        return True, b""

    starts = [(data.rfind(prefix), prefix) for prefix in PRIVATE_KEY_MARKER_STARTS]
    start_at, prefix = max(starts, key=lambda item: item[0])
    if start_at >= 0:
        candidate = data[start_at:]
        body = candidate[len(prefix) :]
        if b"\n" not in body and b"\r" not in body:
            if b"-" not in body or PARTIAL_PRIVATE_KEY_MARKER.fullmatch(body):
                if len(candidate) >= MAX_MARKER_CANDIDATE:
                    return True, b""
                return False, candidate

    carry_size = max(len(prefix) for prefix in PRIVATE_KEY_MARKER_STARTS) - 1
    return False, data[-carry_size:]


def _descriptor_contains_secret(
    descriptor: int, exact_patterns: tuple[bytes, bytes]
) -> bool:
    exact_carry = b""
    marker_carry = b""
    exact_carry_size = max(len(pattern) for pattern in exact_patterns) - 1

    while chunk := os.read(descriptor, SCAN_CHUNK_SIZE):
        exact_data = exact_carry + chunk
        if any(pattern in exact_data for pattern in exact_patterns):
            return True
        exact_carry = exact_data[-exact_carry_size:]

        marker_found, marker_carry = _marker_carry(marker_carry + chunk)
        if marker_found:
            return True
    return False


def _scan_directory(
    directory_descriptor: int,
    relative_directory: Path,
    exact_patterns: tuple[bytes, bytes],
    offenders: list[str],
) -> None:
    # Every regular file and directory remains open through BOTH complete
    # content/metadata passes and their terminal all-entry sweeps.
    records: list[dict[str, object]] = []
    owned: list[int] = []
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

    def metadata(record: dict[str, object]) -> tuple[tuple[str, bytes], ...]:
        descriptor = record["fd"]
        if descriptor is not None:
            return tuple((name, os.getxattr(descriptor, name)) for name in sorted(os.listxattr(descriptor)))
        anchor = f"/proc/self/fd/{record['parent']}/{record['name']}"
        return tuple((name, os.getxattr(anchor, name, follow_symlinks=False)) for name in sorted(os.listxattr(anchor, follow_symlinks=False)))

    def bind(descriptor: int | None, parent: int | None, name: str | None, status: os.stat_result) -> None:
        record = {"fd": descriptor, "parent": parent, "name": name, "status": status}
        records.append(record)
        if stat.S_ISDIR(status.st_mode):
            record["names"] = sorted(os.listdir(descriptor))
        elif stat.S_ISLNK(status.st_mode):
            record["target"] = os.readlink(name, dir_fd=parent)
        record["xattrs"] = metadata(record)
        for child in record.get("names", []):
            before = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            kind = stat.S_IFMT(before.st_mode)
            if kind not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK):
                raise RuntimeError("unsupported node in leakage scan")
            if kind != stat.S_IFDIR and before.st_nlink != 1:
                raise RuntimeError("unsupported link count in leakage scan")
            child_fd = None
            if kind != stat.S_IFLNK:
                child_fd = os.open(child, flags | (os.O_DIRECTORY if kind == stat.S_IFDIR else 0), dir_fd=descriptor)
                try:
                    owned.append(child_fd)
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(child_fd)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                if _version(before) != _version(os.fstat(child_fd)):
                    raise RuntimeError("entry identity changed during traversal")
            bind(child_fd, descriptor, child, before)

    def sweep() -> None:
        for record in records:
            before = record["status"]
            descriptor = record["fd"]
            kind = "directory" if stat.S_ISDIR(before.st_mode) else "entry"
            if record["parent"] is not None:
                named = os.stat(record["name"], dir_fd=record["parent"], follow_symlinks=False)
                if _version(named) != _version(before):
                    raise RuntimeError(f"{kind} identity changed during traversal")
            if descriptor is not None and _version(os.fstat(descriptor)) != _version(before):
                raise RuntimeError(f"{kind} identity changed during traversal")
            if "names" in record and sorted(os.listdir(descriptor)) != record["names"]:
                raise RuntimeError("directory identity changed during traversal")
            if "target" in record and os.readlink(record["name"], dir_fd=record["parent"]) != record["target"]:
                raise RuntimeError("entry identity changed during traversal")
            if metadata(record) != record["xattrs"]:
                raise RuntimeError("entry metadata changed during traversal")

    def contains(value: bytes) -> bool:
        return any(pattern in value for pattern in exact_patterns) or _marker_carry(value)[0]

    def decoded_metadata(descriptor: int) -> bool:
        def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate metadata field")
                result[key] = value
            return result
        def visit(value: object, depth: int = 0) -> bool:
            if depth > 64:
                raise ValueError("metadata nesting exceeds the accepted limit")
            if isinstance(value, str):
                matched = contains(value.encode("utf-8"))
                if all(ord(character) <= 255 for character in value):
                    matched |= contains(value.encode("latin-1"))
                return matched
            if isinstance(value, list):
                return any(visit(item, depth + 1) for item in value)
            if isinstance(value, dict):
                return any(visit(key, depth + 1) or visit(item, depth + 1) for key, item in value.items())
            return False
        try:
            value = json.loads(_read_bound_descriptor(descriptor, "metadata descriptor"), object_pairs_hook=pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite metadata")))
            return visit(value)
        except (ValueError, UnicodeError, RecursionError):
            raise RuntimeError("decoded metadata is invalid during leakage scan") from None

    try:
        bind(directory_descriptor, None, None, os.fstat(directory_descriptor))
        results = []
        for _pass in range(2):
            sweep()
            matched = False
            for record in records:
                for value in (record["name"], record.get("target")):
                    if value is not None:
                        matched |= contains(os.fsencode(value))
                for name, value in record["xattrs"]:
                    matched |= contains(os.fsencode(name)) or contains(value)
                if stat.S_ISREG(record["status"].st_mode):
                    descriptor = record["fd"]
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    matched |= _descriptor_contains_secret(descriptor, exact_patterns)
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if record["name"] in {"rpm-artifacts.json", "installed-files.json", "source-capsule.json", "rootfs-audit.json", "container-contract.json", "leakage-scan.json", "build-report.json"}:
                        matched |= decoded_metadata(descriptor)
            sweep()
            results.append(matched)
        if results[0] != results[1]:
            raise RuntimeError("leakage scan changed during traversal")
        if results[1]:
            offenders.append("private-key leakage detected")
    except OSError:
        raise RuntimeError("leakage scan changed during traversal") from None
    finally:
        _close_descriptor_sequence(owned, sys.exception(), reverse=True)


def _read_bound_descriptor(descriptor: int, description: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{description} must be a regular file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, SCAN_CHUNK_SIZE):
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _version(before) != _version(after):
        raise RuntimeError(f"{description} changed while being read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def scan_descriptors(private_key_descriptor: int, root_descriptor: int) -> int:
    """Scan an exact held tree using patterns derived from the exact held key."""
    private_key_pem = _read_bound_descriptor(
        private_key_descriptor, "private key descriptor"
    )
    private_key_der = _openssl(
        [
            "pkey",
            "-in",
            f"/proc/self/fd/{private_key_descriptor}",
            "-outform",
            "DER",
        ],
        pass_fds=(private_key_descriptor,),
    )
    exact_patterns = (private_key_pem, private_key_der)
    root_before = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_before.st_mode):
        raise NotADirectoryError("scan root descriptor")

    scan_descriptor = os.dup(root_descriptor)
    try:
        offenders: list[str] = []
        opened_root = os.fstat(scan_descriptor)
        _require_identity(root_before, opened_root, "directory", Path("."))
        _scan_directory(scan_descriptor, Path(), exact_patterns, offenders)
        root_after = os.fstat(root_descriptor)
        _require_identity(opened_root, root_after, "directory", Path("."))
        if _version(opened_root) != _version(root_after):
            raise RuntimeError("directory identity changed during traversal: .")
    finally:
        _release_primary = sys.exception()
        try:
            os.close(scan_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    if offenders:
        print("private-key leakage detected")
    return 1 if offenders else 0


def scan_file_descriptors(
    private_key_descriptor: int, files: dict[str, int]
) -> list[str]:
    """Return public labels of held regular descriptors containing key material."""
    if not files or len(files) != len(set(files)):
        raise ValueError("held file scan requires unique public labels")
    private_key_pem = _read_bound_descriptor(
        private_key_descriptor, "private key descriptor"
    )
    private_key_der = _openssl(
        [
            "pkey",
            "-in",
            f"/proc/self/fd/{private_key_descriptor}",
            "-outform",
            "DER",
        ],
        pass_fds=(private_key_descriptor,),
    )
    patterns = (private_key_pem, private_key_der)
    results: list[list[str]] = []
    versions: dict[str, tuple[int, ...]] = {}
    for _pass in range(2):
        offenders: list[str] = []
        for label, descriptor in sorted(files.items()):
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("held scan input is not regular")
            current_version = _version(before)
            if label in versions and versions[label] != current_version:
                raise RuntimeError("held scan input changed")
            versions[label] = current_version
            os.lseek(descriptor, 0, os.SEEK_SET)
            if _descriptor_contains_secret(descriptor, patterns):
                offenders.append(label)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if _version(os.fstat(descriptor)) != current_version:
                raise RuntimeError("held scan input changed")
        for label, descriptor in sorted(files.items()):
            if _version(os.fstat(descriptor)) != versions[label]:
                raise RuntimeError("held scan input changed during terminal sweep")
        results.append(offenders)
    if results[0] != results[1]:
        raise RuntimeError("held scan result changed between passes")
    return results[1]


def scan(private_key: Path, root: Path) -> int:
    key_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    private_key_descriptor = os.open(private_key, key_flags)
    try:
        root_descriptor = os.open(root.resolve(strict=True), directory_flags)
        try:
            return scan_descriptors(private_key_descriptor, root_descriptor)
        finally:
            _release_primary = sys.exception()
            try:
                os.close(root_descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    finally:
        _release_primary = sys.exception()
        try:
            os.close(private_key_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    describe_parser = subparsers.add_parser("describe")
    describe_parser.add_argument("--certificate", required=True, type=Path)
    describe_parser.add_argument("--output", required=True, type=Path)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--private-key", required=True, type=Path)
    scan_parser.add_argument("--root", required=True, type=Path)

    subparsers.add_parser("scan-fixed-fds")
    subparsers.add_parser("scan-artifacts-fixed-fds")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "describe":
        describe(arguments.certificate, arguments.output)
        return 0
    if arguments.command == "scan":
        return scan(arguments.private_key, arguments.root)
    if arguments.command == "scan-fixed-fds":
        return scan_descriptors(25, 50)
    if arguments.command == "scan-artifacts-fixed-fds":
        offenders = scan_file_descriptors(
            25,
            {"srpm": 30, "core": 31, "modules": 32, "meta": 33},
        )
        for offender in offenders:
            print(offender)
        return 1 if offenders else 0
    raise AssertionError(f"unhandled command: {arguments.command}")


if __name__ == "__main__":
    raise SystemExit(main())
