"""Describe and audit a local module-signing identity without exposing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
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


def _openssl(arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *arguments],
        check=True,
        capture_output=True,
        input=input_bytes,
    ).stdout


def _strip_prefix(line: str, prefix: str) -> str:
    if not line.startswith(prefix):
        raise ValueError(f"unexpected openssl output: missing {prefix!r}")
    return line[len(prefix) :]


def describe(certificate: Path, output: Path) -> None:
    certificate_bytes = certificate.read_bytes()
    public_key_pem = _openssl(
        ["x509", "-in", os.fspath(certificate), "-pubkey", "-noout"]
    )
    public_key_der = _openssl(
        ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_key_pem
    )
    details = _openssl(
        [
            "x509",
            "-in",
            os.fspath(certificate),
            "-noout",
            "-serial",
            "-subject",
            "-startdate",
            "-enddate",
        ]
    ).decode("utf-8")
    lines = details.splitlines()
    if len(lines) != 4:
        raise ValueError("unexpected openssl certificate description")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "certificate_sha256": hashlib.sha256(certificate_bytes).hexdigest(),
        "spki_sha256": hashlib.sha256(public_key_der).hexdigest(),
        "serial": _strip_prefix(lines[0], "serial="),
        "subject": _strip_prefix(lines[1], "subject="),
        "not_before": _strip_prefix(lines[2], "notBefore="),
        "not_after": _strip_prefix(lines[3], "notAfter="),
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".part",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            os.chmod(temporary.fileno(), 0o600)
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _version(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_identity(
    expected: os.stat_result,
    observed: os.stat_result,
    kind: str,
    relative_path: Path,
) -> None:
    if _identity(expected) != _identity(observed):
        raise RuntimeError(
            f"{kind} identity changed during traversal: {relative_path.as_posix()}"
        )


def _stat_at(
    name: str, directory_descriptor: int, kind: str, relative_path: Path
) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError(
            f"{kind} identity changed during traversal: {relative_path.as_posix()}"
        ) from error


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
    directory_before = os.fstat(directory_descriptor)
    with os.scandir(directory_descriptor) as entries:
        names = sorted(entry.name for entry in entries)

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    for name in names:
        relative_path = relative_directory / name
        before = _stat_at(name, directory_descriptor, "entry", relative_path)
        if stat.S_ISDIR(before.st_mode):
            child_descriptor = os.open(
                name, directory_flags, dir_fd=directory_descriptor
            )
            try:
                opened = os.fstat(child_descriptor)
                _require_identity(before, opened, "directory", relative_path)
                _scan_directory(
                    child_descriptor, relative_path, exact_patterns, offenders
                )
                after = _stat_at(
                    name, directory_descriptor, "directory", relative_path
                )
                _require_identity(opened, after, "directory", relative_path)
            finally:
                os.close(child_descriptor)
        elif stat.S_ISREG(before.st_mode):
            file_descriptor = os.open(name, file_flags, dir_fd=directory_descriptor)
            try:
                opened = os.fstat(file_descriptor)
                _require_identity(before, opened, "file", relative_path)
                matched = _descriptor_contains_secret(file_descriptor, exact_patterns)
                if _version(opened) != _version(os.fstat(file_descriptor)):
                    raise RuntimeError(
                        "file changed during traversal: "
                        f"{relative_path.as_posix()}"
                    )
                after = _stat_at(name, directory_descriptor, "file", relative_path)
                _require_identity(opened, after, "file", relative_path)
                if matched:
                    offenders.append(relative_path.as_posix())
            finally:
                os.close(file_descriptor)

    if _version(directory_before) != _version(os.fstat(directory_descriptor)):
        display_path = relative_directory.as_posix() or "."
        raise RuntimeError(
            f"directory identity changed during traversal: {display_path}"
        )


def scan(private_key: Path, root: Path) -> int:
    private_key_pem = private_key.read_bytes()
    private_key_der = _openssl(
        ["pkey", "-in", os.fspath(private_key), "-outform", "DER"]
    )
    exact_patterns = (private_key_pem, private_key_der)
    resolved_root = root.resolve(strict=True)
    root_before = os.stat(resolved_root, follow_symlinks=False)
    if not stat.S_ISDIR(root_before.st_mode):
        raise NotADirectoryError(resolved_root)

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_descriptor = os.open(resolved_root, directory_flags)
    offenders: list[str] = []
    try:
        opened_root = os.fstat(root_descriptor)
        _require_identity(root_before, opened_root, "directory", Path("."))
        _scan_directory(root_descriptor, Path(), exact_patterns, offenders)
        root_after = os.stat(resolved_root, follow_symlinks=False)
        _require_identity(opened_root, root_after, "directory", Path("."))
    finally:
        os.close(root_descriptor)

    for offender in sorted(offenders):
        print(offender)
    return 1 if offenders else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    describe_parser = subparsers.add_parser("describe")
    describe_parser.add_argument("--certificate", required=True, type=Path)
    describe_parser.add_argument("--output", required=True, type=Path)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--private-key", required=True, type=Path)
    scan_parser.add_argument("--root", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "describe":
        describe(arguments.certificate, arguments.output)
        return 0
    if arguments.command == "scan":
        return scan(arguments.private_key, arguments.root)
    raise AssertionError(f"unhandled command: {arguments.command}")


if __name__ == "__main__":
    raise SystemExit(main())
