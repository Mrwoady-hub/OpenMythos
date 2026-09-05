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
PRIVATE_KEY_MARKER = re.compile(
    rb"-----(?:BEGIN|END) [^-\r\n]*PRIVATE KEY-----"
)


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


def scan(private_key: Path, root: Path) -> int:
    private_key_pem = private_key.read_bytes()
    private_key_der = _openssl(
        ["pkey", "-in", os.fspath(private_key), "-outform", "DER"]
    )
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise NotADirectoryError(resolved_root)
    offenders: list[str] = []

    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, directory_names, file_names in os.walk(
        resolved_root, followlinks=False, onerror=raise_walk_error
    ):
        directory_path = Path(directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not (directory_path / name).is_symlink()
        ]
        for name in file_names:
            candidate = directory_path / name
            candidate_stat = candidate.lstat()
            if not stat.S_ISREG(candidate_stat.st_mode):
                continue
            descriptor = os.open(
                candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError(f"file changed during scan: {candidate}")
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    contents = stream.read()
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if (
                private_key_pem in contents
                or private_key_der in contents
                or PRIVATE_KEY_MARKER.search(contents) is not None
            ):
                offenders.append(candidate.relative_to(resolved_root).as_posix())

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
