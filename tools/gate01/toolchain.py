from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Sequence

from tools.gate01.inputs import load_json_object, sha256_file


@dataclass(frozen=True)
class ToolchainLock:
    schema_version: int
    architecture: str
    image_reference: str
    manifest_digest: str
    archive_sha256: str
    commands: dict[str, str]
    installed_rpms: Sequence[str]


TOOLCHAIN_FIELDS = {
    "schema_version",
    "architecture",
    "image_reference",
    "manifest_digest",
    "archive_sha256",
    "commands",
    "installed_rpms",
}
REQUIRED_COMMANDS = {"gcc", "ld", "make", "rpmbuild", "rpm", "python3"}
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_toolchain_lock(path: Path) -> ToolchainLock:
    raw = load_json_object(path)
    unknown = set(raw) - TOOLCHAIN_FIELDS
    missing = TOOLCHAIN_FIELDS - set(raw)
    if unknown or missing:
        raise ValueError(
            f"toolchain lock unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )
    return ToolchainLock(**{**raw, "installed_rpms": tuple(raw["installed_rpms"])})


def validate_toolchain_lock(lock: ToolchainLock) -> None:
    if lock.schema_version != 1 or lock.architecture != "x86_64":
        raise ValueError("toolchain schema/architecture mismatch")
    if ":latest" in lock.image_reference or "@sha256:" not in lock.image_reference:
        raise ValueError("floating image reference")
    if not OCI_DIGEST_RE.fullmatch(lock.manifest_digest):
        raise ValueError("invalid toolchain manifest digest")
    if not RAW_SHA256_RE.fullmatch(lock.archive_sha256):
        raise ValueError("invalid toolchain archive digest")
    if not lock.image_reference.endswith("@" + lock.manifest_digest):
        raise ValueError("toolchain reference/digest mismatch")
    if set(lock.commands) != REQUIRED_COMMANDS:
        raise ValueError("toolchain command inventory mismatch")
    if any(not value.strip() for value in lock.commands.values()):
        raise ValueError("toolchain command version is empty")
    if list(lock.installed_rpms) != sorted(set(lock.installed_rpms)):
        raise ValueError("installed RPM inventory must be sorted and unique")


def write_toolchain_lock(
    path: Path,
    *,
    image_reference: str,
    manifest_digest: str,
    archive_sha256: str,
    commands: dict[str, str],
    installed_rpms: list[str],
) -> None:
    lock = ToolchainLock(
        schema_version=1,
        architecture="x86_64",
        image_reference=image_reference,
        manifest_digest=manifest_digest,
        archive_sha256=archive_sha256,
        commands=dict(commands),
        installed_rpms=tuple(sorted(set(installed_rpms))),
    )
    validate_toolchain_lock(lock)
    payload = asdict(lock)
    payload["installed_rpms"] = list(lock.installed_rpms)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _write(args: argparse.Namespace) -> None:
    report = load_json_object(args.report)
    report_fields = {"commands", "installed_rpms"}
    unknown = set(report) - report_fields
    missing = report_fields - set(report)
    if unknown or missing:
        raise ValueError(
            f"toolchain report unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )
    write_toolchain_lock(
        args.path,
        image_reference=args.image_reference,
        manifest_digest=args.manifest_digest,
        archive_sha256=args.archive_sha256,
        commands=report["commands"],
        installed_rpms=report["installed_rpms"],
    )


def _verify(args: argparse.Namespace) -> None:
    lock = load_toolchain_lock(args.path)
    validate_toolchain_lock(lock)
    if args.archive is not None and sha256_file(args.archive) != lock.archive_sha256:
        raise ValueError("toolchain archive digest mismatch")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    write_parser = subparsers.add_parser("write")
    write_parser.add_argument("--path", required=True, type=Path)
    write_parser.add_argument("--image-reference", required=True)
    write_parser.add_argument("--manifest-digest", required=True)
    write_parser.add_argument("--archive-sha256", required=True)
    write_parser.add_argument("--report", required=True, type=Path)
    write_parser.set_defaults(handler=_write)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("path", type=Path)
    verify_parser.add_argument("--archive", type=Path)
    verify_parser.set_defaults(handler=_verify)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
