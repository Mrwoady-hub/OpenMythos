from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


CONFIG_ASSIGNMENT_RE = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.+)$")
CONFIG_NOT_SET_RE = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
REQUIREMENTS_FIELDS = {
    "schema_version",
    "kernel_version",
    "kernel_release",
    "required",
}


@dataclass(frozen=True)
class ConfigRequirements:
    schema_version: int
    kernel_version: str
    kernel_release: str
    required: dict[str, str]


def parse_config(path: Path) -> dict[str, str]:
    config: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        assignment = CONFIG_ASSIGNMENT_RE.fullmatch(line)
        not_set = CONFIG_NOT_SET_RE.fullmatch(line)
        if assignment:
            symbol, value = assignment.groups()
        elif not_set:
            symbol, value = not_set.group(1), "n"
        elif not line or line.startswith("#"):
            continue
        else:
            raise ValueError(f"malformed config line {line_number}: {line}")
        if symbol in config:
            raise ValueError(f"duplicate config symbol: {symbol}")
        config[symbol] = value
    return config


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_requirements(path: Path) -> ConfigRequirements:
    raw = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
    )
    if not isinstance(raw, dict):
        raise ValueError("requirements root must be an object")
    unknown = set(raw) - REQUIREMENTS_FIELDS
    missing = REQUIREMENTS_FIELDS - set(raw)
    if unknown or missing:
        raise ValueError(
            f"requirements unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("requirements schema_version must be 1")
    if not isinstance(raw["kernel_version"], str) or not isinstance(
        raw["kernel_release"], str
    ):
        raise ValueError("kernel version and release must be strings")
    required = raw["required"]
    if not isinstance(required, dict):
        raise ValueError("required must be an object")
    symbols = list(required)
    if symbols != sorted(symbols):
        raise ValueError("required symbols must be sorted")
    if any(not symbol.startswith("CONFIG_") for symbol in symbols):
        raise ValueError("required symbols must start with CONFIG_")
    if any(not isinstance(value, str) for value in required.values()):
        raise ValueError("required symbol values must be strings")
    return ConfigRequirements(
        schema_version=raw["schema_version"],
        kernel_version=raw["kernel_version"],
        kernel_release=raw["kernel_release"],
        required=dict(required),
    )


def audit_config(
    config: dict[str, str], requirements: ConfigRequirements
) -> list[str]:
    errors: list[str] = []
    for symbol, expected in requirements.required.items():
        if symbol not in config:
            errors.append(f"{symbol}: missing, expected {expected}")
        elif config[symbol] != expected:
            errors.append(f"{symbol}: expected {expected}, got {config[symbol]}")
    return sorted(errors)


def _audit(args: argparse.Namespace) -> int:
    errors = audit_config(parse_config(args.config), load_requirements(args.requirements))
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def _checksum(args: argparse.Namespace) -> int:
    digest = hashlib.sha256(args.config.read_bytes()).hexdigest()
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_text(f"{digest}  {args.config.name}\n", encoding="ascii")
    temporary.replace(args.output)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("--config", required=True, type=Path)
    audit_parser.add_argument("--requirements", required=True, type=Path)
    audit_parser.set_defaults(handler=_audit)

    checksum_parser = subparsers.add_parser("checksum")
    checksum_parser.add_argument("--config", required=True, type=Path)
    checksum_parser.add_argument("--output", required=True, type=Path)
    checksum_parser.set_defaults(handler=_checksum)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
