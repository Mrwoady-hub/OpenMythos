from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Sequence


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
SOURCE_FIELDS = {
    "schema_version",
    "product",
    "version",
    "archive_url",
    "archive_sha256",
    "signature_url",
    "signature_sha256",
    "signer_fingerprint",
    "source_date_epoch",
    "patches",
}
EXTERNAL_FIELDS = {
    "schema_version",
    "architecture",
    "fedora_bootc",
    "image_builder",
    "root_filesystem",
}
FEDORA_FIELDS = {
    "reference",
    "tag_observed",
    "version",
    "index_digest",
    "manifest_digest",
}
IMAGE_BUILDER_FIELDS = {"reference", "index_digest", "manifest_digest"}


@dataclass(frozen=True)
class SourceLock:
    schema_version: int
    product: str
    version: str
    archive_url: str
    archive_sha256: str
    signature_url: str
    signature_sha256: str
    signer_fingerprint: str
    source_date_epoch: int
    patches: Sequence[dict[str, Any]]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_object(path: Path) -> dict[str, Any]:
    raw = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
    )
    if not isinstance(raw, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return raw


def _require_exact_fields(raw: dict[str, Any], expected: set[str], name: str) -> None:
    unknown = set(raw) - expected
    missing = expected - set(raw)
    if unknown or missing:
        raise ValueError(
            f"{name} unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )


def load_source_lock(path: Path) -> SourceLock:
    raw = load_json_object(path)
    _require_exact_fields(raw, SOURCE_FIELDS, "source lock")
    if not isinstance(raw["patches"], list):
        raise ValueError("source lock patches must be a JSON array")
    return SourceLock(**{**raw, "patches": tuple(raw["patches"])})


def validate_source_lock(lock: SourceLock) -> None:
    if type(lock.schema_version) is not int or lock.schema_version != 1:
        raise ValueError("schema_version must be 1")
    if lock.product != "linux-openmythos" or lock.version != "6.18.48":
        raise ValueError("unexpected product or kernel version")
    if lock.archive_url != (
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.48.tar.xz"
    ):
        raise ValueError("unexpected kernel archive URL")
    if lock.signature_url != (
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.48.tar.sign"
    ):
        raise ValueError("unexpected kernel signature URL")
    for name, value in (
        ("archive_sha256", lock.archive_sha256),
        ("signature_sha256", lock.signature_sha256),
    ):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise ValueError(f"{name} must be 64 lowercase hex characters")
    if not isinstance(lock.signer_fingerprint, str) or not FINGERPRINT_RE.fullmatch(
        lock.signer_fingerprint
    ):
        raise ValueError("signer_fingerprint must be 40 uppercase hex characters")
    if type(lock.source_date_epoch) is not int or lock.source_date_epoch != 1787899659:
        raise ValueError("unexpected SOURCE_DATE_EPOCH")
    if lock.patches:
        raise ValueError("Gate 01 patch list must be empty")


def load_external_inputs(path: Path) -> dict[str, Any]:
    return load_json_object(path)


def validate_external_inputs(raw: dict[str, Any]) -> None:
    _require_exact_fields(raw, EXTERNAL_FIELDS, "external input lock")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("external input schema/architecture mismatch")
    if raw["architecture"] != "x86_64":
        raise ValueError("external input schema/architecture mismatch")
    if raw["root_filesystem"] != "ext4":
        raise ValueError("Gate 01 root filesystem must be ext4")
    fedora = raw["fedora_bootc"]
    builder = raw["image_builder"]
    if not isinstance(fedora, dict) or not isinstance(builder, dict):
        raise ValueError("image locks must be JSON objects")
    _require_exact_fields(fedora, FEDORA_FIELDS, "fedora_bootc")
    _require_exact_fields(builder, IMAGE_BUILDER_FIELDS, "image_builder")
    if fedora["reference"] != "quay.io/fedora/fedora-bootc":
        raise ValueError("unexpected Fedora bootc repository")
    if fedora["tag_observed"] != "44" or fedora["version"] != "44.20260905.0":
        raise ValueError("unexpected Fedora bootc version metadata")
    if builder["reference"] != "ghcr.io/osbuild/image-builder-cli":
        raise ValueError("unexpected image-builder repository")
    for section_name, section in (("fedora_bootc", fedora), ("image_builder", builder)):
        for digest_name in ("index_digest", "manifest_digest"):
            value = section[digest_name]
            if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
                raise ValueError(f"{section_name}.{digest_name} is not a sha256 digest")


def _validsig_primary_fingerprint(status_path: Path) -> str:
    statuses = [
        line.removeprefix("[GNUPG:] ").split()
        for line in status_path.read_text(encoding="utf-8").splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if len(statuses) != 1:
        raise ValueError("signature status must contain exactly one VALIDSIG")
    fields = statuses[0]
    if len(fields) < 2 or fields[0] != "VALIDSIG":
        raise ValueError("malformed VALIDSIG status")
    fingerprint = fields[-1]
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("VALIDSIG primary fingerprint is malformed")
    return fingerprint


def _inspect_oci_manifest(archive: Path) -> str:
    result = subprocess.run(
        ["skopeo", "inspect", "--raw", f"oci-archive:{archive}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return f"sha256:{hashlib.sha256(result.stdout).hexdigest()}"


def _atomic_write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def record_fetch(args: argparse.Namespace) -> None:
    source_lock = load_source_lock(args.source_lock)
    validate_source_lock(source_lock)
    external_lock = load_external_inputs(args.external_lock)
    validate_external_inputs(external_lock)

    observed_archive_sha256 = sha256_file(args.archive)
    if observed_archive_sha256 != source_lock.archive_sha256:
        raise ValueError("kernel archive digest mismatch")
    observed_signature_sha256 = sha256_file(args.signature)
    if observed_signature_sha256 != source_lock.signature_sha256:
        raise ValueError("kernel signature digest mismatch")
    signer_fingerprint = _validsig_primary_fingerprint(args.signature_status)
    if signer_fingerprint != source_lock.signer_fingerprint:
        raise ValueError("signature primary fingerprint mismatch")

    archives = {
        "fedora_bootc": args.fedora_archive,
        "image_builder": args.image_builder_archive,
    }
    image_reports: dict[str, dict[str, str]] = {}
    for image_name, archive in archives.items():
        image_lock = external_lock[image_name]
        observed_manifest = _inspect_oci_manifest(archive)
        if observed_manifest != image_lock["manifest_digest"]:
            raise ValueError(f"{image_name} child manifest digest mismatch")
        image_reports[image_name] = {
            "repository": image_lock["reference"],
            "expected_manifest_digest": image_lock["manifest_digest"],
            "observed_manifest_digest": observed_manifest,
            "archive_sha256": sha256_file(archive),
        }

    report = {
        "schema_version": 1,
        "source": {
            "expected_archive_sha256": source_lock.archive_sha256,
            "observed_archive_sha256": observed_archive_sha256,
            "expected_signature_sha256": source_lock.signature_sha256,
            "observed_signature_sha256": observed_signature_sha256,
            "signer_fingerprint": signer_fingerprint,
            "signature_valid": True,
        },
        "images": image_reports,
        "network_phase_completed": True,
    }
    _atomic_write_json(args.output, report)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record-fetch")
    record.add_argument("--source-lock", required=True, type=Path)
    record.add_argument("--external-lock", required=True, type=Path)
    record.add_argument("--archive", required=True, type=Path)
    record.add_argument("--signature", required=True, type=Path)
    record.add_argument("--signature-status", required=True, type=Path)
    record.add_argument("--fedora-archive", required=True, type=Path)
    record.add_argument("--image-builder-archive", required=True, type=Path)
    record.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "record-fetch":
        record_fetch(args)
        return 0
    raise ValueError(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
