# Stone Boot Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and prove a reproducible Fedora 44 bootc QCOW2 that boots the OpenMythos-owned Linux 6.18.48 kernel under x86_64 UEFI QEMU and emits machine-verifiable identity evidence.

**Architecture:** Gate 01 builds a verified upstream kernel into three Fedora-compatible RPMs (`kernel-openmythos`, `-core`, and `-modules`) inside one pinned Fedora 44 toolchain image. A derived bootc payload replaces Fedora's stock kernel with those RPMs, runs `bootc container lint`, and is converted by the unified `image-builder` into an ext4 QCOW2. Two isolated builds must agree on the SRPM, installed RPM contents, OCI manifest/config/layers, and normalized immutable filesystem manifest; a one-shot UEFI QEMU boot must report the expected OS, kernel, source, config, and bootc payload digests.

**Tech Stack:** Linux 6.18.48, Fedora 44 bootc, RPM/rpmbuild, Podman/Buildah/Skopeo, dracut, unified osbuild `image-builder`, Python 3 standard library, Bash, QEMU 10.2, OVMF, systemd, Make.

**Spec:** `docs/superpowers/specs/2026-08-31-openmythos-os-architecture-design.md`

## Global Constraints

- Gate 01 is x86_64 and UEFI-only.
- The base is Fedora 44 bootc, pinned to x86_64 manifest `sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756` from index `sha256:778cafb9040cd2fb91d3ae7bf68bff6e775714cdd6ee47cbd9970646c40fd2cf`, image version `44.20260905.0`.
- The disk converter is unified `image-builder`, pinned to x86_64 manifest `sha256:b44e26d185916d28a88bbc04faa986ccc44535691715f1bc276523693b19ccca` from index `sha256:8605bd61eb884a403736c8cc201a1fbd5b0dcdcf58988902cb65753867934353`.
- The kernel source is upstream Linux 6.18.48. Its `linux-6.18.48.tar.xz` SHA-256 is `5ebdadb10a4b5708fc6b1c457764a110bc49f8150cc3502c59b921ead8c6fc8c`; its detached signature SHA-256 is `71abbb7d63d2978f1c8ed42bae650ec33a6039fe085f39178e4815bbed583dbc`.
- The kernel.org signer must be Greg Kroah-Hartman, fingerprint `647F28654894E3BD457199BE38DBBDC86092693E`.
- `SOURCE_DATE_EPOCH` is `1787899659` (`2026-08-28T06:47:39Z`).
- `linux-openmythos` is the product label. RPM names use `kernel-openmythos`. The expected kernel release is `6.18.48-1.openmythos.fc44.x86_64`.
- The only permitted downstream kernel patch set is the explicitly locked list in `source.lock.json`; Gate 01 starts with an empty list.
- Gate 01 includes only firmware and drivers needed by QEMU virtual hardware. It does not include NVIDIA, the reference-hardware firmware cohort, Hyprland, Quickshell, Codex, Claude, Hermes integration, installer ISO work, MOK enrollment, Secure Boot acceptance, updates, rollback, or physical-disk writes.
- Gate 01 PE kernel signing is deferred to Gate 02. Module signing remains enabled and uses one declared development-only key supplied from outside Git; its public identity is captured before the build and the same private key is supplied byte-for-byte as sealed FD25 only to signing work in both reproducibility builders. The signed-module comparison is reproducible for that declared per-run identity; a third party needs that same external identity to reproduce signature bytes. Gate 02 replaces it with controlled release-key provisioning.
- A private key, credential, generated disk, RPM, source archive, container archive, or build cache must never be committed.
- Existing files under `open_mythos/` are not modified by this gate.
- Network access is allowed only for the explicit input-fetch and initial toolchain-image construction steps. Kernel, RPM, payload, comparison, QCOW2, and QEMU proof steps run from locked local inputs.
- Build scripts use `set -Eeuo pipefail`, quote paths, refuse execution as the wrong privilege level, and write only below `build/gate01/` unless they are invoking rootful Podman storage explicitly.
- Rootful operations are limited to isolated Podman stores and `image-builder`; no command receives a physical block device.
- Every task ends with its own tests and commit. Never stage the user's unrelated `open_mythos/main.py` work.

---

## Planned Repository Map

```text
.github/workflows/gate01.yml                  privileged self-hosted full-gate workflow
.gitignore                                    local build, key, VM, and visual scratch exclusions
Makefile                                      stable developer entry points
os/build/inputs.lock.json                     immutable external OCI/tool inputs
os/build/toolchain.lock.json                  generated kernel-builder digest and RPM inventory
os/build/qemu.lock.json                       QEMU and OVMF proof-environment lock
os/build/reproducibility-allowlist.json        reviewed metadata-only RPM differences
os/build/schemas/gate01-evidence.schema.json  final evidence contract
os/kernel/Containerfile.builder               Fedora 44 kernel build environment
os/kernel/README.md                           kernel ownership and key-handling notes
os/kernel/source.lock.json                    source, signature, epoch, and patch lock
os/kernel/keys/gregkh-kernel-releases.asc     pinned public verification key
os/kernel/keys/gregkh-kernel-releases.asc.sha256 exact public-key blob lock
os/kernel/config/fedora-44-x86_64.config      pinned Fedora compatibility baseline
os/kernel/config/fedora-44-x86_64.config.sha256 baseline checksum
os/kernel/config/gate01-x86_64.fragment       deliberate OpenMythos config changes
os/kernel/config/requirements.json            exact required symbol/value contract
os/kernel/config/6.18.48-x86_64.config        generated, reviewed final config
os/kernel/config/6.18.48-x86_64.config.sha256 generated config checksum
os/kernel/packaging/kernel-openmythos.spec     focused meta/core/modules RPM packaging
os/images/gate01/Containerfile                derived bootc payload
os/images/gate01/disk.toml                    image-builder kernel command-line customization
os/images/gate01/firmware.lock.json            empty QEMU firmware contract
os/images/gate01/files/usr/lib/os-release      OpenMythos image identity
os/images/gate01/files/usr/lib/openmythos/gate01-release.env.in
os/images/gate01/files/usr/libexec/openmythos-gate01-boot-report
os/images/gate01/files/usr/lib/systemd/system/openmythos-gate01-boot-report.service
os/images/gate01/files/usr/lib/systemd/system/openmythos-gate01-boot-report.timer
scripts/gate01/create-development-key.sh      local module-key bootstrap
scripts/gate01/fetch-inputs.sh                checksum and OpenPGP-verified source fetch
scripts/gate01/build-toolchain.sh              build and lock the Fedora toolchain image
scripts/gate01/generate-config.sh              deterministic final-config generation
scripts/gate01/build-kernel.sh                 isolated SRPM/RPM build
scripts/gate01/build-payload.sh                isolated OCI payload build/export
scripts/gate01/build-qcow2.sh                  pinned image-builder conversion
scripts/gate01/boot-qemu.sh                    disposable UEFI boot harness
scripts/gate01/repro-check.sh                  two-builder comparison
scripts/gate01/release-gate.sh                 ordered, fail-closed Gate 01 entry point
scripts/gate01/preflight.sh                    read-only fast/full host checks
tools/gate01/layout.py                         path and workspace invariants
tools/gate01/inputs.py                         lock validation and digest helpers
tools/gate01/toolchain.py                      builder inventory and lock validation
tools/gate01/kernel_config.py                  config parser and requirements audit
tools/gate01/module_key.py                     public-only module identity evidence
tools/gate01/proof_io.py                       descriptor custody, sealing, and receipt I/O
tools/gate01/container_runtime.py              exact Podman lifecycle and live attestation
tools/gate01/kernel_bootstrap.py               stdlib-only held-FD entry and sealed code authority
tools/gate01/kernel_build.py                   kernel build, inspection, and proof orchestration
tools/gate01/oci_rootfs.py                     independent OCI merge and mounted-root audit
tools/gate01/rpm_artifacts.py                  RPM set and installed-content manifest
tools/gate01/oci_artifacts.py                  OCI descriptor extraction/comparison
tools/gate01/qcow2_artifacts.py                normalized immutable-tree comparison
tools/gate01/boot_report.py                    serial report parsing and assertions
tools/gate01/evidence.py                       canonical final evidence assembly
tests/gate01/fixtures/                         deliberately valid and invalid small fixtures
tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json  exact normalized no-hook runtime fixture
tests/gate01/test_*.py                         fast standard-library unit tests
docs/operations/gate01-stone-boot-proof.md     exact operator runbook and recovery guidance
```

Generated artifacts live under `build/gate01/{cache,secrets,builder-a,builder-b,canonical,compare,evidence}`. Each builder keeps its own kernel, payload, QCOW2, Podman, and QEMU subdirectories. The build directory is disposable; the final evidence bundle is copied to release storage by CI before cleanup.

## Gate 01 Pass/Fail Contract

The gate is green only when all of these are true:

1. The source archive checksum, detached-signature checksum, signature, and signer fingerprint verify.
2. The final committed config has no unresolved symbols and matches every value in `requirements.json`.
3. Builder A and B produce byte-identical SRPMs.
4. Builder A and B produce the same RPM NEVR set and identical normalized installed-file manifests, including module signatures; raw binary RPM hashes are recorded but advisory.
5. Builder A and B produce identical OCI manifest digest, config digest, and ordered layer digests.
6. `bootc container lint` passes and the payload contains exactly one kernel directory, with `vmlinuz` and `initramfs.img` adjacent under `/usr/lib/modules/$kver/`, and no payload-owned `/boot` content.
7. Two QCOW2 conversions produce matching normalized `/usr` and deployment-content manifests. QCOW2 byte hashes and allocation maps are advisory because UUIDs and wrapper metadata may differ.
8. A fresh copy-on-write disk boots via OVMF, reports UEFI, runs the exact OpenMythos kernel, reports the expected bootc payload digest, reaches `multi-user.target`, and powers off cleanly.
9. Every negative fixture fails for its named invariant.
10. `build/gate01/evidence/gate01-evidence.json` validates against the schema and has `verdict: "pass"`.

### Task 1: Establish the Gate 01 repository and command contract

**Files:**
- Create: `.gitignore`
- Create: `Makefile`
- Create: `tools/__init__.py`
- Create: `tools/gate01/__init__.py`
- Create: `tools/gate01/layout.py`
- Create: `tests/gate01/__init__.py`
- Create: `tests/gate01/test_layout.py`

**Interfaces:**
- Consumes: repository root resolved from `tools/gate01/layout.py`.
- Produces: `REPO_ROOT`, `GATE01_BUILD_ROOT`, `relative_to_repo(path: Path) -> Path`, and `require_gate01_output(path: Path) -> Path`; stable `make gate01-unit` and later `make gate01` entry points.

- [ ] **Step 1: Write the failing path-boundary tests**

```python
# tests/gate01/test_layout.py
from pathlib import Path
import unittest

from tools.gate01.layout import (
    GATE01_BUILD_ROOT,
    REPO_ROOT,
    relative_to_repo,
    require_gate01_output,
)


class LayoutTests(unittest.TestCase):
    def test_build_root_is_scoped_to_repository(self) -> None:
        self.assertEqual(GATE01_BUILD_ROOT, REPO_ROOT / "build" / "gate01")

    def test_relative_to_repo_rejects_escape(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside repository"):
            relative_to_repo(REPO_ROOT.parent / "other")

    def test_gate01_output_rejects_broad_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside Gate 01 build root"):
            require_gate01_output(REPO_ROOT)

    def test_gate01_output_accepts_descendant(self) -> None:
        candidate = GATE01_BUILD_ROOT / "builder-a" / "rpms"
        self.assertEqual(require_gate01_output(candidate), candidate.resolve())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test and confirm the module is absent**

Run: `python3 -m unittest tests.gate01.test_layout -v`

Expected: `ERROR` with `ModuleNotFoundError: No module named 'tools.gate01.layout'`.

- [ ] **Step 3: Implement the path boundary**

```python
# tools/gate01/layout.py
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE01_BUILD_ROOT = (REPO_ROOT / "build" / "gate01").resolve()


def relative_to_repo(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"path is outside repository: {resolved}") from exc


def require_gate01_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(GATE01_BUILD_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"path is outside Gate 01 build root: {resolved}"
        ) from exc
    if resolved == GATE01_BUILD_ROOT:
        raise ValueError("refusing Gate 01 build root itself as an output target")
    return resolved
```

Create empty `tools/__init__.py`, `tools/gate01/__init__.py`, and `tests/gate01/__init__.py` so imports are deterministic.

- [ ] **Step 4: Add repository exclusions and stable make targets**

```gitignore
# .gitignore
/.superpowers/
/build/
/dist/
**/__pycache__/
*.py[cod]
*.pem
*.key
*.p12
*.qcow2
*.oci.tar
*.rpm
```

```make
# Makefile
PYTHON ?= python3

.PHONY: gate01-unit gate01-inputs gate01-config gate01-kernel gate01-payload
.PHONY: gate01-qcow2 gate01-boot gate01-repro gate01

gate01-unit:
	$(PYTHON) -m unittest discover -s tests/gate01 -p 'test_*.py' -v

gate01-inputs:
	scripts/gate01/fetch-inputs.sh

gate01-config:
	scripts/gate01/generate-config.sh --check

gate01-kernel:
	scripts/gate01/build-kernel.sh canonical

gate01-payload:
	scripts/gate01/build-payload.sh canonical

gate01-qcow2:
	scripts/gate01/build-qcow2.sh canonical

gate01-boot:
	scripts/gate01/boot-qemu.sh canonical

gate01-repro:
	scripts/gate01/repro-check.sh

gate01:
	scripts/gate01/release-gate.sh
```

- [ ] **Step 5: Verify the boundary and repository hygiene**

Run: `python3 -m unittest tests.gate01.test_layout -v`

Expected: four tests pass.

Run: `git check-ignore -v .superpowers/example build/gate01/example test.qcow2 test.key`

Expected: each path is matched by the new root `.gitignore`.

Run: `git diff --check`

Expected: no output.

- [ ] **Step 6: Commit the repository contract**

```bash
git add .gitignore Makefile tools/__init__.py tools/gate01/__init__.py \
  tools/gate01/layout.py tests/gate01/__init__.py tests/gate01/test_layout.py
git commit -m "build: establish Stone Boot Proof contract"
```

### Task 2: Lock and verify every external Gate 01 input

**Files:**
- Create: `os/build/inputs.lock.json`
- Create: `os/kernel/source.lock.json`
- Create: `os/kernel/keys/gregkh-kernel-releases.asc`
- Create: `os/kernel/keys/gregkh-kernel-releases.asc.sha256`
- Create: `tools/gate01/inputs.py`
- Create: `scripts/gate01/fetch-inputs.sh`
- Create: `tests/gate01/test_inputs.py`
- Create: `tests/gate01/fixtures/source-lock-bad-digest.json`

**Interfaces:**
- Consumes: the exact OCI, kernel, signature, fingerprint, and epoch values in Global Constraints.
- Produces: `sha256_file(path: Path) -> str`, `load_source_lock(path: Path) -> SourceLock`, `validate_source_lock(lock: SourceLock) -> None`, `load_external_inputs(path: Path) -> dict[str, Any]`, `validate_external_inputs(raw: dict[str, Any]) -> None`, verified files at `build/gate01/cache/sources/linux-6.18.48.{tar.xz,tar.sign}`, pinned OCI archives at `build/gate01/cache/images/{fedora-bootc,image-builder}.oci.tar`, canonical `build/gate01/cache/input-verification.json`, and exit code `0` only after every digest and OpenPGP check passes.

- [ ] **Step 1: Write failing lock validation tests**

```python
# tests/gate01/test_inputs.py
import json
from pathlib import Path
import tempfile
import unittest

from tools.gate01.inputs import (
    load_external_inputs,
    load_source_lock,
    validate_external_inputs,
    validate_source_lock,
)


REPO = Path(__file__).resolve().parents[2]


class InputLockTests(unittest.TestCase):
    def test_canonical_source_lock_is_valid(self) -> None:
        lock = load_source_lock(REPO / "os/kernel/source.lock.json")
        validate_source_lock(lock)
        self.assertEqual(lock.version, "6.18.48")
        self.assertEqual(lock.patches, ())

    def test_canonical_external_input_lock_is_valid(self) -> None:
        raw = load_external_inputs(REPO / "os/build/inputs.lock.json")
        validate_external_inputs(raw)
        self.assertEqual(raw["architecture"], "x86_64")
        self.assertEqual(raw["root_filesystem"], "ext4")

    def test_non_sha256_digest_is_rejected(self) -> None:
        fixture = REPO / "tests/gate01/fixtures/source-lock-bad-digest.json"
        lock = load_source_lock(fixture)
        with self.assertRaisesRegex(ValueError, "archive_sha256"):
            validate_source_lock(lock)

    def test_unknown_fields_are_rejected(self) -> None:
        canonical = json.loads(
            (REPO / "os/kernel/source.lock.json").read_text(encoding="utf-8")
        )
        canonical["floating_ref"] = "latest"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(canonical), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                load_source_lock(path)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and confirm the lock API is absent**

Run: `python3 -m unittest tests.gate01.test_inputs -v`

Expected: `ERROR` because `tools.gate01.inputs` does not exist.

- [ ] **Step 3: Add the exact external image lock**

```json
{
  "schema_version": 1,
  "architecture": "x86_64",
  "fedora_bootc": {
    "reference": "quay.io/fedora/fedora-bootc",
    "tag_observed": "44",
    "version": "44.20260905.0",
    "index_digest": "sha256:778cafb9040cd2fb91d3ae7bf68bff6e775714cdd6ee47cbd9970646c40fd2cf",
    "manifest_digest": "sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756"
  },
  "image_builder": {
    "reference": "ghcr.io/osbuild/image-builder-cli",
    "index_digest": "sha256:8605bd61eb884a403736c8cc201a1fbd5b0dcdcf58988902cb65753867934353",
    "manifest_digest": "sha256:b44e26d185916d28a88bbc04faa986ccc44535691715f1bc276523693b19ccca"
  },
  "root_filesystem": "ext4"
}
```

- [ ] **Step 4: Add the exact kernel source lock and invalid fixture**

```json
{
  "schema_version": 1,
  "product": "linux-openmythos",
  "version": "6.18.48",
  "archive_url": "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.48.tar.xz",
  "archive_sha256": "5ebdadb10a4b5708fc6b1c457764a110bc49f8150cc3502c59b921ead8c6fc8c",
  "signature_url": "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.48.tar.sign",
  "signature_sha256": "71abbb7d63d2978f1c8ed42bae650ec33a6039fe085f39178e4815bbed583dbc",
  "signer_fingerprint": "647F28654894E3BD457199BE38DBBDC86092693E",
  "source_date_epoch": 1787899659,
  "patches": []
}
```

The invalid fixture is the same object except `archive_sha256` is exactly `"sha256-is-not-accepted-here"`.

- [ ] **Step 5: Implement strict dataclass parsing and digest validation**

```python
# tools/gate01/inputs.py
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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


def load_source_lock(path: Path) -> SourceLock:
    raw = load_json_object(path)
    unknown = set(raw) - SOURCE_FIELDS
    missing = SOURCE_FIELDS - set(raw)
    if unknown or missing:
        raise ValueError(
            f"source lock unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )
    return SourceLock(**{**raw, "patches": tuple(raw["patches"])})


def validate_source_lock(lock: SourceLock) -> None:
    if lock.schema_version != 1:
        raise ValueError("schema_version must be 1")
    if lock.product != "linux-openmythos" or lock.version != "6.18.48":
        raise ValueError("unexpected product or kernel version")
    for name, value in (
        ("archive_sha256", lock.archive_sha256),
        ("signature_sha256", lock.signature_sha256),
    ):
        if not SHA256_RE.fullmatch(value):
            raise ValueError(f"{name} must be 64 lowercase hex characters")
    if not re.fullmatch(r"[0-9A-F]{40}", lock.signer_fingerprint):
        raise ValueError("signer_fingerprint must be 40 uppercase hex characters")
    if lock.source_date_epoch != 1787899659:
        raise ValueError("unexpected SOURCE_DATE_EPOCH")
    if lock.patches:
        raise ValueError("Gate 01 patch list must be empty")


EXTERNAL_FIELDS = {
    "schema_version", "architecture", "fedora_bootc",
    "image_builder", "root_filesystem",
}
FEDORA_FIELDS = {
    "reference", "tag_observed", "version", "index_digest", "manifest_digest",
}
IMAGE_BUILDER_FIELDS = {"reference", "index_digest", "manifest_digest"}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_external_inputs(path: Path) -> dict[str, Any]:
    return load_json_object(path)


def _require_exact_fields(raw: dict[str, Any], expected: set[str], name: str) -> None:
    unknown = set(raw) - expected
    missing = expected - set(raw)
    if unknown or missing:
        raise ValueError(
            f"{name} unknown fields={sorted(unknown)} missing={sorted(missing)}"
        )


def validate_external_inputs(raw: dict[str, Any]) -> None:
    _require_exact_fields(raw, EXTERNAL_FIELDS, "external input lock")
    if raw["schema_version"] != 1 or raw["architecture"] != "x86_64":
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
            if not DIGEST_RE.fullmatch(section[digest_name]):
                raise ValueError(f"{section_name}.{digest_name} is not a sha256 digest")
```

- [ ] **Step 6: Retrieve and pin the kernel.org release key**

Run the key lookup in a disposable keyring, reject every fingerprint except the locked fingerprint, export only that public key, and remove the disposable keyring:

```bash
keyring_dir=$(mktemp -d)
chmod 700 "$keyring_dir"
GNUPGHOME="$keyring_dir" gpg --batch --auto-key-locate clear,wkd \
  --locate-keys gregkh@kernel.org
fingerprint=$(GNUPGHOME="$keyring_dir" gpg --batch --with-colons \
  --fingerprint gregkh@kernel.org | awk -F: '$1 == "fpr" {print $10; exit}')
test "$fingerprint" = "647F28654894E3BD457199BE38DBBDC86092693E"
GNUPGHOME="$keyring_dir" gpg --batch --armor --export "$fingerprint" \
  > os/kernel/keys/gregkh-kernel-releases.asc
(cd os/kernel/keys && sha256sum gregkh-kernel-releases.asc \
  > gregkh-kernel-releases.asc.sha256)
rm -rf -- "$keyring_dir"
```

Run `sha256sum --check os/kernel/keys/gregkh-kernel-releases.asc.sha256`, then show the committed key in a disposable keyring and remove that keyring after the fingerprint check.

Expected: the blob checksum passes and the fingerprint is exactly `647F28654894E3BD457199BE38DBBDC86092693E`. Later builds never regenerate the committed key from WKD.

- [ ] **Step 7: Implement the verified, fail-closed fetch script**

The script accepts no arguments for the release path. For negative testing only, it also accepts `--source-lock PATH --skip-images`; `PATH` must resolve below `build/gate01/`, and those two options must appear together.

```bash
#!/usr/bin/env bash
# scripts/gate01/fetch-inputs.sh
set -Eeuo pipefail
umask 022

repo_root=$(git rev-parse --show-toplevel)
lock="$repo_root/os/kernel/source.lock.json"
skip_images=0
if [[ $# -ne 0 ]]; then
  [[ $# -eq 3 ]] || exit 2
  [[ $1 == --source-lock && $3 == --skip-images ]] || exit 2
  lock=$(realpath -- "$2")
  [[ $lock == "$repo_root/build/gate01/"* ]] || exit 2
  skip_images=1
fi
cache="$repo_root/build/gate01/cache/sources"
image_cache="$repo_root/build/gate01/cache/images"
key="$repo_root/os/kernel/keys/gregkh-kernel-releases.asc"
image_lock="$repo_root/os/build/inputs.lock.json"
mkdir -p "$cache" "$image_cache"

(cd "$repo_root/os/kernel/keys" && \
  sha256sum --check gregkh-kernel-releases.asc.sha256)

keyring_dir=""
archive=""
signature=""
cleanup() {
  if [[ -n "$archive" ]]; then rm -f -- "$archive.part"; fi
  if [[ -n "$signature" ]]; then rm -f -- "$signature.part"; fi
  rm -f -- "$image_cache/fedora-bootc.oci.tar.part"
  rm -f -- "$image_cache/image-builder.oci.tar.part"
  if [[ -n "$keyring_dir" ]]; then
    rm -rf -- "$keyring_dir"
  fi
}
trap cleanup EXIT

version=$(jq -er '.version' "$lock")
archive="$cache/linux-$version.tar.xz"
signature="$cache/linux-$version.tar.sign"
archive_url=$(jq -er '.archive_url' "$lock")
signature_url=$(jq -er '.signature_url' "$lock")
archive_sha=$(jq -er '.archive_sha256' "$lock")
signature_sha=$(jq -er '.signature_sha256' "$lock")
expected_fpr=$(jq -er '.signer_fingerprint' "$lock")

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$archive.part" "$archive_url"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$signature.part" "$signature_url"
printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum --check --status
printf '%s  %s\n' "$signature_sha" "$signature.part" | sha256sum --check --status
mv "$archive.part" "$archive"
mv "$signature.part" "$signature"

keyring_dir=$(mktemp -d -p "$cache")
chmod 700 "$keyring_dir"
GNUPGHOME="$keyring_dir" gpg --batch --import "$key" >/dev/null 2>&1
actual_fpr=$(GNUPGHOME="$keyring_dir" gpg --batch --with-colons \
  --fingerprint | awk -F: '$1 == "fpr" {print $10; exit}')
test "$actual_fpr" = "$expected_fpr"
signature_status="$cache/signature-status.txt"
xz -cd "$archive" | GNUPGHOME="$keyring_dir" gpgv --status-fd=1 \
  --keyring "$keyring_dir/pubring.kbx" "$signature" - > "$signature_status"
grep -q '^\[GNUPG:\] VALIDSIG ' "$signature_status"

if [[ $skip_images -eq 0 ]]; then
  for image_name in fedora_bootc image_builder; do
    reference=$(jq -er --arg name "$image_name" '.[$name].reference' "$image_lock")
    manifest=$(jq -er --arg name "$image_name" '.[$name].manifest_digest' "$image_lock")
    case "$image_name" in
      fedora_bootc) output="$image_cache/fedora-bootc.oci.tar" ;;
      image_builder) output="$image_cache/image-builder.oci.tar" ;;
      *) exit 2 ;;
    esac
    skopeo copy --override-os linux --override-arch amd64 \
      "docker://$reference@$manifest" "oci-archive:$output.part:$image_name"
    actual="sha256:$(skopeo inspect --raw "oci-archive:$output.part" | sha256sum | awk '{print $1}')"
    test "$actual" = "$manifest"
    mv "$output.part" "$output"
  done
  python3 -m tools.gate01.inputs record-fetch \
    --source-lock "$lock" --external-lock "$image_lock" \
    --archive "$archive" --signature "$signature" \
    --signature-status "$signature_status" \
    --fedora-archive "$image_cache/fedora-bootc.oci.tar" \
    --image-builder-archive "$image_cache/image-builder.oci.tar" \
    --output "$repo_root/build/gate01/cache/input-verification.json"
  printf 'cached Fedora bootc and image-builder at their locked x86_64 manifests\n'
fi
printf 'verified linux-%s source and signature from %s\n' "$version" "$expected_fpr"
```

The fetch report records each local OCI archive's raw SHA-256 for custody, but that transport-tar hash is not a committed identity because Skopeo serialization can vary. Every later consumer reopens the archive, hashes the selected raw manifest, and requires the committed child-manifest digest before import; the content-addressed manifest/config/layers, not the tar wrapper, are the immutable input.

The `inputs.py record-fetch` subcommand rejects duplicate JSON keys, rechecks every source digest, requires exactly one GnuPG `VALIDSIG` status and the locked primary fingerprint, opens both OCI archives through Skopeo to recheck their child manifests, and atomically writes exact fields `schema_version`, `source`, `images`, and `network_phase_completed`. The two nested image objects include repository, expected/observed manifest digest, and raw archive SHA-256; `source` includes expected/observed archive and signature hashes, signer fingerprint, and `signature_valid=true`. The negative `--skip-images` path does not write or overwrite this report.

- [ ] **Step 8: Run positive and negative verification**

Run: `python3 -m unittest tests.gate01.test_inputs -v`

Expected: four tests pass.

Run: `scripts/gate01/fetch-inputs.sh`

Expected: `verified linux-6.18.48 source and signature from 647F28654894E3BD457199BE38DBBDC86092693E`.

Negative check: copy the lock to `build/gate01/source.lock.bad.json`, change one hex digit of `archive_sha256`, then run `scripts/gate01/fetch-inputs.sh --source-lock build/gate01/source.lock.bad.json --skip-images`. Expected: nonzero at SHA-256 verification before OpenPGP verification. Do not modify the committed lock.

- [ ] **Step 9: Commit the immutable input contract**

```bash
git add os/build/inputs.lock.json os/kernel/source.lock.json \
  os/kernel/keys/gregkh-kernel-releases.asc \
  os/kernel/keys/gregkh-kernel-releases.asc.sha256 tools/gate01/inputs.py \
  scripts/gate01/fetch-inputs.sh tests/gate01/test_inputs.py \
  tests/gate01/fixtures/source-lock-bad-digest.json
git commit -m "build: lock Gate 01 source and image inputs"
```

### Task 3: Build and pin the Fedora 44 kernel toolchain image

**Files:**
- Create: `os/kernel/Containerfile.builder`
- Create: `os/build/toolchain.lock.json`
- Create: `tools/gate01/toolchain.py`
- Create: `scripts/gate01/build-toolchain.sh`
- Create: `tests/gate01/test_toolchain.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `fedora_bootc.manifest_digest` from `os/build/inputs.lock.json`.
- Produces: local image `localhost/openmythos/kernel-builder:fedora44`, OCI archive `build/gate01/cache/kernel-builder.oci.tar`, and `ToolchainLock` containing its actual manifest digest, archive digest, installed RPM NEVRAs, and compiler/build-tool versions. All later kernel builds consume the archive and verify both digests before running with `--network=none`.

- [ ] **Step 1: Write failing toolchain-lock tests**

```python
# tests/gate01/test_toolchain.py
import json
from pathlib import Path
import tempfile
import unittest

from tools.gate01.toolchain import load_toolchain_lock, validate_toolchain_lock


REPO = Path(__file__).resolve().parents[2]


class ToolchainLockTests(unittest.TestCase):
    def test_committed_lock_has_required_tools(self) -> None:
        lock = load_toolchain_lock(REPO / "os/build/toolchain.lock.json")
        validate_toolchain_lock(lock)
        self.assertEqual(lock.architecture, "x86_64")
        self.assertIn("gcc", lock.commands)
        self.assertIn("rpmbuild", lock.commands)
        self.assertIn("make", lock.commands)

    def test_floating_builder_reference_is_rejected(self) -> None:
        raw = {
            "schema_version": 1,
            "architecture": "x86_64",
            "image_reference": "localhost/openmythos/kernel-builder:latest",
            "manifest_digest": "sha256:" + "1" * 64,
            "archive_sha256": "2" * 64,
            "commands": {"gcc": "gcc 15", "make": "GNU Make 4", "rpmbuild": "RPM 6"},
            "installed_rpms": ["gcc-15-1.fc44.x86_64"]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolchain.lock.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            lock = load_toolchain_lock(path)
            with self.assertRaisesRegex(ValueError, "floating image reference"):
                validate_toolchain_lock(lock)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and confirm the toolchain API is absent**

Run: `python3 -m unittest tests.gate01.test_toolchain -v`

Expected: `ERROR` because `tools.gate01.toolchain` does not exist.

- [ ] **Step 3: Define the smallest Fedora 44 builder that can compile and package Linux**

```dockerfile
# os/kernel/Containerfile.builder
FROM quay.io/fedora/fedora-bootc@sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756

RUN dnf -y install \
      bash bc binutils bison cpio diffutils dwarves \
      elfutils-libelf-devel findutils flex gcc gcc-c++ glibc-static \
      gpg2 hostname kmod libfaketime make openssl openssl-devel patch \
      perl-interpreter python3 python3-jsonschema rpm-build rpmdevtools rsync tar xz zstd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

RUN test "$(rpm --eval '%{?dist}')" = ".fc44" \
    && test "$(uname -m)" = "x86_64"

LABEL org.opencontainers.image.title="OpenMythos Linux 6.18 Gate 01 builder" \
      org.opencontainers.image.source="https://github.com/The-Swarm-Corporation/OpenMythos" \
      org.opencontainers.image.base.digest="sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756"
```

This is the only step allowed to resolve Fedora RPM repositories. The resulting OCI archive, not a future rebuild of this Containerfile, is the toolchain input used by the reproducibility proof.

- [ ] **Step 4: Implement canonical toolchain recording and validation**

`tools/gate01/toolchain.py` must define these exact public interfaces and bodies:

```python
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
    "schema_version", "architecture", "image_reference", "manifest_digest",
    "archive_sha256", "commands", "installed_rpms",
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
```

Import `asdict` and `dataclass` from `dataclasses`, plus `argparse`, `hashlib`, `json`, `Path`, and `re`; import `load_json_object` and `sha256_file` from `tools.gate01.inputs`. The CLI has a `write` parser with the five options shown in Step 5 and a `verify` parser with positional lock path plus optional `--archive`. `write` loads the report with duplicate-key rejection, passes its two exact keys to `write_toolchain_lock`, and exits nonzero on unknown report keys. `verify` validates the lock; when `--archive` is supplied, it also compares `sha256_file(archive)` with `archive_sha256` and raises `ValueError("toolchain archive digest mismatch")` on disagreement.

- [ ] **Step 5: Implement the one-time builder construction and lock script**

The script must:

1. refuse root;
2. pull the exact Fedora child manifest from `inputs.lock.json`;
3. build with `--pull=never --no-cache --format=oci --timestamp=1787899659`;
4. export with Skopeo to `build/gate01/cache/kernel-builder.oci.tar`;
5. calculate the archive SHA-256 and raw OCI manifest digest;
6. run the image to capture command versions and `rpm -qa --qf '%{NEVRA}\n' | LC_ALL=C sort`;
7. write `os/build/toolchain.lock.json` through `write_toolchain_lock`;
8. immediately reload and validate the new lock.

Use these exact core commands in `scripts/gate01/build-toolchain.sh`:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
test "$(id -u)" -ne 0 || { echo "run the toolchain build rootless" >&2; exit 2; }

repo_root=$(git rev-parse --show-toplevel)
inputs="$repo_root/os/build/inputs.lock.json"
output="$repo_root/build/gate01/cache/kernel-builder.oci.tar"
tag="localhost/openmythos/kernel-builder:fedora44"
base_ref=$(jq -er '.fedora_bootc.reference' "$inputs")
base_digest=$(jq -er '.fedora_bootc.manifest_digest' "$inputs")
mkdir -p "$(dirname "$output")"

podman pull "$base_ref@$base_digest"
podman build --pull=never --no-cache --format=oci \
  --timestamp=1787899659 --tag "$tag" \
  --file "$repo_root/os/kernel/Containerfile.builder" "$repo_root/os/kernel"
skopeo copy "containers-storage:$tag" "oci-archive:$output"

archive_sha=$(sha256sum "$output" | awk '{print $1}')
manifest_digest="sha256:$(skopeo inspect --raw "oci-archive:$output" | sha256sum | awk '{print $1}')"
report="$repo_root/build/gate01/cache/toolchain-report.json"
podman run --rm --network=none "$tag" python3 -c '
import json, subprocess
commands = {
    "gcc": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
    "ld": subprocess.check_output(["ld", "--version"], text=True).splitlines()[0],
    "make": subprocess.check_output(["make", "--version"], text=True).splitlines()[0],
    "rpmbuild": subprocess.check_output(["rpmbuild", "--version"], text=True).strip(),
    "rpm": subprocess.check_output(["rpm", "--version"], text=True).strip(),
    "python3": subprocess.check_output(["python3", "--version"], text=True).strip(),
}
rpms = subprocess.check_output(
    ["rpm", "-qa", "--qf", "%{NEVRA}\\n"], text=True
).splitlines()
print(json.dumps({"commands": commands, "installed_rpms": sorted(set(rpms))}))
' > "$report"

python3 -m tools.gate01.toolchain write \
  --path "$repo_root/os/build/toolchain.lock.json" \
  --image-reference "$tag@$manifest_digest" \
  --manifest-digest "$manifest_digest" \
  --archive-sha256 "$archive_sha" \
  --report "$report"
python3 -m tools.gate01.toolchain verify "$repo_root/os/build/toolchain.lock.json"
```

The module CLI must implement the `write` and `verify` subcommands shown above, with `argparse`, and must reject an archive whose hash differs from the committed lock when later called with `verify --archive PATH`.

- [ ] **Step 6: Build the image, then prove it can be consumed without network access**

Run: `scripts/gate01/build-toolchain.sh`

Expected: the builder archive exists, `toolchain.lock.json` contains actual values rather than a moving tag, and validation exits `0`.

Run:

```bash
podman image rm localhost/openmythos/kernel-builder:fedora44
skopeo copy oci-archive:build/gate01/cache/kernel-builder.oci.tar \
  containers-storage:localhost/openmythos/kernel-builder:fedora44
podman run --rm --network=none \
  localhost/openmythos/kernel-builder:fedora44 gcc --version
```

Expected: the compiler version exactly matches `toolchain.lock.json` with no registry access.

- [ ] **Step 7: Run tests and add the toolchain make target**

Add:

```make
.PHONY: gate01-toolchain
gate01-toolchain:
	scripts/gate01/build-toolchain.sh
```

Run: `python3 -m unittest tests.gate01.test_toolchain -v`

Expected: two tests pass.

Run: `make gate01-unit`

Expected: all Gate 01 unit tests pass.

- [ ] **Step 8: Commit the pinned toolchain definition and generated lock**

```bash
git add Makefile os/kernel/Containerfile.builder os/build/toolchain.lock.json \
  tools/gate01/toolchain.py scripts/gate01/build-toolchain.sh \
  tests/gate01/test_toolchain.py
git commit -m "build: pin the Fedora 44 kernel toolchain"
```

### Task 4: Generate and audit the owned Linux configuration

**Files:**
- Create: `os/kernel/config/gate01-x86_64.fragment`
- Create: `os/kernel/config/fedora-44-x86_64.config`
- Create: `os/kernel/config/fedora-44-x86_64.config.sha256`
- Create: `os/kernel/config/requirements.json`
- Create: `os/kernel/config/6.18.48-x86_64.config`
- Create: `os/kernel/config/6.18.48-x86_64.config.sha256`
- Create: `tools/gate01/kernel_config.py`
- Create: `scripts/gate01/generate-config.sh`
- Create: `tests/gate01/test_kernel_config.py`
- Create: `tests/gate01/fixtures/config-valid`
- Create: `tests/gate01/fixtures/config-wrong-form`
- Modify: `Makefile`

**Interfaces:**
- Consumes: a stock x86_64 config extracted once from the pinned Fedora bootc image and then committed with its checksum, the verified Linux 6.18.48 archive, and the committed fragment.
- Produces: `parse_config(path: Path) -> dict[str, str]`, `load_requirements(path: Path) -> ConfigRequirements`, `audit_config(config: dict[str, str], requirements: ConfigRequirements) -> list[str]`, and one byte-stable final config whose checksum file is formatted as `<64 lowercase hex><two spaces>6.18.48-x86_64.config`.

- [ ] **Step 1: Write the failing config parser and audit tests**

```python
# tests/gate01/test_kernel_config.py
from pathlib import Path
import unittest

from tools.gate01.kernel_config import audit_config, load_requirements, parse_config


REPO = Path(__file__).resolve().parents[2]


class KernelConfigTests(unittest.TestCase):
    def test_final_config_meets_gate01_contract(self) -> None:
        config = parse_config(REPO / "os/kernel/config/6.18.48-x86_64.config")
        requirements = load_requirements(REPO / "os/kernel/config/requirements.json")
        self.assertEqual(audit_config(config, requirements), [])

    def test_not_set_is_parsed_as_n(self) -> None:
        config = parse_config(REPO / "tests/gate01/fixtures/config-valid")
        self.assertEqual(config["CONFIG_UNUSED_DRIVER"], "n")

    def test_wrong_builtin_module_form_is_rejected(self) -> None:
        config = parse_config(REPO / "tests/gate01/fixtures/config-wrong-form")
        requirements = load_requirements(REPO / "os/kernel/config/requirements.json")
        errors = audit_config(config, requirements)
        self.assertIn("CONFIG_VIRTIO_BLK: expected y, got m", errors)

    def test_committed_checksum_matches_config(self) -> None:
        config_path = REPO / "os/kernel/config/6.18.48-x86_64.config"
        checksum_path = config_path.with_suffix(config_path.suffix + ".sha256")
        expected, filename = checksum_path.read_text(encoding="ascii").split()
        self.assertEqual(filename, config_path.name)
        import hashlib
        self.assertEqual(expected, hashlib.sha256(config_path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and confirm the config API is absent**

Run: `python3 -m unittest tests.gate01.test_kernel_config -v`

Expected: `ERROR` because `tools.gate01.kernel_config` does not exist.

- [ ] **Step 3: Commit the deliberate Gate 01 configuration fragment**

Use these exact settings in `os/kernel/config/gate01-x86_64.fragment`:

```text
CONFIG_LOCALVERSION=""
# CONFIG_LOCALVERSION_AUTO is not set
CONFIG_DEFAULT_HOSTNAME="openmythos"
CONFIG_BUILD_SALT=""
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_COMPRESS is not set
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_ALL is not set
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_HASH="sha256"
CONFIG_MODULE_SIG_KEY=""
CONFIG_SYSTEM_TRUSTED_KEYS="certs/openmythos-module.pem"
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_PLATFORM_KEYRING=y
CONFIG_LOAD_UEFI_KEYS=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_MIXED=y
CONFIG_EFIVAR_FS=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TMPFS=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_PCI=y
CONFIG_PCI_MSI=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_SCSI_VIRTIO=y
CONFIG_VIRTIO_NET=m
CONFIG_NET_FAILOVER=m
CONFIG_FAILOVER=m
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_FW_LOADER=y
```

The Fedora config is the compatibility baseline; this fragment is the reviewed OpenMythos delta. Gate 01 adds no AMDGPU, Realtek Wi-Fi/Ethernet, NVMe reference-hardware policy, NVIDIA module, or hardware firmware requirement. Those become explicit config and artifact changes in Gate 03. `CONFIG_VIRTIO_NET=m` gives the module-signing proof at least one loadable QEMU driver while storage, EFI, ext4, and serial-console drivers remain built in.

- [ ] **Step 4: Define the exact requirements document**

`os/kernel/config/requirements.json` has exactly these top-level fields:

```json
{
  "schema_version": 1,
  "kernel_version": "6.18.48",
  "kernel_release": "6.18.48-1.openmythos.fc44.x86_64",
  "required": {
    "CONFIG_BLK_DEV_INITRD": "y",
    "CONFIG_BUILD_SALT": "\"\"",
    "CONFIG_CGROUPS": "y",
    "CONFIG_DEVTMPFS": "y",
    "CONFIG_DEVTMPFS_MOUNT": "y",
    "CONFIG_EFI": "y",
    "CONFIG_EFI_STUB": "y",
    "CONFIG_EFIVAR_FS": "y",
    "CONFIG_EXT4_FS": "y",
    "CONFIG_FW_LOADER": "y",
    "CONFIG_INTEGRITY": "y",
    "CONFIG_INTEGRITY_PLATFORM_KEYRING": "y",
    "CONFIG_LOAD_UEFI_KEYS": "y",
    "CONFIG_LOCALVERSION": "\"\"",
    "CONFIG_LOCALVERSION_AUTO": "n",
    "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY": "y",
    "CONFIG_MODULES": "y",
    "CONFIG_MODULE_COMPRESS": "n",
    "CONFIG_MODULE_SIG": "y",
    "CONFIG_MODULE_SIG_ALL": "n",
    "CONFIG_MODULE_SIG_FORCE": "y",
    "CONFIG_MODULE_SIG_HASH": "\"sha256\"",
    "CONFIG_MODULE_SIG_KEY": "\"\"",
    "CONFIG_MODULE_SIG_SHA256": "y",
    "CONFIG_SCSI_VIRTIO": "y",
    "CONFIG_SECONDARY_TRUSTED_KEYRING": "y",
    "CONFIG_SECURITYFS": "y",
    "CONFIG_SECURITY_LOCKDOWN_LSM": "y",
    "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY": "y",
    "CONFIG_SECURITY_SELINUX": "y",
    "CONFIG_SERIAL_8250": "y",
    "CONFIG_SERIAL_8250_CONSOLE": "y",
    "CONFIG_SYSTEM_TRUSTED_KEYS": "\"certs/openmythos-module.pem\"",
    "CONFIG_VIRTIO": "y",
    "CONFIG_VIRTIO_BLK": "y",
    "CONFIG_VIRTIO_CONSOLE": "y",
    "CONFIG_VIRTIO_NET": "m",
    "CONFIG_VIRTIO_PCI": "y"
  }
}
```

The JSON keys under `required` are sorted. `load_requirements` rejects any top-level field other than `schema_version`, `kernel_version`, `kernel_release`, and `required`; rejects non-string symbol values; requires every symbol to start with `CONFIG_`; and rejects duplicate or unsorted symbols by comparing the decoded order through `object_pairs_hook`.

- [ ] **Step 5: Implement deterministic parsing and auditing**

`parse_config` reads ASCII lines and accepts only `CONFIG_NAME=value` and `# CONFIG_NAME is not set`; it stores the latter as `n`, rejects a duplicate symbol, and ignores other comments and blank lines. `audit_config` returns one lexicographically sorted error per missing or mismatched required symbol in the exact forms `CONFIG_X: missing, expected y` and `CONFIG_X: expected y, got m`. The module CLI supports:

```text
python3 -m tools.gate01.kernel_config audit --config PATH --requirements PATH
python3 -m tools.gate01.kernel_config checksum --config PATH --output PATH
```

`audit` prints each error to stderr and exits `1`, otherwise exits `0`. `checksum` writes the checksum format defined above atomically through a sibling `.tmp` file and `Path.replace`.

- [ ] **Step 6: Implement final-config generation from locked inputs**

`scripts/gate01/generate-config.sh` accepts exactly one mode, `--refresh-baseline`, `--write`, or `--check`, refuses root, verifies the source and toolchain locks, verifies the cached toolchain archive, and imports that archive into a disposable rootless Podman store below `build/gate01/config-work/store`. In `--refresh-baseline` mode it additionally requires `build/gate01/cache/images/fedora-bootc.oci.tar`, reopens the archive through Skopeo, hashes its selected raw manifest, requires equality with `fedora_bootc.manifest_digest` in `os/build/inputs.lock.json`, and only then imports that local archive into the same disposable store. It performs no registry lookup or pull. Using the imported image ID—not a tag or registry reference—it runs with `--network=none`, extracts exactly one `/usr/lib/modules/*/config`, writes it atomically to `fedora-44-x86_64.config`, writes its checksum, and exits. This is the only mode that reads a config from the base image. The operator reviews and commits these two files before using either other mode. Inside the pinned builder, with `--network=none`, `--write` and `--check` must:

1. extract `linux-6.18.48.tar.xz` with `tar --no-same-owner --no-same-permissions`;
2. verify `fedora-44-x86_64.config.sha256` and use the committed baseline, never a newly extracted file;
3. run `scripts/kconfig/merge_config.sh -m <committed-stock-config> <fragment>` with `KCONFIG_CONFIG=<work>/merged.config`;
4. run `make O=<work>/out KCONFIG_CONFIG=<work>/merged.config olddefconfig`;
5. run `make O=<work>/out KCONFIG_CONFIG=<work>/merged.config listnewconfig` and require empty stdout;
6. run the Python audit against `<work>/merged.config`;
7. normalize the final file to a trailing newline without changing generated ordering.

In `--write` mode, copy the result atomically to `os/kernel/config/6.18.48-x86_64.config` and generate its checksum. In `--check` mode, byte-compare both regenerated files to the committed files and print `Gate 01 kernel config is current`; any difference exits `1` and prints the paths to compare. Always remove the disposable container store with a trap after verifying it lies below `build/gate01/config-work/`.

- [ ] **Step 7: Generate, review, and prove the final config**

Run: `scripts/gate01/generate-config.sh --refresh-baseline`

Expected: the pinned Fedora config and its checksum are written. Review the source image evidence, then stage these files before generating the OpenMythos config.

Run: `scripts/gate01/generate-config.sh --write`

Expected: the full config and checksum are written; the audit reports no errors.

Run: `scripts/gate01/generate-config.sh --check`

Expected: `Gate 01 kernel config is current`.

Run: `python3 -m unittest tests.gate01.test_kernel_config -v`

Expected: four tests pass.

Negative check: copy the final config beneath `build/gate01/`, change only `CONFIG_VIRTIO_BLK=y` to `CONFIG_VIRTIO_BLK=m`, and run the audit CLI. Expected: exit `1` and `CONFIG_VIRTIO_BLK: expected y, got m`.

- [ ] **Step 8: Commit the owned config and generator**

```bash
git add Makefile os/kernel/config tools/gate01/kernel_config.py \
  scripts/gate01/generate-config.sh tests/gate01/test_kernel_config.py \
  tests/gate01/fixtures/config-valid tests/gate01/fixtures/config-wrong-form
git commit -m "kernel: own and audit the Gate 01 config"
```

### Task 5: Create the external development module-signing identity

**Files:**
- Create: `os/kernel/README.md`
- Create: `scripts/gate01/create-development-key.sh`
- Create: `tools/gate01/module_key.py`
- Create: `tests/gate01/test_module_key.py`

**Interfaces:**
- Consumes: no secret from the repository.
- Produces: mode `0600` `build/gate01/secrets/module-signing.key`, public `module-signing.pem`, DER `module-signing.x509`, and canonical `module-key.json` containing the public certificate SHA-256, Subject Public Key Info SHA-256, certificate serial, subject, and validity dates. It never prints or copies private-key bytes.

- [ ] **Step 1: Write failing certificate-manifest tests**

`tests/gate01/test_module_key.py` creates a temporary RSA certificate with `openssl`, calls `python3 -m tools.gate01.module_key describe --certificate CERT --output JSON`, and asserts:

- the JSON has exactly `schema_version`, `certificate_sha256`, `spki_sha256`, `serial`, `subject`, `not_before`, and `not_after`;
- both hashes are 64 lowercase hexadecimal characters;
- a second `describe` invocation is byte-identical;
- a missing certificate exits nonzero;
- no JSON value contains `PRIVATE KEY`.

- [ ] **Step 2: Run the test and confirm the module-key API is absent**

Run: `python3 -m unittest tests.gate01.test_module_key -v`

Expected: `ERROR` because `tools.gate01.module_key` does not exist.

- [ ] **Step 3: Implement the public-only certificate descriptor**

`tools/gate01/module_key.py` uses `subprocess.run(argument_list, check=True, capture_output=True)` with argument arrays, never `shell=True`. It computes `certificate_sha256` over the PEM bytes and obtains the remaining values with these commands:

```text
openssl x509 -in CERT -pubkey -noout
openssl pkey -pubin -outform DER
openssl x509 -in CERT -noout -serial -subject -startdate -enddate
```

It hashes the DER public key for `spki_sha256`, strips only the known prefixes from certificate fields, serializes sorted/indented JSON with a final newline, creates the parent directory with mode `0700`, and writes atomically with mode `0600`.

The module also provides `scan --private-key KEY --root DIR`. It reads the PEM and converts it to private-key DER in memory, walks only regular files below the resolved root without following symlinks, and fails if either complete secret encoding or any PEM private-key marker occurs. It prints only a fixed redacted diagnostic, never matching bytes or derived fragments.

- [ ] **Step 4: Implement idempotent, local-only key creation**

`scripts/gate01/create-development-key.sh` accepts optional `--output-dir DIR` and otherwise uses `build/gate01/secrets`. It must resolve the path and reject anything outside `build/gate01/` unless the explicit path is beneath the process's `TMPDIR` (needed by its test). It uses `umask 077`, refuses partial key sets, and if all four output files already exist verifies them and exits without replacing them.

For a new set, run:

```bash
openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
  -subj '/CN=OpenMythos Gate 01 Development Module Key/O=OpenMythos Development/' \
  -keyout "$output_dir/module-signing.key.part" \
  -out "$output_dir/module-signing.pem.part"
openssl x509 -in "$output_dir/module-signing.pem.part" -outform DER \
  -out "$output_dir/module-signing.x509.part"
```

Verify the private/public pair by comparing the SHA-256 of `openssl pkey -pubout -outform DER` from each, move the three `.part` files atomically, chmod the private key `0600` and public files `0644`, then call the descriptor CLI to create `module-key.json`. A trap deletes only `.part` files in the validated output directory. The final line prints the public SPKI hash and the warning `development key only; Gate 02 replaces this identity`.

- [ ] **Step 5: Document the signing boundary**

`os/kernel/README.md` states that:

- Git contains the public certificate path in the config but no private key material;
- Gate 01 uses one locally generated identity for both clean builders so RSA module signatures are comparable;
- the private key is supplied byte-for-byte as sealed FD25 only to signing work and secret scanners, never mounted by pathname, and never enters an SRPM, RPM, OCI layer, QCOW2, log, or evidence bundle;
- the public certificate is included in the kernel trust set and evidence;
- Gate 01 does not PE-sign the kernel and does not claim Secure Boot acceptance;
- Gate 02 replaces this development identity with controlled kernel/module signing and MOK enrollment evidence.

- [ ] **Step 6: Prove idempotence and repository exclusion**

Run: `scripts/gate01/create-development-key.sh`

Run it a second time and compare `sha256sum build/gate01/secrets/*` before and after.

Expected: both lists match and no key is replaced.

Run: `git check-ignore -v build/gate01/secrets/module-signing.key`

Expected: the root `.gitignore` excludes it.

Run: `python3 -m unittest tests.gate01.test_module_key -v`

Expected: all certificate-manifest tests pass.

- [ ] **Step 7: Commit only code and documentation**

```bash
git add os/kernel/README.md tools/gate01/module_key.py \
  scripts/gate01/create-development-key.sh tests/gate01/test_module_key.py
if git diff --cached --name-only | grep -Eq '\.(key|pem|x509|p12)$'; then exit 1; fi
git commit -m "kernel: add development module-signing boundary"
```

### Task 6: Package `linux-openmythos` as focused Fedora-compatible RPMs

**Files:**
- Create: `os/kernel/packaging/kernel-openmythos.spec`
- Create: `tools/gate01/proof_io.py`
- Create: `tools/gate01/container_runtime.py`
- Create: `tools/gate01/kernel_bootstrap.py`
- Create: `tools/gate01/kernel_build.py`
- Create: `tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json`
- Create: `tools/gate01/oci_rootfs.py`
- Create: `tools/gate01/rpm_artifacts.py`
- Create: `scripts/gate01/build-kernel.sh`
- Create: `tests/gate01/test_kernel_build.py`
- Create: `tests/gate01/test_oci_rootfs.py`
- Create: `tests/gate01/test_rpm_artifacts.py`
- Create: `tests/gate01/fixtures/rpm-manifest-valid.json`
- Create: `tests/gate01/fixtures/rpm-manifest-duplicate-nevra.json`
- Modify: `tools/gate01/module_key.py`
- Modify: `tests/gate01/test_module_key.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: the exact verified source archive and source lock, final config/checksum/requirements, packaging spec, public certificate/manifest, mode-`0600` private key, locked toolchain OCI archive/manifest, and the complete repository-local verifier closure. The supervisor opens every input with `O_NOFOLLOW` before validation and thereafter treats the held descriptor, not its pathname, as authoritative.
- Produces: one genuine source RPM plus `kernel-openmythos`, `kernel-openmythos-core`, and `kernel-openmythos-modules` binary RPMs for release `6.18.48-1.openmythos.fc44.x86_64`; descriptor-originated `rpm-artifacts.json` and `installed-files.json`; public build/rootfs/container/leakage evidence; and detached receipt-last commit markers.
- Preserves: each accepted builder tree at `build/gate01/<id>/kernel`, with RPMs at `rpmbuild/RPMS/x86_64/` and `rpmbuild/SRPMS/`. Its detached sibling receipt is `build/gate01/<id>/kernel.receipt.json`.
- Provides: the closed launcher commands `build BUILDER`, `compare`, `meta-requirements BUILDER`, and `lifecycle-check` (builder shorthand remains supported). All production operations require held FD60 bootstrap execution, sealed ZIP FD61 and authority FD62 before creating output; direct file/module entry is unsupported. Proof pairs remain `build/gate01/compare/kernel-rpms.json` plus its receipt and `meta-requirements.json` plus its receipt.

**Trust and threat boundary:**

- The trusted computing base is a clean initial launcher, the host kernel and filesystem, the audited absolute host tools plus Podman/crun, and exclusive custody of the build UID/process set, descriptors, private scratch, and private stores by non-malicious Gate 01 processes. The proof detects in-scope pathname replacement, in-place mutation, mutate-then-restore, unexpected writers, container-root mutation, and output replacement during the supervised run and again at every consumer boundary.
- A hostile pre-entry loader or shell (`LD_PRELOAD`, `BASH_ENV`, exported functions), ptrace or `/proc/<pid>/fd` theft, an arbitrary active same-UID compromise, a compromised host kernel/runtime/tool binary, and coordinated replacement after a completed consumer revalidation are outside this userspace proof. `bash -p`, isolated Python, and a discarded ambient environment harden the supported launch; they do not retroactively make a hostile pre-entry process trustworthy.
- Only the signing-capable build exec receives the sealed private-key descriptor. The supervisor may use its held key descriptor for the final leakage scan, but PID 1, live verifier, compiler probe, rootfs auditors, artifact inspector, comparison, and meta-requirements proof receive no key descriptor, pathname, hash, or key-derived value.
- No OCI hook participates in the proof: the generated config must omit the `hooks` key entirely; any present value, including null, fails. There is an explicit residual TCB interval after start and before live attestation, during which the locked `/usr/bin/sleep`, its dynamic loader, and its mapped libraries execute. Those bytes have already been proved against the sealed OCI model, and no key, build input, artifact, or evidence descriptor is exposed during that interval; correct host-kernel/runtime enforcement remains part of the stated TCB.

- [ ] **Step 1: Write failing supervisor, rootfs, and descriptor-inspection tests**

`tests/gate01/test_kernel_build.py` first exercises the proof boundaries without running a kernel build. It requires:

- simultaneous `O_NOFOLLOW` binding of every input, two descriptor hash passes, parent/path/listing anchors, and rejection of inode replacement, in-place mutation, and mutate-then-restore;
- a deterministic, fully sealed verifier capsule; a private-key copy that is byte-compared into a sealed memfd without invoking SHA-256; fixed descriptor roles `20` (verifier), `21` (certificate), `22` (source), `23` (config), `24` (spec), `25` (key), `26` (build result), and `30`-`33` (SRPM/core/modules/meta);
- a clean allowlisted subprocess environment and exact Podman create/init/config contract, including deterministic `HOME=/tmp` and `HOSTNAME=openmythos-builder`, exact namespaces/mounts, absence of the `hooks` key, and no implicit repository/input mount, proxy variable, generated hosts file, network, or image volume;
- the only legal work path `CREATED_INIT_AUDITED -> STARTED_UNATTESTED -> LIVE_ATTESTED -> AUTHORIZED_ROOTFS_AUDITED -> WORK_AUTHORIZED`, with rejection of config replacement, an extra live process/thread/FD/mount/route/listener, the wrong PID 1 executable/mapped file/root/scratch identity or flag, a nonempty scratch directory, or any attempt to execute work before authorization;
- one descriptor-derived `/run/.containerenv` runtime projection and one prebaseline-only VFS normalization; tests prove no normalizer runs after start, mutate-then-restore before start or during work is detected by raw anchors/audits, post-stop audit failure prevents a receipt, and cleanup attempts every container/store/scratch removal and converts cleanup failure into overall failure;
- disk-backed anonymous `O_TMPFILE` slots, exact `1+3` RPM acquisition, rejection of extra/alternate-architecture/path-replaced outputs, positive proof that all artifact writers are reaped, closure of every writable descriptor, read-only reopen/lease, and no stable artifact pathname before final publication;
- an exact accepted-tree allowlist, full-tree secret scan, a build report that remains `"acceptance": "pending-detached-receipt"`, `renameat2(RENAME_NOREPLACE)` publication, rollback on receipt failure, and receipt/tree revalidation by consumers.

`tests/gate01/test_oci_rootfs.py` builds small OCI archives in memory and requires `canonicalize_oci_archive` and `audit_rootfs` to reject malformed descriptors/digests, duplicate JSON keys and archive paths, unsafe tar paths, unsupported nodes/xattrs, path replacement, mutation during hashing, and incomplete scans. Positive fixtures cover ordered layer replacement, explicit and implicit directories, whiteouts, opaque whiteouts, symlinks, regular and symlink hardlinks including forward/cross-layer targets, xattrs, ownership projection through the rootless UID/GID map, and exact pre/post equality.

`tests/gate01/test_rpm_artifacts.py` retains the manifest fixtures and requires `load_rpm_manifest`/`validate_rpm_manifest` to enforce the existing exact NEVRA, architecture, release, ownership, mode, payload, and private-marker contract. New descriptor regressions additionally prove that RPM header query, raw hashing, `rpm2cpio`, strict newc parsing, extraction, file hashing, `modinfo`, and CMS verification consume the same immutable descriptor; they reject path rebinding, same-path replacement, post-listing mutation, malformed/trailing CPIO data, traversal, special files, hardlinks, symlink pivots, and any source RPM whose exact four-file payload differs from the declared spec/source/config/certificate hashes.

`tests/gate01/test_module_key.py` adds fixed-descriptor leakage-scan cases: replacing the key pathname cannot change the scanned secret, replacing or mutating the output tree during the scan fails closed, and no private bytes or derived digest appear in output.

The original manifest assertions remain mandatory:

- accepts exactly one source NEVRA and these three sorted binary package names;
- rejects duplicate NEVRAs;
- rejects any architecture other than `x86_64` for binaries and `src` for the source;
- rejects a kernel release other than `6.18.48-1.openmythos.fc44.x86_64`;
- rejects a file path outside `/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64/` in the core or modules payload;
- rejects a private-key suffix or the byte marker `PRIVATE KEY` in an extracted regular file;
- accepts raw binary RPM hashes as recorded fields without using them to decide installed-content equality.

- [ ] **Step 2: Run the focused tests and confirm the new proof APIs are absent**

Run:

```bash
python3 -B -m unittest \
  tests.gate01.test_kernel_build \
  tests.gate01.test_oci_rootfs \
  tests.gate01.test_rpm_artifacts \
  tests.gate01.test_module_key -v
```

Expected: `ERROR` because `tools.gate01.proof_io`, `tools.gate01.container_runtime`, `tools.gate01.kernel_build`, and `tools.gate01.oci_rootfs` do not exist, followed by focused RED failures for the descriptor-only RPM and module-key interfaces before those are implemented.

- [ ] **Step 3: Add the focused RPM spec**

`os/kernel/packaging/kernel-openmythos.spec` uses:

```spec
%global kernel_release 6.18.48-1.openmythos.fc44.x86_64
%global _buildhost openmythos-builder.invalid
%global clamp_mtime_to_source_date_epoch 1
%global use_source_date_epoch_as_buildtime 1
%global _source_payload w19.zstdio
%global _binary_payload w19.zstdio
%global debug_package %{nil}

Name:           kernel-openmythos
Version:        6.18.48
Release:        1.openmythos%{?dist}
Summary:        OpenMythos-owned Linux kernel
License:        GPL-2.0-only
URL:            https://www.kernel.org/
Source0:        linux-%{version}.tar.xz
Source1:        6.18.48-x86_64.config
Source2:        module-signing.pem
BuildRequires:  bc, binutils, bison, dwarves, elfutils-libelf-devel, flex, gcc, make
BuildRequires:  kmod, openssl, openssl-devel, perl-interpreter, python3, rsync
Requires:       kernel-openmythos-core-uname-r = %{kernel_release}
Requires:       kernel-openmythos-modules-uname-r = %{kernel_release}
Provides:       installonlypkg(kernel)
Provides:       kernel = %{version}-%{release}

%description
The install-only OpenMythos kernel package for the Stone image.

%package core
Summary: OpenMythos kernel image and built-in metadata
Provides: kernel-openmythos-core-uname-r = %{kernel_release}
Provides: kernel-core-uname-r = %{kernel_release}

%description core
The bootable OpenMythos kernel and built-in module metadata.

%package modules
Summary: Signed loadable modules for the OpenMythos kernel
Provides: kernel-openmythos-modules-uname-r = %{kernel_release}
Provides: kernel-modules-uname-r = %{kernel_release}
Requires: kernel-openmythos-core-uname-r = %{kernel_release}

%description modules
Loadable modules signed by the externally supplied Gate 01 identity.
```

The remaining spec sections must implement this exact contract:

1. `%prep` expands Source0, copies Source1 to `.config`, and copies Source2 to `certs/openmythos-module.pem`. It fails unless `$OPENMYTHOS_MODULE_SIGNING_KEY` names a readable regular file, but it never copies or symlinks that private key into the source tree.
2. `%build` verifies the config SHA-256 against `$OPENMYTHOS_CONFIG_SHA256`; runs `make olddefconfig`; requires the post-resolution config hash to remain unchanged; and builds `all` with `LOCALVERSION=-1.openmythos.fc44.x86_64`, `KBUILD_BUILD_VERSION=1`, `KBUILD_BUILD_USER=openmythos`, `KBUILD_BUILD_HOST=openmythos-builder`, `KBUILD_BUILD_TIMESTAMP=@1787899659`, and both `KCFLAGS` and `KAFLAGS` set to `-fdebug-prefix-map=%{_builddir}=. -fmacro-prefix-map=%{_builddir}=.`.
3. `%install` runs `modules_install` into `%{buildroot}/usr`, then signs each uncompressed `.ko` in bytewise path order with `scripts/sign-file sha256 "$OPENMYTHOS_MODULE_SIGNING_KEY" certs/openmythos-module.pem`. `CONFIG_MODULE_SIG_ALL=n` prevents the compilation phase from signing, so signing is an explicit deterministic packaging transform. The public certificate path is the in-tree file staged during `%prep`; no ambiguous `%{SOURCE2}` expansion is used during signing. It removes `build` and `source` symlinks, copies `arch/x86/boot/bzImage` to `/usr/lib/modules/%{kernel_release}/vmlinuz`, copies `.config` to `config`, copies `System.map`, and runs `depmod -b %{buildroot}/usr %{kernel_release}`.
4. An explicit empty main `%files` section forces RPM 6 to emit the fileless meta package. `%files core` owns exactly `vmlinuz`, `config`, `System.map`, `modules.builtin`, `modules.builtin.modinfo`, `modules.builtin.alias.bin`, and `modules.builtin.bin`. `%files modules` owns exactly `kernel/`, `modules.alias*`, `modules.dep*`, `modules.devname`, `modules.order`, `modules.softdep`, `modules.symbols*`, and `modules.weakdep`. No package owns any other path.
5. `%posttrans core` calls `kernel-install add` only when `OPENMYTHOS_IMAGE_BUILD` is not `1`; `%preun core` calls `kernel-install remove` only on final erase and only when `OPENMYTHOS_IMAGE_BUILD` is not `1`. Both use the exact `%{kernel_release}` and adjacent `vmlinuz` path. The bootc payload sets `OPENMYTHOS_IMAGE_BUILD=1`, so it never creates payload-owned `/boot` content.
6. `%changelog` begins with a fixed UTC entry dated from `SOURCE_DATE_EPOCH`; no wall-clock value is generated during a build.

- [ ] **Step 4: Implement the independent OCI semantic model and full VFS audit**

`tools/gate01/oci_rootfs.py` is independent of Podman's extraction and exposes:

```python
canonicalize_oci_archive(
    archive_fd: int,
    *,
    expected_archive_sha256: str,
    expected_manifest_digest: str,
) -> OciRootfsManifest
audit_rootfs(
    root: os.PathLike[str] | str,
    *,
    projection: OwnershipProjection | None = None,
) -> RootfsAudit
assert_semantic_equal(
    expected: OciRootfsManifest | RootfsAudit,
    actual: OciRootfsManifest | RootfsAudit,
) -> None
assert_audits_equal(before: RootfsAudit, after: RootfsAudit) -> None
project_runtime_bind_file(
    manifest: OciRootfsManifest,
    source_fd: int,
    *,
    target: str,
    projection: OwnershipProjection | None = None,
) -> OciRootfsManifest
normalize_vfs_materialization(
    root: os.PathLike[str] | str,
    expected: OciRootfsManifest,
    *,
    projection: OwnershipProjection | None = None,
    runtime_bind_targets: Iterable[str] = (),
) -> tuple[RootfsAudit, Mapping[str, Any]]
```

The canonicalizer hashes the held OCI archive itself, validates the exact index/manifest/config/blob descriptor digests and sizes, selects only the locked `linux/amd64` manifest, and merges every ordered layer in memory. It implements directory replacement, whiteouts, opaque whiteouts, regular files, directories, symlinks, and logical hardlink groups without trusting Podman's result. It rejects duplicate or unsafe archive/tar names, unsupported node types, malformed PAX/xattrs, unresolved hardlinks, and inconsistent OCI history/rootfs metadata.

The mounted-root auditor securely opens the root without following a symlink, walks every unique actual path exactly once (including `/`), holds directory and file descriptors while reading, hashes every regular file, reads symlink targets and supported xattrs, records modes/types/sizes/ownership/hardlink groups, projects rootless host IDs through the actual Podman UID/GID map, and checks path/stat anchors after the complete pass. It must not derive the expected answer from `podman export`, an overlay diff, or a second pathname copy. For the currently locked builder archive the independent merge yields exactly `138,619` non-root paths plus a separately committed `/` entry and root anchor. Counts are supporting evidence; acceptance is equality of the complete mappings.

After `podman init`, open and hold the exact config-created source of `/run/.containerenv`, derive its complete runtime semantic record from that descriptor, and extend the locked OCI model by exactly that one path. The mounted materialization must therefore contain exactly `138,620` non-root paths, the separate root entry/anchor, and an explicit runtime-projection record for `/run/.containerenv`; no target bytes or mutable source pathname may supply the expected value.

Podman's VFS import has two documented representation losses: it does not restore directory mtimes after creating descendants, and it may materialize tar hardlinks-to-symlinks as separate symlink inodes. Exactly once, before accepting the stopped-container baseline, `normalize_vfs_materialization` first proves that the full path set is exact and that every difference is limited to those two cases or the projected `/run/.containerenv` mode/mtime. It repairs only those descriptor-anchored fields, skips no-op chmod/utime calls, rechecks every untouched raw entry, and performs a complete audit equal to the extended sealed model. No normalizer is callable after PID 1 starts. For both the signing builder and the distinct secret-free inspector, the complete `authorized` audit immediately before work and the complete post-stop audit must equal that accepted baseline in semantic and raw commitments. Any extra, missing, retyped, relinked, metadata-changed, content-changed, or mutate-then-restore path fails the run.

The normalization evidence has exact `schema_version: 3` and `watch_profile: "linux-inotify-fanotify-vfs-normalization-v3"`. Its other six fields are `initial_raw_ledger`, `repair_groups`, `directory_mtimes`, `hardlinks`, `runtime_bind_targets`, and `raw_operations`. The complete canonical initial raw ledger, including `/`, is encoded with `zlib-base64-canonical-raw-ledger-v1`: level-9 zlib plus canonical base64, exact entry count, uncompressed size, and SHA-256. Bounds are 250,000 entries, 256 MiB uncompressed, and 16 MiB encoded. Decode requires bounded complete decompression with EOF and no trailing/multistream data, exact hash/size, canonical recompression equality, duplicate-free JSON, and parse/recanonicalize equality. Production still requires exactly 138,621 total entries (138,620 non-root); codec bounds do not relax the locked image count.

`repair_groups` declares complete sorted membership with the canonical minimum-path representative. The consumer reconstructs every initial row once and replays exact, unique, ordered aggregate transitions: one `symlink_hardlink` phase covering all planned link/exchange/unlink repairs, then one `runtime_bind_target` transition per changed target (possibly chmod plus utime), then deepest-first directory-mtime transitions. `raw_operations` records these authorized aggregate phase transitions, not one row per syscall. Every before-row must equal the currently reconstructed row; representative/member/parent coverage, operation-specific fields, and displaced-inode remaining aliases/link counts are mandatory. Partially linked groups are valid only with exact initial equivalence classes and no outside or cross-group aliases. The final reconstructed complete-ledger SHA-256 and full root anchor must equal the accepted audit's `raw_sha256` and anchor; a self-consistent affected-row chain alone is not authority.

Live syscall exactness is separately enforced by the frozen v3 event machines. Inotify retains held parent/inode identities and exact initial child listings for all repaired group members, including source parents, plus each runtime/mtime target and its necessary parent/root external-parent anchor. Each random repair name has exact create -> exchange -> unlink events, exact nonzero distinct rename cookies, inode MOVE_SELF events, and explicitly bracketed zero-link watch retirement. Repair-phase parent-self ATTRIB is forbidden. Directory utime and runtime chmod/utime have separate exact dual parent/inode ATTRIB profiles; unrelated names, masks, multiplicities, overflow, watch loss, malformed data, or ambiguous/coalesced sequences fail closed. Watches are installed before ledger revalidation and an empty baseline drain, and remain authoritative through each exact operation/aggregate ledger check and terminal raw/audit drain. Authorized metadata transitions advance any surviving long-lived repair-parent authority only after their exact local proof.

Inotify alone cannot distinguish external hardlink-count churn coalescing with an authorized inode ATTRIB. Every mutating syscall therefore also uses one operation-local fanotify FID group per affected inode (at most two for exchange), with exact prebound opaque filesystem ID and file handle, no child-event marks, strict bounded metadata/FID parsing, and one exact event per group. Unsupported FID/mark/filesystem/kernel profiles and all queue/setup/read errors fail closed. A fresh minimal child performs exactly one prepared raw mutating syscall; separate actors cannot merge into that child's fanotify record. PID values never authorize events. Setup requires exactly one native thread and ignored SIGPIPE. A CLOEXEC pipe blocks the child until the parent has acquired a pidfd, closed its own reader, and successfully written the exact one-byte token; only that live-reader proof authenticates the pidfd. Pre-authentication failure closes the writer and reaps without signalling. Post-authentication termination uses only that pidfd, never a numeric PID; all helper descriptors and child status have explicit cleanup ownership. The minimal helper and exclusive non-malicious UID/process execution boundary remain trusted; notification does not establish actor identity.

Immediate child listings are indexed once. Directory/runtime metadata watches are operation-local (at most three simultaneous inotify watches for a directory operation), while necessary repair watches persist through terminal verification. Work scales with ledger entries and authorized operations, not the product of directory count and ledger size. The committed 100/300/4,097-directory positive regression checks an explicit linear ledger-operation bound and watch peak; kernel resource exhaustion is fatal, never a reason to omit proof.

- [ ] **Step 5: Implement fixed-descriptor RPM, CPIO, module, and leakage inspection**

`tools/gate01/rpm_artifacts.py inspect-fixed-fds` receives only the sealed verifier at `20`, sealed public certificate at `21`, read-only artifact descriptors `30`-`33`, and anonymous result descriptors `40` (`rpm-artifacts.json`), `41` (`installed-files.json`), and `42` (structured inspection result). The inspector is their sole writer; after it exits, the supervisor closes the writers and reopens the evidence inodes read-only. Production inspection never reopens an RPM by pathname. Each RPM descriptor is used for its raw hash, `rpm -qp` header and file queries, `rpm2cpio`, strict `070701` newc parsing, and extraction; the validated CPIO stream is held in an anonymous descriptor and the extracted regular-file hashes must equal the bytes parsed from that same stream.

The source RPM must be genuine and its payload must be exactly these four root-owned mode-`0644` regular files, with no directories, links, or extras:

```text
kernel-openmythos.spec
linux-6.18.48.tar.xz
6.18.48-x86_64.config
module-signing.pem
```

Their hashes must equal the held spec/source/config/certificate inputs. The binary packages retain the exact meta/core/modules topology, root ownership, safe modes, nonempty required metadata, exact `modules.order`, and no special files, compressed modules, hardlinks, or symlink pivots. Directories are omitted only from normalized installed-file JSON; their exact header/CPIO/extracted topology is still verified.

For every uncompressed `.ko`, one securely opened extracted-file descriptor supplies the file hash, private-marker scan, Linux signature trailer, DER CMS, and `modinfo` queries. Require an appended PKCS#7/CMS signature that cryptographically verifies against descriptor `21` with embedded/untrusted certificates disabled, declares SHA-256 as its CMS digest algorithm, reports signer `OpenMythos Gate 01 Development Module Key`, reports `sig_id` `PKCS#7`, and has a vermagic first token exactly equal to the kernel release. A mutation or pathname replacement between any two operations fails.

`tools/gate01/module_key.py` exposes `scan_descriptors(private_key_descriptor: int, root_descriptor: int) -> int`; its `scan-fixed-fds` CLI receives the sealed key at `25` and accepted-candidate root at `50`. It derives the complete secret encodings in memory, walks held descriptors without following links, performs a final tree/path/version sweep, emits only a fixed redacted diagnostic, and never emits or computes a secret hash. The path-based Task 5 CLI may remain for compatibility, but Task 6 production code uses only the descriptor interface.

Keep `validate` and pure-JSON `compare` behavior: comparison fails on the genuine SRPM hash, NEVRA set, normalized installed-file records, or module signatures, while raw binary RPM byte hashes remain recorded advisory differences. The supervisor, not a path-based inspector, owns production receipt publication.

- [ ] **Step 6: Implement the descriptor-custody build supervisor**

Keep the source closure split by authority. `tools/gate01/proof_io.py` owns held-input identity, fixed-descriptor projection, memfd sealing, `O_TMPFILE` slots, complete leakage scans, tree commitments, and detached receipt publication/revalidation. `tools/gate01/container_runtime.py` owns the controlled environment, Podman store/container lifecycle, exact generated-config validation, descriptor-derived runtime projection, rootfs workers, and live process/mount attestation. `tools/gate01/kernel_build.py` owns evidence schemas, build/inspection orchestration, comparison/meta proofs, and the CLI. `tools/gate01/oci_rootfs.py` remains independent of Podman. Freeze the pre-split public behavior and source hashes, move code mechanically behind these boundaries, and rerun the same focused/no-build checks before accepting the split.

Resource ownership is normative across constructors, container/list registration, context/callback adoption, writes, and rollback. Every acquisition has an immediate local owner before any fallible inspection or registration; transfer occurs only after successful adoption. Context and stack callers pass non-owning factory arguments: acquisition occurs inside the established local guard, never as an already-open argument awaiting a later context/adoption call. Terminal cleanup drains existing ownership incrementally, detaching each current numeric/object field before its single kernel-close attempt; it must not allocate an action list, tuple, closure, or exception snapshot before attempting release. Any genuinely retryable owner plan must remain intact on formation failure, but automatic terminal unwinds cannot rely on an unavailable caller retry. Exception snapshots use the nonallocating `sys.exception()` scalar (supported by the required Python 3.12+), or explicit exception binding, rather than allocating `sys.exc_info()` tuples. Attempt every independently authorized cleanup even if earlier actions fail. Preserve an existing primary exception object unchanged and attach best-effort fixed nonsensitive category notes; with no primary, aggregate cleanup errors and fail. These rules apply before the durable receipt boundary; only the explicitly post-durable local close/unlock/output path may issue a fixed warning while retaining success. Public output readback must bind actual stored bytes to the caller's original supplied bytes before returning an identity or publishing; this never authorizes a private-key digest.

Store initialization holds the exact parent/listing and a bounded creation watch before mkdir, immediately opens the created directory into a local numeric guard, and retains original custody before later validation/registration. A first observation/open failure may remove only the uniquely proved just-created empty directory using exact CREATE/DELETE|ISDIR provenance and restored parent listing/link count. Move/replacement/extra/ambiguous events forbid deletion and produce a fixed cleanup diagnostic rather than adopting a replacement. A failed current initialization never falls back to stale-store pathname acquisition. Material cleanup retains its original held custody through every authorized attempt, continues eligible siblings after command/removal failures, then independently releases all scope. Released scope is terminal and cannot be retried to reacquire a recreated pathname. Container creation/start attempts conservatively retain exact invocation ownership before the command can take effect, including a policy-finalizer failure after subprocess completion; output parsing or later validation cannot discharge that ownership. Stop/wait ambiguity retains the exact-authorized fallback stop/force-removal path. Store cleanup separately captures its subprocess outcome in a caller-owned completion cell before policy finalization: only proven returncode-zero completion enables the existing bounded safe recreated-bookkeeping cleanup. Nonzero or unproven completion never authorizes adopting replacement children, and the original policy/command exception remains fatal after all independently authorized cleanup.

`scripts/gate01/build-kernel.sh build BUILDER_ID` accepts only `builder-a`, `builder-b`, or `canonical`, refuses root, resolves every work path below `build/gate01/`, and performs this fail-closed lifecycle:

1. Install cleanup before creating state. Open and hold the exact helper closure (`tools/__init__.py`, `tools/gate01/__init__.py`, `inputs.py`, `kernel_bootstrap.py`, `kernel_config.py`, `toolchain.py`, `module_key.py`, `proof_io.py`, `container_runtime.py`, `rpm_artifacts.py`, `oci_rootfs.py`, and `kernel_build.py`), launcher, spec, source/toolchain locks, source/toolchain archives, config/checksum/requirements, public certificate/manifest, and private key. Require exact regular-file identity/mode/link count as applicable, two stable reads, exact parent/listing anchors, and all declared hashes. Reuse the exact executed sealed bootstrap ZIP as the verifier, copy build public inputs into sealed memfds, and byte-compare the private key into a fully sealed memfd without hashing it. Discard the ambient environment and use absolute audited executable paths.
2. Independently canonicalize the exact held toolchain archive, create fresh builder-specific VFS graphroot/runroot/tmp/scratch directories outside the future accepted tree, and load the archive through its held descriptor. Verify the imported image's manifest and config identities against the lock.
3. `podman create` an offline, read-only-root container with `--network=none`, `--no-hostname`, `--no-hosts`, `--image-volume=ignore`, `--http-proxy=false`, `--unsetenv-all`, a hardened `/tmp` tmpfs, deterministic `HOME=/tmp` and `HOSTNAME=openmythos-builder`, and exactly one private bind at `/tmp/work`. The scratch bind is `rw,nosuid,nodev,rbind` and may execute because Kbuild runs newly built helpers; no repository, source, key, output, store, or default host path is mounted. Run `podman init`, then bind the exact generated OCI config and its exact runtime-created `.containerenv` source with `O_NOFOLLOW`. Before the initial child bind/baseline, install one coalesced inotify watch per held parent inode. At every transition rehash/re-stat the held targets, revalidate each target name and parent path identity, require all stable parent metadata plus the exact baseline listing, and reject target-basename modify/close-write/attribute/create/delete/move events, watch loss/self-move/unmount, queue overflow, or malformed events. Podman's transient exec bookkeeping may advance only parent mtime/ctime and may emit only events for unrelated sibling names that are absent again at the final exact-listing boundary. Require the config's root path, ordered environment, capabilities, namespaces, process command, ten exact mounts and sources, readonly/masked paths, and absence of the `hooks` key; reject every extra field that changes the security contract.
4. While PID 1 has never run, mount the stopped container. Extend the sealed OCI mapping from the held `.containerenv` descriptor by exactly `/run/.containerenv`, require `138,619` locked non-root paths plus that one runtime projection and the separate root entry/anchor, and perform the one permitted prebaseline VFS normalization described in Step 4. Record its complete bounded delta, then require a full exact semantic/raw audit and transition to `CREATED_INIT_AUDITED`. No hook is installed or invoked, and no later phase may normalize the rootfs.
5. Start only inert `/usr/bin/sleep infinity`, entering `STARTED_UNATTESTED` without exposing a key, public build input, artifact, or evidence descriptor. Host-side live attestation must observe exactly one PID/cgroup with the expected executable and audited mapped loader/libraries, command line, ordered environment, UID/GID, zero capabilities, `NoNewPrivs`, seccomp, cwd, namespaces, thread/child/process set, stdio-only descriptor set, exact mount topology and bind-source identities, loopback-only network with no listener/route, and an empty anchored scratch directory. A nonce-bound, secret-free verifier exec receives only sealed descriptor `20` and independently proves the readonly root and exact scratch/mount contract from inside; after it exits, require the exact one-process set to return, repeat the host record byte-for-byte, and revalidate both watched runtime inputs under the target-event policy above. Only then enter `LIVE_ATTESTED`. Perform a complete semantic/raw rootfs audit equal to the prebaseline and a final watched-config/process check immediately before the explicit `WORK_AUTHORIZED` transition. Run the keyless compiler probe only after authorization.
6. Create four anonymous, disk-backed `O_TMPFILE` artifact slots on a private filesystem and pass fixed descriptors `20`-`26` and `30`-`33` only to the build exec. Stage source/config/certificate/spec from `22`/`23`/`21`/`24` into the private rpmbuild tree as mode `0644` with mtime `1787899659`; invoke absolute `/usr/bin/rpmbuild` with key `/proc/self/fd/25`, the fixed config hash, fixed locale/timezone/build user/build host/timestamp/prefix maps, and `-j4`. Mark the artifact slots close-on-exec so rpmbuild and its children never inherit them.
7. After rpmbuild and every descendant exit, acquire exactly one SRPM and the three exact binary RPM names directly into slots `30`-`33`; reject all extra entries before and after copying. Prove no live process holds a writable artifact descriptor, close every writer, reopen each anonymous inode read-only, acquire the supported read lease, and recheck size/content/inode/link-count identity. The artifacts remain anonymous and supervisor-held.
8. Immediately before stop, require a clean watched-input boundary and the prevalidated exact owner/mode/type/inode metadata for the `attach` socket and `ctl`/`winsz` FIFOs. During stop, require this exact per-name partial order: `attach` emits one zero-cookie `IN_DELETE`; `ctl` and `winsz` each emit one zero-cookie `IN_CLOSE_WRITE` followed later by one zero-cookie `IN_DELETE`. Cross-name interleaving is unconstrained, but the watched descriptor, basename bytes, masks, cookies, multiplicity, and per-name order are exact; reject every duplicate, extra mask/event/name, target event, queue overflow, or watch loss. Immediately afterward require the config-parent listing to equal its baseline minus exactly those endpoints, require every surviving entry and both bound targets to retain their complete pre-stop metadata/content/path identities, record both the event multiset and observed sequence together with the pre/post listings, endpoint metadata, and exact allowed delta, and adopt the reduced listing as the post-stop baseline. Then run the complete post-rootfs audit without normalization. Require its semantic mapping to equal the extended independent OCI model and require its semantic/raw record to equal the prebaseline and authorized audit records. Then remove the container, scratch, and every signing-capable store/runtime path. Any post-audit or cleanup failure invalidates the run and permits no receipt.
9. Import the same held OCI archive into a different fresh secret-free inspector store and container. Repeat the complete no-hook sequence `CREATED_INIT_AUDITED -> STARTED_UNATTESTED -> LIVE_ATTESTED -> AUTHORIZED_ROOTFS_AUDITED -> WORK_AUTHORIZED`, including its own descriptor-bound `.containerenv` projection, one-time prebaseline normalization evidence, host/inside live attestation, authorized rootfs recheck, post-stop audit, and cleanup. Only its work exec receives sealed verifier `20`, certificate `21`, read-only artifacts `30`-`33`, and anonymous evidence/result outputs `40`/`41`/`42` for `rpm_artifacts.py inspect-fixed-fds`; the inspector lifecycle receives neither key `25` nor a key pathname, environment value, hash, or key-derived value.
10. Revalidate all held public inputs and anonymous artifacts. Copy only the four read-only RPM descriptors and two canonical evidence descriptors into a hidden candidate output; create canonical public logs/evidence with the build report still pending; then run the full descriptor-only private-key leakage scan over that exact candidate.
11. Require the candidate to contain exactly the following regular files and their implied directories, with no symlink, hardlink, special file, empty undeclared directory, extraction tree, or scratch residue:

```text
rpmbuild/RPMS/x86_64/kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm
rpmbuild/RPMS/x86_64/kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm
rpmbuild/RPMS/x86_64/kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm
rpmbuild/SRPMS/kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm
rpm-artifacts.json
installed-files.json
build.log
compiler-version.txt
build-report.json
source-capsule.json
rootfs-audit.json
container-contract.json
leakage-scan.json
```

`rootfs-audit.json` records, for both builder and inspector, the locked `138,619` non-root count, separate root entry/anchor, one-path runtime projection, materialized count, and prebaseline/authorized/post semantic and raw commitments plus equality verdicts. `container-contract.json` records the exact config/fixture hashes, `hooks_present=false`, actual sealed containers/storage policy hashes, store/scratch/runtime-input bindings, the exact post-stop event partial order, image authority basis, bounded prebaseline VFS-normalization delta, and host/inside live attestations including held userns ownership projection and the complete 33-row canonical mount graph. State transitions belong to `rootfs-audit.json`; before/authorized/after records must be fully equal. `source-capsule.json` records public input identities, the full ordered bootstrap authority, and exact executed/verifier capsule hashes; `leakage-scan.json` records completion/verdict without a key hash or matched bytes. `SOURCES`, `SPECS`, `BUILD`, `BUILDROOT`, extracted files, runtime snapshots, Podman state, and scratch are forbidden from the accepted tree.

12. Fsync the complete candidate, calculate its exact type/mode/UID/GID/size/hash tree commitment, atomically rename it without replacement to `build/gate01/<id>/kernel`, fsync the parent, and publish `build/gate01/<id>/kernel.receipt.json` last through another no-replace/fsync sequence. If receipt publication fails, roll the tree back; if any earlier operation or cleanup fails, publish neither final tree nor receipt. The receipt commits the intended absolute path, complete tree, source-capsule hash, and inspector-originated RPM-manifest hash. Every later consumer must open and revalidate the detached receipt plus all 13 semantically validated files through a coherent held descriptor view, with no xattrs and explicit nonzero expected UID/GID (future rootful consumers use validated SUDO_UID/SUDO_GID). Every acceptance check and material cleanup precedes final receipt-parent fsync. Once that fsync succeeds, no rollback or fallible revalidation occurs: remaining process-local close/unlock/output failures emit fixed warnings while preserving success.

Builder A and canonical retain outer timezone `UTC` and umask `0022`; builder B retains outer timezone `Pacific/Honolulu` and umask `0077`. The supervisor rejects any other environment or inherited umask before creating state. Different host scratch/store/output paths provide path variation. Both build execs receive the same controlled container environment and record the outer/declaration split without attempting an injected hostname file.

- [ ] **Step 7: Replace the shell driver with a hardened thin launcher**

`scripts/gate01/build-kernel.sh` uses `#!/bin/bash -p`, a closed argument grammar, exact builder-specific outer timezone/umask, fixed PATH/locale and absolute runtime tools. It rejects root and unsupported Bash/loader/Python startup variables. Its non-symlink physical repository path is authoritative. Opening FD60 on `tools/gate01/kernel_bootstrap.py` is the trusted clean-launch instant; isolated stdlib-only Python validates its own descriptor and all 13 ordered source paths before any repository package import. It seals executable ZIP FD61 plus canonical authority FD62, closes FD60, and dispatches the requested command. The same held closure is rechecked at the final pre-receipt boundary.

```sh
scripts/gate01/build-kernel.sh build builder-a
scripts/gate01/build-kernel.sh build builder-b
scripts/gate01/build-kernel.sh compare
scripts/gate01/build-kernel.sh meta-requirements builder-a
# Keyless integration, only when explicitly authorized:
scripts/gate01/build-kernel.sh lifecycle-check
```

The inherited application-FD matrix is exact (standard FDs 0–2 are separate):

| Role | Inherited application descriptors |
|---|---|
| Clean launcher/bootstrap | FD60, then sealed executable FD61 + canonical authority FD62; close FD60 |
| Inert PID1 / compiler probe | None |
| Live/no-build verifier | FD20 sealed verifier |
| OCI summary worker | FD18 archive + FD20 verifier |
| Rootfs audit worker | FD18 archive + FD19 runtime containerenv + FD20 verifier |
| Public input audit | FD20 verifier + FD21 certificate + FD50–57 exact public input-audit roles; no FD25 |
| Signing build wrapper | FD20–26 + FD30–33; FD21–24 are certificate/source/config/spec, FD25 sealed key, FD26 result |
| Artifact inspector | FD20, FD21, read-only FD30–33, output FD40/41/42 (RPM manifest/installed manifest/result) |
| Meta worker | FD20 + read-only FD33 only |
| Secret tree scanner | FD20 + FD25 + FD50 held tree |
| Secret artifact scanner | FD20 + FD25 + read-only FD30–33 |

The host retains FD61/62 as executing authority but does not forward them to
container workers. Writer probes, writer close, second probes, read-only reopen,
read leases and terminal identity checks cover artifacts and every anonymous
manifest/result/log output. Pathname `rpm_artifacts inspect` is retired and
refuses before traversal; inspection authority is `inspect-fixed-fds` only.

The launcher contains no container, key, artifact, scan, cleanup or publication logic. Builder shorthand (`builder-a`, `builder-b`, `canonical`) remains supported for `make gate01-kernel` compatibility. No production command directly executes a mutable `kernel_build.py` path.

- [ ] **Step 8: Add receipt-bound comparison and meta-requirements proofs**

Run:

```bash
scripts/gate01/build-kernel.sh compare
scripts/gate01/build-kernel.sh meta-requirements builder-a
```

`compare` first revalidates both `kernel.receipt.json` files and both complete builder trees while holding the exact RPM/manifests, then writes canonical `build/gate01/compare/kernel-rpms.json`. The comparison requires byte-identical genuine SRPMs, exact NEVRAs, installed files, and module signatures; raw binary-RPM differences are advisory only and require a documented RPM-header cause before a green gate. After all inputs are revalidated and temporary state is cleaned, publish `build/gate01/compare/kernel-rpms.receipt.json` last with the same no-replace/fsync/rollback protocol. It requires identical strict source capsules and hard-compares all security metadata. Its commitment includes the comparison file and both input receipt/tree/capsule hashes.

`meta-requirements` revalidates the selected builder receipt/tree, supplies only sealed verifier FD20 and exact read-only meta-RPM FD33 to a new offline secret-free locked-image container. `rpm_artifacts meta-fixed-fd` independently validates identity, fileless policy, the complete framed RPM security metadata, compressed payload digest and full CPIO digest. It rejects every unexpected inherited application FD and returns strict canonical JSON. Full dependency tuples, including RPM-generated capabilities, are validated without filtering or deduplication; the result contains these exact two uname dependencies:

```text
kernel-openmythos-core-uname-r = 6.18.48-1.openmythos.fc44.x86_64
kernel-openmythos-modules-uname-r = 6.18.48-1.openmythos.fc44.x86_64
```

The meta query uses another fresh secret-free store/container and the same no-hook init/live/authorized/post lifecycle; it receives no key or build input, and no proof is publishable if its post-audit or cleanup fails. After that lifecycle completes, write canonical `build/gate01/compare/meta-requirements.json` and publish `build/gate01/compare/meta-requirements.receipt.json` last with the same no-replace/fsync/rollback protocol. Its commitment includes the proof file, exact meta-RPM hash, and selected builder receipt/tree hash. Task 7, Task 10, the release gate, and every manual consumer must reject a missing/replaced receipt and revalidate the committed file/tree immediately before use.

- [ ] **Step 9: Run the no-build verification and fresh review gate**

The no-build evidence commits schema version 1, the complete canonical bootstrap
authority and its SHA-256, the executed sealed capsule SHA-256, the full locked OCI
summary, selected public toolchain lock/archive hashes, and the canonical scoped
base/current manifest plus SHA-256. Its scope is sealed in `proof_io.py`: public
roots `tools/gate01`, `scripts/gate01`, `tests/gate01`, `os/kernel/config`,
`os/kernel/packaging`; explicit files `tools/__init__.py`, `Makefile`,
`os/kernel/Containerfile.builder`, `os/kernel/README.md`,
`os/kernel/source.lock.json`, `os/build/toolchain.lock.json`, and these exact
architecture/plan documents. Never walk `os/kernel/keys`, `build` (including
secrets), `.git`, or `.superpowers` for current-source evidence; public
certificates/manifests require their separate explicitly authorized input policy.

Use absolute trusted Git plumbing at immutable base
`cfc94e5437dac3f80deed3bad70c3d56ae4840a1`, without replacements, hooks, fsmonitor,
index, ignore rules or filters as authority. Record raw relative path bytes as
hex, immutable base Git mode/OID and direct current type/full mode/file size/SHA-256,
including unchanged tracked files, deletions, untracked files and directories.
Only untracked `__pycache__` components are excluded. Reject symlinks, special
nodes, hardlinked regular files and xattrs. Hold the original source files,
directories and ancestor identities through the lifecycle and all material
cleanup; two-pass terminal hash/version/listing checks and exact 13-file
bootstrap mode/size/hash cross-binding run again after cleanup.

The no-build record preserves full equal before/authorized/after rootfs records,
all ten transitions, exact config/fixture/sealed-policy identities, store and
runtime-input bindings, normalization and live userns/mount evidence. It sets
`cleanup={container_removed:true,store_removed:true,temporary_tree_removed:true,
scope_revalidated_after_cleanup:true,verdict:"pass"}` only after every operation
succeeds. Cleanup errors already prevent return; holding/rechecking authority
through that interval is additionally mandatory.

Run:

```bash
python3 -B -m unittest \
  tests.gate01.test_kernel_build \
  tests.gate01.test_oci_rootfs \
  tests.gate01.test_rpm_artifacts \
  tests.gate01.test_module_key -v
python3 -B -m unittest discover -s tests/gate01 -p 'test_*.py' -v
python3 -m py_compile \
  tools/gate01/proof_io.py tools/gate01/container_runtime.py \
  tools/gate01/kernel_bootstrap.py tools/gate01/kernel_build.py tools/gate01/oci_rootfs.py \
  tools/gate01/rpm_artifacts.py tools/gate01/module_key.py \
  tests/gate01/test_kernel_build.py tests/gate01/test_oci_rootfs.py \
  tests/gate01/test_rpm_artifacts.py tests/gate01/test_module_key.py
bash -n scripts/gate01/build-kernel.sh
shellcheck scripts/gate01/build-kernel.sh
git diff --check
git grep -l -I -E '^-----BEGIN (RSA |EC )?PRIVATE KEY-----$' -- os tools scripts tests docs .github
# Expected exit is exactly 1 (no header); any other exit needs investigation.
# Also review every explicitly scoped untracked Task 6 source/fixture.
```

After explicit controller authorization, separately run:

```bash
scripts/gate01/build-kernel.sh lifecycle-check
```

Expected: every focused and full Gate 01 unit test passes; the real no-build lifecycle imports the held locked archive into a disposable VFS store and proves the exact no-hook state machine, descriptor-derived runtime projection, one-time prebaseline normalization, live process/mount contract, three rootfs audits, and cleanup without acquiring a key or publishing output; compilation, Bash syntax, ShellCheck, and diff checks pass; and the tracked-tree marker scan lists no private key. Freeze the exact scoped diff/source identities and obtain fresh specification and code-review approval of the lifecycle, OCI semantics, descriptor flow, output allowlist, cleanup, and receipt protocol before launching either multi-hour build.

- [ ] **Step 10: Build twice and publish all four detached receipts**

Run only after Step 9 approval:

```bash
scripts/gate01/build-kernel.sh builder-a
scripts/gate01/build-kernel.sh builder-b
scripts/gate01/build-kernel.sh compare
scripts/gate01/build-kernel.sh meta-requirements builder-a
```

Expected: both complete rootfs-audited build/inspection runs pass; both builder receipts revalidate; `kernel-rpms.json` has verdict `pass`; `meta-requirements.json` contains the exact two uname requirements; all four detached receipts are last-write commit markers; and the source/helper/diff identities recorded before launch remain unchanged afterward. No accepted runtime, extraction, scratch, signing store, inspection store, writable artifact descriptor, or unreceipted output remains.

- [ ] **Step 11: Commit kernel packaging and inspection**

```bash
git add Makefile os/kernel/packaging/kernel-openmythos.spec \
  scripts/gate01/build-kernel.sh \
  tools/gate01/proof_io.py tools/gate01/container_runtime.py \
  tools/gate01/kernel_bootstrap.py tools/gate01/kernel_build.py tools/gate01/oci_rootfs.py \
  tools/gate01/rpm_artifacts.py tools/gate01/module_key.py \
  tests/gate01/test_kernel_build.py tests/gate01/test_oci_rootfs.py \
  tests/gate01/test_rpm_artifacts.py tests/gate01/test_module_key.py \
  tests/gate01/fixtures/rpm-manifest-*.json \
  tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json \
  docs/superpowers/plans/2026-09-03-stone-boot-proof.md \
  docs/superpowers/specs/2026-08-31-openmythos-os-architecture-design.md \
  os/kernel/README.md
git commit -m "kernel: package signed OpenMythos kernel RPMs"
```

### Task 7: Assemble and prove the Fedora 44 bootc payload

**Files:**
- Create: `os/images/gate01/Containerfile`
- Create: `os/images/gate01/firmware.lock.json`
- Create: `os/images/gate01/files/usr/lib/os-release`
- Create: `os/images/gate01/files/usr/lib/openmythos/gate01-release.env.in`
- Create: `os/images/gate01/files/usr/libexec/openmythos-gate01-boot-report`
- Create: `os/images/gate01/files/usr/lib/systemd/system/openmythos-gate01-boot-report.service`
- Create: `os/images/gate01/files/usr/lib/systemd/system/openmythos-gate01-boot-report.timer`
- Create: `tools/gate01/oci_artifacts.py`
- Create: `scripts/gate01/build-payload.sh`
- Create: `tests/gate01/test_oci_artifacts.py`
- Create: `tests/gate01/fixtures/oci-index-valid.json`
- Create: `tests/gate01/fixtures/oci-index-multiple-manifests.json`
- Modify: `Makefile`

**Interfaces:**
- Consumes: the digest-pinned Fedora 44 bootc base and one accepted Task 6 RPM set only through its detached sibling `build/gate01/<id>/kernel.receipt.json`. Before opening any RPM, the consumer uses the Task 6 receipt primitives from `tools/gate01/proof_io.py` to bind and revalidate the receipt, its intended absolute tree path, the complete exact 13-file tree commitment, and the committed inspector manifest.
- Produces: `build/gate01/BUILDER_ID/payload/openmythos-gate01.oci.tar`, a digest-qualified OCI descriptor report, a bootc layout report, and a payload that emits one `OPENMYTHOS_BOOT_REPORT=<compact-json>` line only when booted with `openmythos.gate01=1`.

- [ ] **Step 1: Write failing OCI parser tests**

`tests/gate01/test_oci_artifacts.py` builds tiny temporary OCI layouts from fixture `index.json` plus synthetic config, manifest, and layer blobs, then tests:

- exactly one `linux/amd64` image manifest is required;
- every descriptor digest must equal the hash of its referenced blob;
- the selected manifest media type is an OCI image manifest;
- config architecture is `amd64` and OS is `linux`;
- config `created` is exactly `2026-08-28T06:47:39Z`;
- `inspect_oci_archive(path)` reports index, manifest, config, and ordered layer digests;
- `compare_oci(left, right)` rejects a reordered or changed layer.

- [ ] **Step 2: Run tests and confirm the OCI API is absent**

Run: `python3 -m unittest tests.gate01.test_oci_artifacts -v`

Expected: `ERROR` because `tools.gate01.oci_artifacts` does not exist.

- [ ] **Step 3: Lock Gate 01 firmware to the empty QEMU requirement**

```json
{
  "schema_version": 1,
  "gate": "01",
  "target": "qemu-q35-virtio",
  "firmware": []
}
```

Q35 firmware executes outside the guest disk as OVMF. The virtio storage, console, and networking devices used here need kernel drivers but no guest firmware blob. Payload validation therefore requires zero regular files or symlinks below `/usr/lib/firmware`; it also rejects installed package names matching `linux-firmware`, `*-firmware`, `amd-gpu-firmware`, `realtek-firmware`, or `nvidia-*`.

- [ ] **Step 4: Add immutable OS and release identity files**

`os/images/gate01/files/usr/lib/os-release` is exactly:

```text
NAME="OpenMythos OS"
ID=openmythos
ID_LIKE=fedora
VERSION="0.1 Gate 01"
VERSION_ID="0.1"
PRETTY_NAME="OpenMythos OS 0.1 (Stone Boot Proof)"
VARIANT="Stone Boot Proof"
VARIANT_ID=stone-gate01
IMAGE_ID=openmythos
IMAGE_VERSION=0.1-gate01
```

`gate01-release.env.in` is a strict key/value template with these keys in this order: `OPENMYTHOS_GATE`, `OPENMYTHOS_KERNEL_RELEASE`, `OPENMYTHOS_KERNEL_NEVRA`, `OPENMYTHOS_KERNEL_CORE_NEVRA`, `OPENMYTHOS_SOURCE_SHA256`, `OPENMYTHOS_CONFIG_SHA256`, `OPENMYTHOS_MODULE_CERTIFICATE_SHA256`, `OPENMYTHOS_TOOLCHAIN_MANIFEST_DIGEST`, and `OPENMYTHOS_BASE_MANIFEST_DIGEST`. The committed values contain `@KERNEL_RELEASE@`, `@KERNEL_NEVRA@`, `@KERNEL_CORE_NEVRA@`, `@SOURCE_SHA256@`, `@CONFIG_SHA256@`, `@MODULE_CERTIFICATE_SHA256@`, `@TOOLCHAIN_MANIFEST_DIGEST@`, and `@BASE_MANIFEST_DIGEST@`; `OPENMYTHOS_GATE=01` is literal. The build script replaces every token exactly once and rejects any remaining `@[A-Z_]*@` sequence.

- [ ] **Step 5: Implement the in-guest identity reporter**

`openmythos-gate01-boot-report` is Bash with `set -Eeuo pipefail`. It sources only the package-owned release env and `/usr/lib/os-release`, then fails unless all of these hold:

- `/sys/firmware/efi` exists;
- `systemctl is-active --quiet multi-user.target` succeeds;
- `uname -r` equals `OPENMYTHOS_KERNEL_RELEASE`;
- `rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}' kernel-openmythos` equals `OPENMYTHOS_KERNEL_NEVRA`;
- `rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}' kernel-openmythos-core` equals `OPENMYTHOS_KERNEL_CORE_NEVRA`;
- `/sys/module/module/parameters/sig_enforce` is `Y` or `1`;
- `modprobe virtio_net` succeeds under signature enforcement, `/sys/module/virtio_net` appears, and `modinfo -F signer virtio_net` equals `OpenMythos Gate 01 Development Module Key`;
- `/sys/kernel/security/lockdown` contains `[integrity]`;
- exactly one directory exists directly below `/usr/lib/modules`, and its basename is the expected release;
- that directory contains nonempty adjacent `vmlinuz` and `initramfs.img` files;
- `/usr/lib/openmythos/gate01-layout.env` exists and contains exactly `OPENMYTHOS_CONTAINER_LAYOUT_VALIDATED=1`; payload construction creates this marker only after proving the pre-deployment container has no `/boot` entry, because the installed disk legitimately gains bootloader files;
- `find /usr/lib/firmware -type f -o -type l` returns no path;
- `bootc status --booted --format=json --format-version=1` succeeds and the sole `imageDigest` inside the returned booted deployment matches `sha256:[0-9a-f]{64}`.

Extract `status.booted.image.imageDigest` by first requesting `--booted`, removing newlines from the JSON, trimming everything through the unique `"booted":{` boundary, and then selecting the sole quoted `imageDigest` value with anchored `sed` expressions. Require exactly one `booted` key and exactly one digest before accepting it. The host-side parser remains authoritative and compares the extracted result with the full JSON-aware expectation.

The script builds compact JSON with `printf` from the controlled values and exactly these keys in sorted order:

```text
base_manifest_digest, bootc_image_digest, config_sha256, firmware_mode,
gate, image_version, kernel_core_nevra, kernel_nevra, kernel_release,
layout_validated, lockdown, module_certificate_sha256, module_probe,
module_sig_enforce, os_id, os_version_id, schema_version, source_sha256, target,
toolchain_manifest_digest, variant_id
```

Use values `firmware_mode=uefi`, `gate=01`, `image_version=0.1-gate01`, `layout_validated=true`, `lockdown=integrity`, `module_probe=virtio_net`, `module_sig_enforce=true`, `os_id=openmythos`, `os_version_id=0.1`, `schema_version=1`, `target=multi-user.target`, and `variant_id=stone-gate01`. Write the JSON atomically to `/run/openmythos/gate01-boot-report.json`, run `systemd-cat -t openmythos-gate01` with that file on stdin, print exactly `OPENMYTHOS_BOOT_REPORT=<json>` to `/dev/ttyS0`, and call `sync`.

- [ ] **Step 6: Schedule reporting only for the proof boot**

The service is:

```ini
[Unit]
Description=Emit OpenMythos Gate 01 boot identity
ConditionKernelCommandLine=openmythos.gate01=1
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/openmythos-gate01-boot-report
ExecStartPost=/usr/bin/systemctl poweroff --no-block
TimeoutStartSec=90
```

The timer is:

```ini
[Unit]
Description=Delay OpenMythos Gate 01 proof until userspace settles
ConditionKernelCommandLine=openmythos.gate01=1

[Timer]
OnActiveSec=3s
AccuracySec=1s
Unit=openmythos-gate01-boot-report.service

[Install]
WantedBy=multi-user.target
```

Enable the timer in the payload. Without the kernel argument it does not activate, emit a report, or power off.

- [ ] **Step 7: Build the payload without network or transient RPM layers**

`os/images/gate01/Containerfile` starts from the exact Fedora manifest digest and sets `LABEL containers.bootc=1`. It consumes RPMs and the realtime shim only through ephemeral read-only build volumes:

```dockerfile
FROM quay.io/fedora/fedora-bootc@sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756

LABEL containers.bootc="1" \
      org.opencontainers.image.title="OpenMythos OS Stone Boot Proof" \
      org.opencontainers.image.version="0.1-gate01"

RUN set -eux; \
    export SOURCE_DATE_EPOCH=1787899659; \
    export TZ=UTC; \
    export LC_ALL=C.UTF-8; \
    export LD_PRELOAD=/run/gate-tools/libfaketime.so.1; \
    export FAKETIME='@2026-08-28 06:47:39'; \
    export DONT_FAKE_MONOTONIC=1; \
    for package in kernel kernel-core kernel-modules kernel-modules-core kernel-modules-extra; do \
      rpm -q "$package" >/dev/null 2>&1 || continue; \
      dnf -y --disablerepo='*' --noautoremove remove "$package"; \
    done; \
    firmware_packages=$(rpm -qa --qf '%{NAME}\n' | LC_ALL=C sort -u | \
      grep -E '(^linux-firmware$|-firmware$|^nvidia-)' || true); \
    if [ -n "$firmware_packages" ]; then \
      printf '%s\n' "$firmware_packages" | xargs -r dnf -y --disablerepo='*' --noautoremove remove; \
    fi; \
    OPENMYTHOS_IMAGE_BUILD=1 dnf -y --disablerepo='*' install /run/kernel-rpms/*.rpm; \
    dnf clean all; \
    rm -rf /var/cache/dnf; \
    mkdir -p /usr/lib/firmware; \
    kver='6.18.48-1.openmythos.fc44.x86_64'; \
    dracut --force --reproducible --no-hostonly --kver "$kver" "/usr/lib/modules/$kver/initramfs.img"; \
    test "$(find /usr/lib/modules -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1; \
    test -s "/usr/lib/modules/$kver/vmlinuz"; \
    test -s "/usr/lib/modules/$kver/initramfs.img"; \
    test -z "$(find /usr/lib/firmware \( -type f -o -type l \) -print -quit)"; \
    test -z "$(find /boot -mindepth 1 -print -quit)"

COPY files/ /

RUN chmod 0755 /usr/libexec/openmythos-gate01-boot-report \
    && mkdir -p /usr/lib/systemd/system/multi-user.target.wants \
    && ln -s ../openmythos-gate01-boot-report.timer \
      /usr/lib/systemd/system/multi-user.target.wants/openmythos-gate01-boot-report.timer \
    && printf '%s\n' 'OPENMYTHOS_CONTAINER_LAYOUT_VALIDATED=1' \
      > /usr/lib/openmythos/gate01-layout.env \
    && bootc container lint
```

`podman build` mounts the RPM directory at `/run/kernel-rpms:ro` and the locked toolchain's `/usr/lib64/faketime/libfaketime.so.1` at `/run/gate-tools/libfaketime.so.1:ro` with `--volume`; those ephemeral build volumes are not OCI layers. Freezing only realtime during the RPM transaction prevents RPM install-time/transaction records from drifting, while `DONT_FAKE_MONOTONIC=1` preserves timeout behavior. Dracut's reproducible mode normalizes initramfs ordering and timestamps. DNF runs with every repository disabled; the build also uses `--network=none --pull=never --no-cache --format=oci --timestamp=1787899659 --security-opt label=disable`.

- [ ] **Step 8: Implement OCI archive inspection and comparison**

`tools/gate01/oci_artifacts.py` reads `oci-layout`, `index.json`, and `blobs/sha256/*` directly from a tar opened with `tarfile` without extracting it. It rejects absolute members, `..` members, links, duplicates, and any blob whose bytes do not match its filename. It selects exactly one OCI image manifest for `linux/amd64`, verifies its config and layer descriptors, and writes canonical JSON containing:

```json
{
  "schema_version": 1,
  "architecture": "amd64",
  "os": "linux",
  "index_digest": "sha256:<index-json-hash>",
  "manifest_digest": "sha256:<manifest-blob-hash>",
  "config_digest": "sha256:<config-blob-hash>",
  "layer_digests": ["sha256:<ordered-layer-hash>"],
  "created": "2026-08-28T06:47:39Z",
  "archive_sha256": "<raw-archive-hash>"
}
```

The literal digest values are computed, not copied. Archive SHA is advisory; manifest, config, and ordered layer values are hard comparison fields. The CLI supports `inspect --archive PATH --output PATH` and `compare --left PATH --right PATH --output PATH`, returning nonzero for any hard-field difference.

- [ ] **Step 9: Implement isolated payload construction and validation**

`scripts/gate01/build-payload.sh BUILDER_ID` requires invocation through `sudo` from a non-root account, requires numeric nonzero `SUDO_UID`/`SUDO_GID`, and accepts the same three builder IDs as the kernel script. Immediately before using an RPM, it opens the sibling `build/gate01/BUILDER_ID/kernel.receipt.json` without following links, rejects a missing/replaced/malformed receipt, and revalidates its intended absolute path, complete `build/gate01/BUILDER_ID/kernel` tree commitment, and inspector-manifest commitment. Only after that consumer-boundary check may it consume the exact three files in `build/gate01/BUILDER_ID/kernel/rpmbuild/RPMS/x86_64`; path-based `rpm_artifacts validate` is an additional semantic check, not the artifact authority. It copies `Containerfile` plus `files/` to a fresh context below the builder output, renders the release env there from locked values, and rejects secrets by filename and content before building. It sets all staged rootfs files to their committed modes and `SOURCE_DATE_EPOCH`, fixes directories to `0755`, and fails if a symlink is not explicitly expected; checkout mtimes and the invoking umask therefore cannot enter a layer.

Use a builder-specific Podman `--root`, `--runroot`, and rootful `--storage-driver=overlay` below `build/gate01/BUILDER_ID/podman`. Import the cached Fedora base archive, tag its selected manifest with the exact digest-qualified source name, and build tag `localhost/openmythos/gate01:BUILDER_ID`. Extract the faketime library from the digest-verified toolchain archive into that builder's private work directory, record its SHA-256, and pass read-only volumes for it and `<absolute-rpm-dir>:/run/kernel-rpms:ro` with the offline flags from Step 7. Export with Skopeo to `payload/openmythos-gate01.oci.tar` and inspect it through the Python tool. Finally chmod artifact/report files `0644`, directories `0755`, and chown only the payload output (not the isolated container store) to `SUDO_UID:SUDO_GID` so unprivileged comparison can read it.

Run the built payload with `--network=none` to execute all of these read-only validations:

```text
bootc container lint
test ID=openmythos and VARIANT_ID=stone-gate01 from /usr/lib/os-release
test exactly one /usr/lib/modules directory with adjacent nonempty vmlinuz/initramfs.img
rpm -q kernel-openmythos kernel-openmythos-core kernel-openmythos-modules
test no Fedora stock kernel package is installed
test no firmware or NVIDIA package/file is installed
test /boot has no entry
systemd-analyze verify the report service and timer
```

Write those observations to canonical `payload-layout.json`; a failure prevents OCI export from becoming an accepted artifact.

- [ ] **Step 10: Build and compare both payloads**

Run:

```bash
sudo scripts/gate01/build-payload.sh builder-a
sudo scripts/gate01/build-payload.sh builder-b
python3 -m tools.gate01.oci_artifacts compare \
  --left build/gate01/builder-a/payload/oci-artifacts.json \
  --right build/gate01/builder-b/payload/oci-artifacts.json \
  --output build/gate01/compare/payload-oci.json
```

Expected: manifest, config, and every ordered layer digest match and the comparison verdict is `pass`. A mismatch fails even if the filesystem-level RPM comparison passed.

- [ ] **Step 11: Run negative tests and commit**

Run: `python3 -m unittest tests.gate01.test_oci_artifacts -v`

Expected: all OCI parsing and mismatch tests pass.

Run the comparator against `oci-index-multiple-manifests.json` assembled with two amd64 manifests.

Expected: nonzero exit and `expected exactly one linux/amd64 image manifest`.

```bash
git add Makefile os/images/gate01 tools/gate01/oci_artifacts.py \
  scripts/gate01/build-payload.sh tests/gate01/test_oci_artifacts.py \
  tests/gate01/fixtures/oci-index-*.json
git commit -m "os: assemble the Gate 01 bootc payload"
```

### Task 8: Convert each payload to a UEFI QCOW2 and normalize its immutable contents

**Files:**
- Create: `os/images/gate01/disk.toml`
- Create: `tools/gate01/qcow2_artifacts.py`
- Create: `scripts/gate01/build-qcow2.sh`
- Create: `tests/gate01/test_qcow2_artifacts.py`
- Create: `tests/gate01/fixtures/qcow-tree-left.json`
- Create: `tests/gate01/fixtures/qcow-tree-wrapper-different.json`
- Create: `tests/gate01/fixtures/qcow-tree-content-different.json`
- Modify: `Makefile`

**Interfaces:**
- Consumes: one digest-qualified payload in an isolated rootful container store and the pinned unified `image-builder` image.
- Produces: an ext4 UEFI QCOW2, osbuild manifest, SPDX SBOM, image-builder log/version, partition inventory, raw QCOW metadata, and a canonical immutable-tree manifest. No command accepts a host block-device argument.

- [ ] **Step 1: Write failing normalization tests**

`tests/gate01/test_qcow2_artifacts.py` loads the three small fixture manifests and asserts:

- changing only `qcow2_sha256`, virtual size, allocated bytes, filesystem UUID, partition UUID, creation timestamp, or deployment directory checksum does not change `normalized_immutable_digest`;
- changing a regular file SHA-256, mode, symlink target, UID/GID, ACL, or SELinux label changes the normalized digest;
- a path outside `/usr`, `/ostree/repo/objects`, or a deployment's immutable `usr` subtree is rejected from the hard comparison set;
- `compare_qcow2(left, right)` reports wrapper differences under `advisory` and content differences under `failures`.

- [ ] **Step 2: Run tests and confirm the QCOW API is absent**

Run: `python3 -m unittest tests.gate01.test_qcow2_artifacts -v`

Expected: `ERROR` because `tools.gate01.qcow2_artifacts` does not exist.

- [ ] **Step 3: Define the disk customization with no login credential**

```toml
# os/images/gate01/disk.toml
[customizations.kernel]
append = "console=tty0 console=ttyS0,115200n8 openmythos.gate01=1"
```

The proof needs no user, password, SSH key, hostname customization, filesystem customization, or network access: the conditioned one-shot service reports to the serial port and powers off. Kernel append is on the current documented bootc-QCOW2 customization allowlist. The build script rejects a blueprint containing `customizations.user`, `password`, `key`, `hostname`, or `filesystem` before invoking image-builder; partition sizing/layout comes from image-builder's pinned bootc generic definition and is captured in its manifest.

- [ ] **Step 4: Implement canonical immutable-tree records**

`tools/gate01/qcow2_artifacts.py` provides:

```text
python3 -m tools.gate01.qcow2_artifacts inspect --image QCOW2 --work-dir DIR --output JSON
python3 -m tools.gate01.qcow2_artifacts compare --left JSON --right JSON --output JSON
```

`inspect` first rejects non-regular files and resolves the QCOW2 path below `build/gate01/`. It invokes commands with argument arrays and captures:

```text
qemu-img check --output=json QCOW2
qemu-img info --output=json QCOW2
qemu-img map --output=json QCOW2
virt-filesystems --long --uuid --all -a QCOW2
```

It requires a GPT disk, one EFI System Partition, and an ext4 root filesystem. Through read-only libguestfs inspection it exports these three hard comparison roots without executing guest code:

1. the mounted deployment `/usr` tree;
2. `/ostree/repo/objects`;
3. every `usr` subtree below `/ostree/deploy/*/deploy/*/`.

It walks with bytewise-sorted POSIX paths and records each regular file, directory, and symlink as `{path,type,mode,uid,gid,size,sha256,link_target,acl,selinux}`. Fields not applicable to the type are JSON `null`. ACL and `security.selinux` are obtained through libguestfs, not inherited from a host-side copy. Modification/access/change/birth times are deliberately omitted. Deployment OS names and checksum-plus-serial path components are replaced with `<os>` and `<deployment>` before hashing; object names and file contents are never rewritten. Duplicate normalized paths fail.
Each record is encoded with `json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` plus newline. `normalized_immutable_digest` is SHA-256 over that complete stream. The output also records raw QCOW SHA-256, `qemu-img info`, allocation map, partition/filesystem UUIDs, and osbuild build identifier under `advisory`.

`compare` fails unless both normalized digests and complete normalized record arrays match. It writes a bounded first-100-path diff and counts all differences; wrapper metadata never suppresses or excuses a content difference.

- [ ] **Step 5: Implement the pinned image-builder invocation**

`scripts/gate01/build-qcow2.sh BUILDER_ID` requires invocation through `sudo` from a non-root account, requires numeric nonzero `SUDO_UID`/`SUDO_GID`, accepts only `builder-a`, `builder-b`, or `canonical`, and resolves every output/store path below the selected builder directory. It validates the payload OCI report, imports that payload and the cached `image-builder.oci.tar` into the same clean builder-specific Podman store, and addresses both by manifest digest.

Before the build it records `lsblk --json --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,MOUNTPOINTS` as read-only host evidence. The image-builder command line may contain only regular-file/directory volume sources under the repository, the isolated container graphroot, `/dev/kvm` when present, and its container-internal destinations. Reject any argument matching `/dev/sd*`, `/dev/vd*`, `/dev/nvme*`, `/dev/mmcblk*`, `/dev/mapper/*`, or `/dev/disk/*`.

Run the pinned container with the same builder-specific `podman --root`, `--runroot`, and rootful `--storage-driver=overlay` options, plus:

```text
--rm
--privileged
--network=none
--pull=never
--security-opt label=disable
--volume <graphroot>:/var/lib/containers/storage
--volume <absolute-disk.toml>:/config.toml:ro
--volume <absolute-output>:/output
--workdir /output
ghcr.io/osbuild/image-builder-cli@sha256:b44e26d185916d28a88bbc04faa986ccc44535691715f1bc276523693b19ccca
build --bootc-ref <digest-qualified-local-payload> --bootc-default-fs ext4
--blueprint /config.toml --with-manifest --with-sbom qcow2
```

Do not pass `--distro`; bootc determines the distribution from the payload. Before conversion, run `image-builder bootc inspect --ref <digest-qualified-local-payload> --format=json` in the same pinned container/storage and retain the output. Capture stdout/stderr and `image-builder version --format=json`. Require exactly one resulting QCOW2, one osbuild manifest, and one SPDX document, rename the disk to `openmythos-gate01.qcow2`, run `qemu-img check`, and call the immutable-tree inspector. Chmod artifact/report files `0644`, directories `0755`, and chown only the QCOW output (not the isolated container store) to `SUDO_UID:SUDO_GID`. Keep the Podman graphroot until the boot report is complete, because image-builder and the booted deployment must resolve the same payload identity.

- [ ] **Step 6: Build two disks and compare hard versus advisory evidence**

Run:

```bash
sudo scripts/gate01/build-qcow2.sh builder-a
sudo scripts/gate01/build-qcow2.sh builder-b
python3 -m tools.gate01.qcow2_artifacts compare \
  --left build/gate01/builder-a/qcow2/qcow2-artifacts.json \
  --right build/gate01/builder-b/qcow2/qcow2-artifacts.json \
  --output build/gate01/compare/qcow2.json
```

Expected: both images pass `qemu-img check`, both have UEFI/GPT plus ext4, normalized immutable digests and records match, and the comparison verdict is `pass`. The two raw QCOW2 SHA-256 values and UUIDs are preserved as advisory observations and are allowed to differ.

Run both `qemu-img compare` and `qemu-img compare --strict` against the two QCOW2 files and record their exit codes/output.

Expected: both results are advisory because generated partition/filesystem UUID sectors are guest-visible yet explicitly normalized by this gate. Non-strict reports virtual-disk byte differences; strict additionally reports allocation/zeroing differences. Neither command substitutes for the hard normalized immutable-tree comparison, and the evidence must name the differing normalized fields rather than describing every difference as wrapper metadata.

- [ ] **Step 7: Run fixture tests and commit**

Run: `python3 -m unittest tests.gate01.test_qcow2_artifacts -v`

Expected: wrapper-only differences pass, content differences fail, and invalid comparison roots are rejected.

```bash
git add Makefile os/images/gate01/disk.toml tools/gate01/qcow2_artifacts.py \
  scripts/gate01/build-qcow2.sh tests/gate01/test_qcow2_artifacts.py \
  tests/gate01/fixtures/qcow-tree-*.json
git commit -m "os: build and normalize Gate 01 QCOW2 images"
```

### Task 9: Boot disposable disks through pinned OVMF and verify the serial identity report

**Files:**
- Create: `os/build/qemu.lock.json`
- Create: `tools/gate01/boot_report.py`
- Create: `scripts/gate01/boot-qemu.sh`
- Create: `tests/gate01/test_boot_report.py`
- Create: `tests/gate01/fixtures/serial-valid.log`
- Create: `tests/gate01/fixtures/serial-wrong-kernel.log`
- Create: `tests/gate01/fixtures/serial-duplicate-report.log`
- Modify: `Makefile`

**Interfaces:**
- Consumes: a read-only QCOW2 base, verified OVMF code/template files, and host-generated expected identity JSON.
- Produces: a disposable QCOW2 overlay, disposable OVMF variable store, complete serial log, QEMU command/version/exit evidence, and a validated `boot-report.json`. It never attaches a physical disk or mutates the base QCOW2.

- [ ] **Step 1: Write failing report parser tests**

`tests/gate01/test_boot_report.py` supplies a complete expectations object and verifies that:

- exactly one line beginning at column zero with `OPENMYTHOS_BOOT_REPORT=` is required;
- CRLF and unrelated serial noise are tolerated;
- unknown/missing JSON fields, duplicate report lines, a malformed digest, or a non-boolean field are rejected;
- every locked identity field must equal expectations;
- `firmware_mode`, `target`, module enforcement, lockdown, layout result, and OS/variant identity have exact accepted values;
- the wrong-kernel fixture reports `kernel_release: expected 6.18.48-1.openmythos.fc44.x86_64`;
- the duplicate fixture reports `expected exactly one boot report, found 2`.

- [ ] **Step 2: Run the tests and confirm the boot-report API is absent**

Run: `python3 -m unittest tests.gate01.test_boot_report -v`

Expected: `ERROR` because `tools.gate01.boot_report` does not exist.

- [ ] **Step 3: Pin the QEMU/OVMF proof environment**

```json
{
  "schema_version": 1,
  "architecture": "x86_64",
  "machine": "q35",
  "qemu_version": "10.2.1",
  "ovmf_code": {
    "path": "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "sha256": "a5708766c49ee39db0f4e7e53d73376e2dbc0d45bf12501c0977c48412bf8902"
  },
  "ovmf_vars_template": {
    "path": "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "sha256": "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"
  },
  "guest_memory_mib": 4096,
  "guest_cpus": 4,
  "timeout_seconds": 300
}
```

`boot_report.py` also exposes `load_qemu_lock`, `validate_qemu_lock`, and `verify_qemu_host`. Structural validation requires exactly the shown fields, syntactically absolute firmware paths, lowercase raw SHA-256 values, machine `q35`, QEMU `10.2.1`, memory `4096`, CPUs `4`, and timeout `300`; it is safe on a hosted unit-test runner without OVMF. `verify_qemu_host`, called only by full preflight/boot, requires the paths to be regular files, verifies both hashes and the installed QEMU version, and saves full `qemu-system-x86_64 --version` output.

- [ ] **Step 4: Implement strict serial extraction and expectation matching**

`tools/gate01/boot_report.py` supports:

```text
python3 -m tools.gate01.boot_report expectations --builder BUILDER_ID --output JSON
python3 -m tools.gate01.boot_report verify --serial LOG --expectations JSON --output JSON
python3 -m tools.gate01.boot_report verify-qemu-lock os/build/qemu.lock.json
```

`expectations` accepts only the three builder IDs, loads source/config/toolchain/module-key/payload evidence, and emits exact expected values for every identity field. It obtains `bootc_image_digest` from that builder's computed OCI `manifest_digest`; no expected digest is embedded into the image, avoiding an impossible self-reference.

`verify` parses the one prefixed line with `json.loads`, rejects non-object data and duplicate keys through `object_pairs_hook`, requires exactly the sorted key set defined in Task 7, and compares the report to expectations. Its output is the accepted report plus `verified: true`; it serializes atomically and prints `Gate 01 boot report verified` only after the file is durable.

- [ ] **Step 5: Implement a disk-safe UEFI QEMU harness**

`scripts/gate01/boot-qemu.sh BUILDER_ID` refuses root, validates `BUILDER_ID`, the QEMU lock, and the builder's QCOW evidence. It creates `build/gate01/BUILDER_ID/qemu/run-<UTC-seconds>-<pid>/`, then:

1. copies `OVMF_VARS_4M.fd` to `OVMF_VARS.fd` and chmods the copy `0600`;
2. creates `disk-overlay.qcow2` with `qemu-img create -f qcow2 -F qcow2 -b <absolute-read-only-base>`, then rechecks the backing filename and format through `qemu-img info --backing-chain --output=json`;
3. generates `expectations.json`;
4. selects KVM with CPU `host` only when `/dev/kvm` is readable/writable and `qemu-system-x86_64 -accel help` lists `kvm`; otherwise selects TCG with CPU `max`;
5. records a shell-escaped command array to `qemu-command.txt` without executing a shell string.

The QEMU argument array is exactly the selected accelerator/CPU plus:

```text
-machine q35
-smp 4
-m 4096
-nodefaults
-drive if=pflash,format=raw,unit=0,readonly=on,file=<locked-OVMF-CODE>
-drive if=pflash,format=raw,unit=1,file=<copied-OVMF-VARS>
-drive if=none,id=stone,format=qcow2,readonly=off,file=<overlay>
-device virtio-blk-pci,drive=stone,bootindex=1
-chardev file,id=serial0,path=<serial.log>
-device isa-serial,chardev=serial0
-display none
-monitor none
-nic none
-no-reboot
```

Invoke it through `timeout --signal=TERM --kill-after=10s 300s`. Exit `0` is required, indicating the report service powered the guest off; timeout or QEMU error fails. The harness then runs the report verifier. It retains the overlay/variable store for diagnosis on failure and marks them disposable in `qemu-run.json`; it never uses `-snapshot` as a substitute for the explicit verified overlay.

- [ ] **Step 6: Boot both independently built disks**

Run:

```bash
scripts/gate01/boot-qemu.sh builder-a
scripts/gate01/boot-qemu.sh builder-b
```

Expected for each: QEMU exits before 300 seconds, the serial log contains exactly one prefixed report, the report says UEFI/multi-user/OpenMythos/exact kernel/enforced modules/integrity lockdown, and its bootc digest matches that builder's OCI manifest digest.

Run: `qemu-img check build/gate01/builder-a/qcow2/openmythos-gate01.qcow2`

Expected: the base remains clean after boot because only its overlay was writable.

- [ ] **Step 7: Prove bad and duplicate evidence fails**

Run the verifier against `serial-wrong-kernel.log` and `serial-duplicate-report.log` with the valid expectation fixture.

Expected: both exit nonzero with their specific error; neither writes an accepted `boot-report.json`.

Run: `python3 -m unittest tests.gate01.test_boot_report -v`

Expected: all parser/lock/expectation tests pass.

- [ ] **Step 8: Commit the UEFI proof harness**

```bash
git add Makefile os/build/qemu.lock.json tools/gate01/boot_report.py \
  scripts/gate01/boot-qemu.sh tests/gate01/test_boot_report.py \
  tests/gate01/fixtures/serial-*.log
git commit -m "test: prove Gate 01 identity under UEFI QEMU"
```

### Task 10: Aggregate the two-builder proof into one fail-closed release gate

**Files:**
- Create: `os/build/reproducibility-allowlist.json`
- Create: `os/build/schemas/gate01-evidence.schema.json`
- Create: `tools/gate01/evidence.py`
- Create: `scripts/gate01/repro-check.sh`
- Create: `scripts/gate01/release-gate.sh`
- Create: `tests/gate01/test_evidence.py`
- Create: `tests/gate01/fixtures/evidence-pass.json`
- Create: `tests/gate01/fixtures/evidence-failed-comparison.json`
- Modify: `Makefile`

**Interfaces:**
- Consumes: every locked input, artifact report, A/B comparison, and accepted boot report from Tasks 2–9.
- Produces: `build/gate01/evidence/gate01-evidence.json`, a schema-validation receipt, SHA-256 checksum list, and final exit `0` only when every hard invariant is green.

- [ ] **Step 1: Write failing evidence-policy tests**

`tests/gate01/test_evidence.py` loads the pass and failed fixtures and asserts:

- `validate_evidence` accepts the complete pass object;
- a nested comparison verdict other than `pass` forces the top-level verdict to fail;
- missing A or B build/boot evidence is rejected;
- unknown keys are rejected recursively;
- a raw binary RPM difference fails unless it exactly matches a reviewed allowlist entry;
- a QCOW wrapper difference is retained but does not fail when normalized content matches;
- any string containing `PRIVATE KEY`, `BEGIN RSA`, an authorization bearer token, or a path outside the repository fails the secret/path scan;
- assembly orders maps deterministically and produces the same bytes from inputs discovered in different filesystem orders.

- [ ] **Step 2: Run tests and confirm the evidence API is absent**

Run: `python3 -m unittest tests.gate01.test_evidence -v`

Expected: `ERROR` because `tools.gate01.evidence` does not exist.

- [ ] **Step 3: Make reproducibility exceptions explicit and initially empty**

```json
{
  "schema_version": 1,
  "binary_rpm_differences": []
}
```

Each future entry must contain exactly `nevra`, `left_sha256`, `right_sha256`, `differing_header_tags`, `cause`, `reviewed_by`, and `review_commit`. Hashes and a nonempty cause are mandatory; `review_commit` must be a 40-character Git object ID reachable from `HEAD`. No wildcard is permitted. Gate 01 starts with no exception, so a binary RPM byte difference fails until its metadata-only cause is isolated, documented, reviewed, and committed. SRPM, installed files, module signatures, OCI descriptors, and normalized disk contents can never be allowlisted.

- [ ] **Step 4: Define the exact evidence object and JSON Schema**

Use JSON Schema Draft 2020-12 with `$id` `https://openmythos.dev/schemas/gate01-evidence.schema.json`. Every object sets `additionalProperties: false`. Define `$defs.rawSha256` as `^[0-9a-f]{64}$`, `$defs.ociDigest` as `^sha256:[0-9a-f]{64}$`, `$defs.kernelRelease` as the literal `6.18.48-1.openmythos.fc44.x86_64`, and `$defs.verdict` as the enum `pass` or `fail`. The schema validates evidence shape for both outcomes; the separate release-policy validator permits publication only for `pass`.

The root requires exactly:

```text
schema_version, gate, generated_at, source_date_epoch, repository_commit,
source, config, toolchain, module_identity, builders, comparisons,
boot_proofs, safety, artifacts, verdict
```

Their exact contracts are:

- `schema_version=1`, `gate="01"`, `source_date_epoch=1787899659`, and `verdict` matching `$defs.verdict`; release-policy validation requires `verdict="pass"`;
- `generated_at` is a UTC RFC 3339 timestamp and `repository_commit` is 40 lowercase hex;
- `source` requires version, archive/signature SHA-256, signer fingerprint, signature verification boolean, and empty patch array;
- `config` requires kernel release, config SHA-256, requirements SHA-256, audit verdict, and unresolved-symbol count `0`;
- `toolchain` requires digest-qualified image reference, manifest digest, archive SHA-256, and inventory SHA-256;
- `module_identity` requires public certificate/SPKI SHA-256 and `development_only=true`; it cannot contain a private-key path;
- `builders` has exactly `builder-a` and `builder-b`, each requiring SRPM/RPM/payload/QCOW report SHA-256 values;
- `comparisons` has exactly `srpm`, `installed_rpm_files`, `binary_rpm_metadata`, `oci`, and `qcow2_immutable`; each comparison is shape-valid with `pass` or `fail`, while release policy requires `pass` for all except an explicitly reviewed binary metadata object;
- `boot_proofs` has exactly `builder-a` and `builder-b`, each containing the accepted Task 9 report and serial-log SHA-256;
- `safety` requires `physical_devices_attached=false`, `base_qcow_mutated=false`, `network_used_after_fetch=false`, `private_key_embedded=false`, `secure_boot_claimed=false`, and `gate_scope="qemu-uefi-only"`;
- `artifacts` contains repository-relative regular-file paths and SHA-256 for the A/B SRPMs, all A/B binary kernel RPMs, A/B OCI archives, A/B QCOW2 files, image-builder bootc-inspect reports, osbuild manifests, SPDX SBOMs, comparison files, and boot logs.

The schema uses `required` for every listed member and `minItems` for the artifact list. `tools/gate01/evidence.py schema-check` invokes `jsonschema.Draft202012Validator.check_schema` and then `validate`. It runs inside the locked toolchain image, where Task 3 installed `python3-jsonschema`; no package is resolved during the release gate.

- [ ] **Step 5: Implement evidence assembly and policy validation**

`tools/gate01/evidence.py` supports:

```text
python3 -m tools.gate01.evidence assemble --build-root DIR --output JSON
python3 -m tools.gate01.evidence validate --evidence JSON --allowlist JSON
python3 -m tools.gate01.evidence checksums --evidence JSON --output FILE
python3 -m tools.gate01.evidence schema-check --schema JSON --evidence JSON
```

`assemble` opens files by an exact repository-relative allowlist, rejects symlinks, and verifies each file remains beneath `build/gate01/` after resolution. It re-runs each domain validator rather than trusting stored `verdict` text. It calculates evidence-file/artifact SHA-256 values, captures `git rev-parse HEAD`, uses the current UTC time only for `generated_at`, and writes canonical sorted/indented JSON atomically.

`validate` walks every key/value recursively, enforces the policy above, verifies every artifact still has its recorded hash, checks the optional RPM-difference allowlist against Git, rejects secret markers case-insensitively, and exits nonzero without rewriting evidence on failure. `checksums` emits sorted two-space SHA-256 lines for releasable OCI/QCOW/SBOM/manifest artifacts plus the evidence JSON itself; it never includes a key, writable overlay, OVMF variable store, container graphroot, or cache file.

- [ ] **Step 6: Implement the focused A/B reproducibility command**

`scripts/gate01/repro-check.sh` refuses root and refuses to run while either builder process lock is held. It calls, in order:

1. source/config/toolchain/module-key validators;
2. RPM compare for builder A/B;
3. OCI compare for builder A/B;
4. QCOW compare for builder A/B;
5. boot-report verification for both builders;
6. evidence validation of all comparison JSON.

It writes `build/gate01/compare/repro-summary.json` only after every command succeeds. That file has exact keys `schema_version`, `srpm`, `installed_rpm_files`, `binary_rpm_metadata`, `oci`, `qcow2_immutable`, `boot_reports`, and `verdict`; every hard value is `pass`. A trap writes `repro-failure.json` with the failed step and exit code but never converts a failure to success.

- [ ] **Step 7: Implement the ordered release-gate entry point**

`scripts/gate01/release-gate.sh` must be launched as the normal developer account. It acquires a nonblocking `flock` on `build/gate01/release.lock`, records start time and commit, and performs this exact sequence:

```text
make gate01-unit
validate os/build/inputs.lock.json, os/kernel/source.lock.json, toolchain lock, and QEMU lock
scripts/gate01/fetch-inputs.sh
verify the cached toolchain archive against os/build/toolchain.lock.json
scripts/gate01/generate-config.sh --check
verify the existing development module key and module-key.json from Task 5
scripts/gate01/build-kernel.sh builder-a
scripts/gate01/build-kernel.sh builder-b
compare RPM evidence
sudo scripts/gate01/build-payload.sh builder-a
sudo scripts/gate01/build-payload.sh builder-b
compare OCI evidence
sudo scripts/gate01/build-qcow2.sh builder-a
sudo scripts/gate01/build-qcow2.sh builder-b
compare QCOW evidence
scripts/gate01/boot-qemu.sh builder-a
scripts/gate01/boot-qemu.sh builder-b
scripts/gate01/repro-check.sh
assemble evidence
validate evidence and its Draft 2020-12 schema inside the locked toolchain
generate SHA256SUMS
```

Before the first build, it checks at least 120 GiB free below the repository, verifies required executables, and requires the Gate 01 tracked inputs to match `HEAD`; unrelated tracked work such as `open_mythos/main.py` is neither inspected nor staged. It prints the exact missing executable/package mapping on preflight failure. It does not build the toolchain automatically: a missing/mismatched locked archive stops with the documented Task 3 provisioning command. It preserves all diagnostic output on failure and never publishes artifacts.

The final two lines on success are exactly:

```text
GATE01_VERDICT=pass
GATE01_EVIDENCE=build/gate01/evidence/gate01-evidence.json
```

- [ ] **Step 8: Exercise success and deliberate failure paths**

Run: `python3 -m unittest tests.gate01.test_evidence -v`

Expected: all strict-schema, recursive-policy, deterministic-ordering, and secret-scan tests pass.

Run the validator against `evidence-failed-comparison.json`.

Expected: nonzero exit identifying the failed comparison; no `SHA256SUMS` is produced.

After Tasks 2–9 have produced their artifacts, run: `scripts/gate01/release-gate.sh`

Expected: the last two lines are the exact success markers above and the evidence schema validation receipt has `valid: true`.

- [ ] **Step 9: Commit the release policy and orchestrator**

```bash
git add Makefile os/build/reproducibility-allowlist.json \
  os/build/schemas/gate01-evidence.schema.json tools/gate01/evidence.py \
  scripts/gate01/repro-check.sh scripts/gate01/release-gate.sh \
  tests/gate01/test_evidence.py tests/gate01/fixtures/evidence-*.json
git commit -m "build: enforce the Stone Boot Proof release gate"
```

### Task 11: Document, automate, and perform final Gate 01 acceptance

**Files:**
- Create: `docs/operations/gate01-stone-boot-proof.md`
- Create: `.github/workflows/gate01.yml`
- Create: `scripts/gate01/preflight.sh`
- Create: `tests/gate01/test_repository_contract.py`
- Modify: `scripts/gate01/release-gate.sh`
- Modify: `Makefile`

**Interfaces:**
- Consumes: a clean implementation of Tasks 1–10 plus a provisioned privileged x86_64 Linux runner.
- Produces: a fast unprivileged pull-request job, a manually invoked full-gate job, an operator runbook, and a final reviewed evidence bundle. It does not publish a release or write physical media.

- [ ] **Step 1: Write failing whole-repository contract tests**

`tests/gate01/test_repository_contract.py` verifies:

- every planned file in the Repository Map exists and every shell entry point is executable;
- every shell script begins with Bash plus `set -Eeuo pipefail` before operational commands;
- no Gate 01 Containerfile contains an unqualified `FROM`, moving tag, `dnf update`, `curl`, or network package repository use;
- every locked digest has the required shape and all JSON lock/schema files reject duplicate keys;
- the Gate 01 scope contains no `nvidia`, `hyprland`, `quickshell`, `codex`, `claude`, provider token, installer, MOK-enrollment, update, rollback, or physical-write implementation (documentation references explaining deferral are allowed through an exact path/line allowlist in the test);
- no command token passed by a QEMU/image-builder script is a physical block-device path;
- no Gate 01 script, Make target, commit path list, or generated evidence path names `open_mythos/**`; the test does not compare against an unstable branch point or reject unrelated user changes;
- repository files contain no private key marker and no tracked generated artifact suffix.

- [ ] **Step 2: Run the contract test and confirm missing documentation/CI is reported**

Run: `python3 -m unittest tests.gate01.test_repository_contract -v`

Expected: failures name the missing runbook, workflow, and preflight script.

- [ ] **Step 3: Add an exact preflight with actionable package mapping**

`scripts/gate01/preflight.sh` is read-only and accepts `--fast` or `--full`. Both modes require Bash, Git, Python 3.12 or newer, Make, jq, curl, GnuPG, OpenSSL, xz, SHA-256 tools, and at least 20 GiB free. Full mode additionally requires Podman, Buildah, Skopeo, QEMU x86_64, qemu-img, OVMF, libguestfs (`guestfish`, `virt-filesystems`), `flock`, `timeout`, KVM-or-TCG availability, and 120 GiB free. It verifies rootless Podman works, `sudo podman info` works for the full gate, and the two OVMF hashes match. On CI it also read-checks the fixed toolchain/key files under `/var/lib/openmythos-gate01/`; on a developer run it checks the already staged cache/key files under `build/gate01/`. It must not install packages, copy keys, or mutate container storage.

On this Ubuntu development host, the runbook's one-time installation command is:

```bash
sudo apt-get update
sudo apt-get install -y podman buildah skopeo qemu-system-x86 qemu-utils \
  ovmf libguestfs-tools jq gnupg openssl curl make shellcheck
```

RPM build tools, dracut, and JSON Schema validation remain inside the digest-locked Fedora toolchain/payload; the host does not need `rpmbuild`, `mock`, `bootc`, or image-builder installed.

- [ ] **Step 4: Write the operator runbook**

`docs/operations/gate01-stone-boot-proof.md` must contain these sections with copy/paste commands and expected terminal markers:

1. scope and explicit non-goals;
2. host requirements and the installation command above;
3. rootless Podman/subuid verification and rootful Podman approval boundary;
4. source/key/OCI input verification;
5. one-time toolchain creation, inspection, and lock commit;
6. final config generation/review;
7. development module-key handling and destruction warning, including that local runs create it once with Task 5 while CI stages a fixed identity from the runner-only `/var/lib/openmythos-gate01/` cache and verifies the public SPKI before use;
8. full `make gate01` execution;
9. evidence and log locations;
10. interpreting hard versus advisory reproducibility fields;
11. safe rerun of one builder;
12. failure recovery that preserves logs;
13. scoped cleanup commands which first resolve and print the exact directory below `build/gate01/` and require interactive confirmation;
14. explicit statement that no physical disk, ISO, Secure Boot/MOK, desktop, NVIDIA, Codex, Claude, or Hermes integration is part of Gate 01;
15. escalation path: stop on unexplained differences; do not weaken a hard comparison or add an allowlist entry without review.

- [ ] **Step 5: Add split GitHub Actions coverage**

`.github/workflows/gate01.yml` uses `permissions: contents: read`, cancels superseded PR runs, and defines:

- `static-and-unit` on `pull_request`, `push`, and `workflow_dispatch`, using a current Ubuntu hosted runner. It checks out by commit, installs only `shellcheck` and `jq`, runs `scripts/gate01/preflight.sh --fast`, `make gate01-unit`, `shellcheck scripts/gate01/*.sh`, `git diff --check`, the private-key scan, and the placeholder scan from Final Review below.
- `full-stone-boot-proof` only on `workflow_dispatch` and only on labels `[self-hosted, linux, x64, openmythos-gate01]`. It has a six-hour timeout, runs `preflight.sh --full`, requires `/var/lib/openmythos-gate01/kernel-builder.oci.tar` to match the committed toolchain lock, and stages the runner's fixed `module-signing.key`, `module-signing.pem`, and `module-signing.x509` into ignored mode-`0700` `build/gate01/secrets/` with modes `0600/0644/0644`. It regenerates `module-key.json`, verifies the public certificate/SPKI against the runner's approved public manifest, runs `make gate01`, uploads `build/gate01/evidence`, both SRPM/RPM sets, both OCI descriptor reports, both image-builder bootc-inspect reports, both osbuild manifests/SBOMs, both serial logs, and both QCOW metadata reports for 30 days, and never uploads the module key, mutable overlays, OVMF variable stores, container storage, or source cache.

The full job checks available disk before work and always uploads bounded diagnostic text/JSON on failure. It does not use a GitHub release, registry push, artifact signing, or physical runner disk other than the repository workspace and container graphroots.

- [ ] **Step 6: Wire final commands and run fast verification**

Make `gate01` call only `scripts/gate01/release-gate.sh`; the release script owns the single `gate01-unit` invocation at the start of its ordered sequence. Add `gate01-preflight` and `gate01-preflight-full` targets.

Run:

```bash
scripts/gate01/preflight.sh --fast
make gate01-unit
shellcheck scripts/gate01/*.sh
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 7: Run the complete acceptance gate on the provisioned runner**

Run: `scripts/gate01/preflight.sh --full`

Run: `make gate01`

Expected: `GATE01_VERDICT=pass`, schema-valid evidence, two accepted UEFI boot reports, and no physical-device argument in the captured command evidence.

Review these exact hard fields before acceptance:

```text
source signature and fingerprint: pass
config audit/unresolved symbols: pass/0
SRPM SHA-256 A == B
installed RPM file manifest A == B
OCI manifest/config/layers A == B
normalized immutable QCOW content A == B
UEFI QEMU boot identity A and B: pass
top-level verdict: pass
```

- [ ] **Step 8: Commit CI and operational acceptance**

```bash
git add Makefile .github/workflows/gate01.yml \
  docs/operations/gate01-stone-boot-proof.md scripts/gate01/preflight.sh \
  scripts/gate01/release-gate.sh tests/gate01/test_repository_contract.py
git commit -m "ci: automate Stone Boot Proof acceptance"
```

## Primary Implementation References

- bootc image contract and kernel layout: <https://bootc.dev/bootc/bootc-images.html>
- bootc status format-version contract: <https://bootc.dev/bootc/man/bootc-status.8.html>
- unified image-builder bootc workflow: <https://osbuild.org/docs/developer-guide/projects/image-builder/usage/>
- image-builder container installation: <https://osbuild.org/docs/developer-guide/projects/image-builder/installation/>
- bootc QCOW2 customization allowlist: <https://osbuild.org/docs/user-guide/image-descriptions/bootc/qcow2/>
- kernel release-signature verification: <https://www.kernel.org/signature.html>
- kernel reproducible-build controls: <https://docs.kernel.org/kbuild/reproducible-builds.html>
- kernel module-signing contract: <https://docs.kernel.org/admin-guide/module-signing.html>
- RPM build process and reproducibility macros: <https://rpm.org/docs/4.20.x/manual/buildprocess.html>
- OCI descriptor and layer identity: <https://github.com/opencontainers/image-spec/blob/main/descriptor.md> and <https://github.com/opencontainers/image-spec/blob/main/layer.md>
- QEMU image comparison semantics: <https://www.qemu.org/docs/master/tools/qemu-img.html>

## Final Review

- [ ] Read this plan and the approved architecture side by side. Confirm every Gate 01 sentence is implemented and every Gate 02–06 feature remains absent.
- [ ] Run `rg -n 'TB[D]|TO[D]O|FIXM[E]|X[X]X|implement late[r]|Add appropriat[e]|add validatio[n]|handle edge case[s]|Write tests fo[r]|Similar t[o]' .github os scripts tools tests docs/operations` and require no result outside quoted negative-test data.
- [ ] Run `python3 -m unittest discover -s tests/gate01 -p 'test_*.py' -v` and require zero failures/skips.
- [ ] Run `shellcheck scripts/gate01/*.sh` and require zero findings.
- [ ] Run `python3 -m compileall -q tools/gate01 tests/gate01` and require exit `0`.
- [ ] Run `git diff --check` and require no whitespace errors.
- [ ] Run `git status --short`, verify generated/key/disk/container artifacts are ignored, and verify no existing `open_mythos/` file was staged.
- [ ] On the privileged runner, run `make gate01` and retain `gate01-evidence.json`, `SHA256SUMS`, comparison reports, osbuild manifests, SPDX SBOMs, serial logs, and tool versions.
- [ ] Re-read the accepted boot reports and verify their payload digest equals the OCI manifest digest rather than an archive hash or tag.
- [ ] Record Gate 01 complete only after the schema-valid evidence says `verdict: "pass"`; otherwise preserve evidence, fix the invariant, and rerun both clean builders.
