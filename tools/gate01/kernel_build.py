"""Fail-closed supervisor for the Gate 01 kernel RPM build and proof workflow."""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager, ExitStack
import errno
import fcntl
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

# Production supervisor entry is possible only from the sealed bootstrap ZIP.
# Unit tests import this package normally; descriptor workers use the verifier
# capsule's package-aware runpy entry.  Direct mutable-path execution must stop
# before importing any repository package.
if __package__ in (None, ""):
    print("kernel supervisor requires sealed bootstrap entry", file=sys.stderr)
    raise SystemExit(2)

from tools.gate01.proof_io import (
    _add_cleanup_note,
    SOURCE_DATE_EPOCH,
    VERIFIER_FD,
    PUBLIC_CERTIFICATE_FD,
    BUILD_KEY_FD,
    BUILD_RESULT_FD,
    ARTIFACT_FD_ROLES,
    EVIDENCE_FD_ROLES,
    RECEIPT_SCHEMA_VERSION,
    RECEIPT_PROTOCOL,
    HASH_CHUNK_SIZE,
    OCI_ARCHIVE_FD,
    RUNTIME_CONTAINERENV_FD,
    SOURCE_ARCHIVE_FD,
    CONFIG_FD,
    SPEC_FD,
    INPUT_AUDIT_FD_ROLES,
    EXPECTED_RPM_FILENAMES,
    ArtifactSet,
    AnonymousOutputs,
    ArtifactSlots,
    BoundInputs,
    BoundScopedDiff,
    InputMetadataPolicy,
    BoundAcceptedTree,
    FixedDescriptors,
    ReceiptError,
    SealedCapsule,
    SealedSecret,
    _DescriptorResource,
    _acquire_read_lease,
    _assert_artifact_writer_custody,
    _canonical_json,
    _copy_descriptor_to_path,
    _directory_names,
    _expected_tree_paths,
    _best_effort_release,
    _post_receipt_warning,
    _fsync_tree,
    _hash_descriptor,
    _json_object_descriptor,
    _json_safe,
    _load_receipt,
    _object_sha256,
    _owned_resource,
    _close_resource_preserving_primary,
    _drain_bound_inputs,
    _drain_bound_scoped_diff,
    _drain_bound_accepted_tree,
    _drain_sealed_capsule,
    _drain_sealed_secret,
    _drain_descriptor_resource,
    _drain_artifact_set,
    _drain_artifact_slots,
    _drain_anonymous_outputs,
    _open_parent_directory,
    _publish_build_log,
    _publish_descriptor,
    _publish_receipt,
    _read_descriptor,
    _remove_scoped_path,
    _rename_noreplace,
    _require_direct_child,
    _require_sealed_regular_descriptor,
    _release_all,
    _close_descriptors,
    _close_descriptor_sequence,
    _release_preserving_primary,
    _safe_relative,
    _scan_artifacts_with_capsule,
    _scan_tree_with_capsule,
    _stat_identity,
    _stat_version,
    _tree_manifest,
    _bound_public_tree,
    _write_descriptor_exact,
    _write_public_file,
    build_verifier_capsule,
    complete_output_scan,
    copy_public_to_sealed_memfd,
    copy_secret_to_sealed_memfd,
    create_detached_receipt,
    export_exact_rpm_set,
    publish_candidate as _publish_candidate_impl,
    publish_evidence_file,
    run_verifier_capsule,
    seal_public_bytes,
    validate_detached_receipt,
    validate_evidence_receipt,
)
from tools.gate01.kernel_bootstrap import (
    AUTHORITY_FD as BOOTSTRAP_AUTHORITY_FD,
    BOOTSTRAP_SOURCE_PATHS,
    CAPSULE_FD as BOOTSTRAP_CAPSULE_FD,
)
from tools.gate01.container_runtime import (
    EXPECTED_MASKED_PATHS,
    EXPECTED_READONLY_PATHS,
    ContainerLifecycleError,
    BoundScratch,
    _drain_bound_scratch,
    _drain_podman_policy,
    _drain_container_backend,
    PodmanContainerBackend,
    SealedPodmanPolicy,
    PodmanStore,
    _attest_live_container,
    _lifecycle_exec_check,
    _load_json_bytes,
    _oci_summary_fixed,
    _projection_from_record,
    _remove_podman_store,
    _rootfs_audit_worker,
    _verify_live_mountinfo,
    _PODMAN_CONTAINERS_CONF,
    _PODMAN_STORAGE_CONF,
    assert_rootfs_audit_records_equal,
    controlled_environment,
    create_rootfs_audit_record,
    podman_create_arguments,
    run_container_lifecycle,
    validate_effective_oci_spec,
    validate_live_process_record,
    validate_live_mount_graph,
)
from tools.gate01.rpm_artifacts import (
    compare_rpm_manifests,
    validate_rpm_manifest,
)

VERIFIER_RELATIVE_PATHS = (
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
_EXECUTED_BOOTSTRAP_AUTHORITY: dict[str, Any] | None = None
_EXECUTED_BOOTSTRAP_CAPSULE_SHA256: str | None = None
_EXECUTED_BOOTSTRAP_AUTHORITY_SHA256: str | None = None
PUBLIC_OUTPUT_FILES = {
    "rpmbuild/SRPMS/kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm": "source-rpm",
    "rpmbuild/RPMS/x86_64/kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm": "meta-rpm",
    "rpmbuild/RPMS/x86_64/kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm": "core-rpm",
    "rpmbuild/RPMS/x86_64/kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm": "modules-rpm",
    "rpm-artifacts.json": "rpm-manifest",
    "installed-files.json": "installed-files",
    "build.log": "build-log",
    "compiler-version.txt": "compiler-version",
    "build-report.json": "build-report",
    "source-capsule.json": "source-capsule",
    "rootfs-audit.json": "rootfs-audit",
    "container-contract.json": "container-contract",
    "leakage-scan.json": "leakage-scan",
}


def publish_candidate(
    candidate: Path,
    final: Path,
    receipt: Path,
    receipt_value: Mapping[str, Any],
    *,
    expected_uid: int,
    expected_gid: int,
    before_receipt: Callable[[], None] | None = None,
) -> None:
    """Compatibility adapter preserving the original kernel module patch points."""
    _publish_candidate_impl(
        candidate,
        final,
        receipt,
        receipt_value,
        rename_noreplace=_rename_noreplace,
        publish_receipt=_publish_receipt,
        before_receipt=before_receipt,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )

def _parse_kernel_config_bytes(value: bytes) -> dict[str, str]:
    assignment = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.+)$")
    not_set = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
    result: dict[str, str] = {}
    try:
        lines = value.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("kernel config must be ASCII") from error
    for line_number, line in enumerate(lines, start=1):
        match = assignment.fullmatch(line)
        absent = not_set.fullmatch(line)
        if match:
            name, configured = match.groups()
        elif absent:
            name, configured = absent.group(1), "n"
        elif not line or line.startswith("#"):
            continue
        else:
            raise ValueError(f"malformed kernel config line {line_number}")
        if name in result:
            raise ValueError(f"duplicate kernel config symbol: {name}")
        result[name] = configured
    return result


def _validate_private_key_descriptor(descriptor: int) -> None:
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise ValueError("private key descriptor is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_uid != os.geteuid()
        or status.st_nlink != 1
    ):
        raise ValueError("private key descriptor metadata is unsafe")


def audit_input_descriptors(
    descriptors: Mapping[str, int],
    *,
    certificate_descriptor: int,
) -> dict[str, Any]:
    """Validate the exact held Gate 01 build-input schema and relationships."""
    if set(descriptors) != set(INPUT_AUDIT_FD_ROLES):
        raise ValueError("input descriptor roles are not exact")
    source_lock = _json_object_descriptor(descriptors["source_lock"], "source lock")
    source_fields = {
        "schema_version", "product", "version", "archive_url",
        "archive_sha256", "signature_url", "signature_sha256",
        "signer_fingerprint", "source_date_epoch", "patches",
    }
    if set(source_lock) != source_fields:
        raise ValueError("source lock schema is not exact")
    if (
        source_lock["schema_version"] != 1
        or source_lock["product"] != "linux-openmythos"
        or source_lock["version"] != "6.18.48"
        or source_lock["source_date_epoch"] != SOURCE_DATE_EPOCH
        or source_lock["patches"] != []
    ):
        raise ValueError("source lock identity is not exact")
    source_sha256 = _hash_descriptor(descriptors["source_archive"])
    if source_lock["archive_sha256"] != source_sha256:
        raise ValueError("source archive differs from source lock")

    toolchain_lock = _json_object_descriptor(
        descriptors["toolchain_lock"], "toolchain lock"
    )
    toolchain_fields = {
        "schema_version", "architecture", "image_reference", "manifest_digest",
        "archive_sha256", "commands", "installed_rpms",
    }
    if set(toolchain_lock) != toolchain_fields:
        raise ValueError("toolchain lock schema is not exact")
    manifest_digest = toolchain_lock.get("manifest_digest")
    if (
        toolchain_lock.get("schema_version") != 1
        or toolchain_lock.get("architecture") != "x86_64"
        or not isinstance(manifest_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is None
        or not str(toolchain_lock.get("image_reference", "")).endswith(
            "@" + manifest_digest
        )
        or toolchain_lock.get("archive_sha256")
        != _hash_descriptor(descriptors["toolchain_archive"])
    ):
        raise ValueError("toolchain archive/identity differs from lock")
    commands = toolchain_lock.get("commands")
    if not isinstance(commands, dict) or set(commands) != {
        "gcc", "ld", "make", "python3", "rpm", "rpmbuild"
    }:
        raise ValueError("toolchain command inventory is not exact")
    rpms = toolchain_lock.get("installed_rpms")
    if not isinstance(rpms, list) or rpms != sorted(set(rpms)):
        raise ValueError("toolchain RPM inventory is not sorted and unique")

    config_bytes = _read_descriptor(descriptors["config"])
    config_sha256 = hashlib.sha256(config_bytes).hexdigest()
    checksum = _read_descriptor(descriptors["config_checksum"])
    expected_checksum = (
        f"{config_sha256}  6.18.48-x86_64.config\n".encode("ascii")
    )
    if checksum != expected_checksum:
        raise ValueError("kernel config checksum file is not exact")
    requirements = _json_object_descriptor(
        descriptors["config_requirements"], "kernel config requirements"
    )
    if set(requirements) != {
        "schema_version", "kernel_version", "kernel_release", "required"
    } or (
        requirements.get("schema_version") != 1
        or requirements.get("kernel_version") != "6.18.48"
        or requirements.get("kernel_release")
        != "6.18.48-1.openmythos.fc44.x86_64"
        or not isinstance(requirements.get("required"), dict)
    ):
        raise ValueError("kernel config requirements schema is not exact")
    parsed_config = _parse_kernel_config_bytes(config_bytes)
    for name, expected in requirements["required"].items():
        if parsed_config.get(name) != expected:
            raise ValueError(f"kernel config requirement mismatch: {name}")

    public_manifest = _json_object_descriptor(
        descriptors["public_manifest"], "public certificate manifest"
    )
    from tools.gate01.module_key import describe_descriptor

    if describe_descriptor(certificate_descriptor) != public_manifest:
        raise ValueError("public certificate differs from its manifest")
    return {
        "certificate_sha256": public_manifest["certificate_sha256"],
        "commands": commands,
        "config_sha256": config_sha256,
        "kernel_release": requirements["kernel_release"],
        "source_archive_sha256": source_sha256,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "toolchain_archive_sha256": toolchain_lock["archive_sha256"],
        "toolchain_config_expected": None,
        "toolchain_image_reference": toolchain_lock["image_reference"],
        "toolchain_manifest_digest": manifest_digest,
    }
def gate01_input_paths(repository: Path) -> dict[str, Path]:
    repository = Path(os.path.abspath(repository))
    gate = repository / "build/gate01"
    result = {
        "source_lock": repository / "os/kernel/source.lock.json",
        "toolchain_lock": repository / "os/build/toolchain.lock.json",
        "source_archive": gate / "cache/sources/linux-6.18.48.tar.xz",
        "toolchain_archive": gate / "cache/kernel-builder.oci.tar",
        "config": repository / "os/kernel/config/6.18.48-x86_64.config",
        "config_checksum": repository / "os/kernel/config/6.18.48-x86_64.config.sha256",
        "config_requirements": repository / "os/kernel/config/requirements.json",
        "public_certificate": gate / "secrets/module-signing.pem",
        "public_manifest": gate / "secrets/module-key.json",
        "private_key": gate / "secrets/module-signing.key",
        "spec": repository / "os/kernel/packaging/kernel-openmythos.spec",
        "scripts/gate01/build-kernel.sh": repository / "scripts/gate01/build-kernel.sh",
    }
    result.update({relative: repository / relative for relative in VERIFIER_RELATIVE_PATHS})
    return result


def _input_policies(
    paths: Mapping[str, Path],
    *,
    public_manifest_mode: int = 0o600,
) -> dict[str, InputMetadataPolicy]:
    """Return the complete exact per-role input metadata contract."""
    uid = os.geteuid()
    gid = os.getegid()
    result: dict[str, InputMetadataPolicy] = {}
    for label in paths:
        if label == "scripts/gate01/build-kernel.sh":
            mode = 0o755
        elif label in {"private_key", "public_manifest"}:
            mode = 0o600 if label == "private_key" else public_manifest_mode
        else:
            mode = 0o644
        result[label] = InputMetadataPolicy(mode=mode, uid=uid, gid=gid)
    return result


def _executed_capsule_from_bound_inputs(inputs: BoundInputs) -> SealedCapsule:
    """Rebind bootstrap evidence to live held sources and duplicate its capsule."""
    authority = _EXECUTED_BOOTSTRAP_AUTHORITY
    expected_capsule = _EXECUTED_BOOTSTRAP_CAPSULE_SHA256
    if authority is None or expected_capsule is None:
        raise RuntimeError("production command did not enter through sealed bootstrap")
    input_hashes = inputs.verify_coherent()
    for relative in BOOTSTRAP_SOURCE_PATHS:
        record = authority["files"][relative]
        status = inputs.status(relative)
        if (
            input_hashes.get(relative) != record["sha256"]
            or status.st_size != record["size"]
            or f"{stat.S_IMODE(status.st_mode):04o}" != record["mode"]
        ):
            raise RuntimeError(
                f"executed bootstrap source differs from held input: {relative}"
            )
    _require_sealed_regular_descriptor(
        BOOTSTRAP_CAPSULE_FD, "executed bootstrap capsule"
    )
    if _hash_descriptor(BOOTSTRAP_CAPSULE_FD) != expected_capsule:
        raise RuntimeError("executed bootstrap capsule changed")
    duplicate = os.dup(BOOTSTRAP_CAPSULE_FD)
    try:
        status = os.fstat(duplicate)
        capsule = SealedCapsule(duplicate, expected_capsule, status.st_size)
        duplicate = -1
        return capsule
    finally:
        if duplicate >= 0:
            closing, duplicate = duplicate, -1
            _release_primary = sys.exception()
            try:
                os.close(closing)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
def _build_exec(config_sha256: str) -> int:
    if len(config_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in config_sha256
    ):
        raise ValueError("config SHA-256 is malformed")
    input_roles = {
        "certificate": PUBLIC_CERTIFICATE_FD,
        "source": 22,
        "config": 23,
        "spec": 24,
    }
    for description, descriptor in input_roles.items():
        _require_sealed_regular_descriptor(descriptor, description)
    _require_sealed_regular_descriptor(BUILD_KEY_FD, "private key")
    result_status = os.fstat(BUILD_RESULT_FD)
    if not stat.S_ISREG(result_status.st_mode) or result_status.st_nlink != 0:
        raise RuntimeError("build result descriptor is not anonymous regular data")
    for descriptor in ARTIFACT_FD_ROLES.values():
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        fcntl.fcntl(descriptor, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

    os.umask(0o022)
    topdir = Path("/tmp/work/rpmbuild")
    if topdir.exists():
        raise RuntimeError("private rpmbuild topdir must begin absent")
    source_directory = topdir / "SOURCES"
    spec_directory = topdir / "SPECS"
    for name in ("BUILD", "BUILDROOT", "RPMS", "SRPMS", "SOURCES", "SPECS"):
        (topdir / name).mkdir(parents=True, exist_ok=False)
    staged = {
        "source": source_directory / "linux-6.18.48.tar.xz",
        "config": source_directory / "6.18.48-x86_64.config",
        "certificate": source_directory / "module-signing.pem",
        "spec": spec_directory / "kernel-openmythos.spec",
    }
    input_hashes = {
        role: _hash_descriptor(descriptor)
        for role, descriptor in input_roles.items()
    }
    staged_hashes = {
        role: _copy_descriptor_to_path(input_roles[role], path, mode=0o644)
        for role, path in staged.items()
    }
    if staged_hashes != input_hashes or input_hashes["config"] != config_sha256:
        raise RuntimeError("staged build inputs do not match their sealed authority")
    source_directory_status = source_directory.lstat()
    spec_directory_status = spec_directory.lstat()
    started = time.monotonic()
    with _owned_resource(BoundInputs.open, _drain_bound_inputs,
        staged, policies=_input_policies(staged)
    ) as staged_inputs:
        environment = {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "OPENMYTHOS_CONFIG_SHA256": config_sha256,
            "OPENMYTHOS_MODULE_SIGNING_KEY": f"/proc/self/fd/{BUILD_KEY_FD}",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
            "TZ": "UTC",
        }
        result = subprocess.run(
            [
                "/usr/bin/rpmbuild",
                "-ba",
                "--define",
                "_topdir /tmp/work/rpmbuild",
                "--define",
                "dist .fc44",
                "--define",
                "_smp_mflags -j4",
                os.fspath(staged["spec"]),
            ],
            cwd="/tmp/work",
            env=environment,
            pass_fds=(BUILD_KEY_FD,),
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"rpmbuild failed with status {result.returncode}")
        staged_inputs.verify_coherent()
        if (
            _stat_version(source_directory.lstat())
            != _stat_version(source_directory_status)
            or _stat_version(spec_directory.lstat())
            != _stat_version(spec_directory_status)
        ):
            raise RuntimeError("staged input directory changed during rpmbuild")
        slots = ArtifactSlots(
            {role: ARTIFACT_FD_ROLES[role] for role in ARTIFACT_FD_ROLES}
        )
        identities = export_exact_rpm_set(
            topdir / "RPMS", topdir / "SRPMS", slots
        )
        # These are borrowed preserved descriptors.  The process exit closes its
        # copies; ownership remains with the host supervisor.
        slots._descriptors.clear()
    _write_descriptor_exact(
        BUILD_RESULT_FD,
        _canonical_json(
            {
                "artifact_identities": identities,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "staged_input_sha256": staged_hashes,
            }
        ),
    )
    return 0
def _audit_inputs_fixed() -> int:
    _require_fixed_descriptor_absent(BUILD_KEY_FD, "input-audit private key")
    value = audit_input_descriptors(
        INPUT_AUDIT_FD_ROLES,
        certificate_descriptor=PUBLIC_CERTIFICATE_FD,
    )
    print(json.dumps(value, sort_keys=True), flush=True)
    return 0
def _lifecycle_toolchain_identity(
    lock_descriptor: int, archive_descriptor: int
) -> tuple[str, str]:
    lock = _json_object_descriptor(lock_descriptor, "toolchain lock")
    required = {
        "schema_version", "architecture", "image_reference", "manifest_digest",
        "archive_sha256", "commands", "installed_rpms",
    }
    if set(lock) != required or lock.get("schema_version") != 1:
        raise RuntimeError("toolchain lock schema is not exact")
    # The OCI manifest platform is amd64; the committed lock deliberately uses
    # the Fedora/RPM architecture spelling for its top-level identity.
    if lock.get("architecture") != "x86_64":
        raise RuntimeError("toolchain lock architecture is not exact")
    archive_sha256 = _hash_descriptor(archive_descriptor)
    if lock.get("archive_sha256") != archive_sha256:
        raise RuntimeError("toolchain archive differs from its lock")
    manifest_digest = lock.get("manifest_digest")
    if not isinstance(manifest_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", manifest_digest
    ) is None:
        raise RuntimeError("toolchain manifest digest is malformed")
    return archive_sha256, manifest_digest
@contextmanager
def _production_code_authority(repository: Path) -> Iterable[Any]:
    if _EXECUTED_BOOTSTRAP_AUTHORITY is None or _EXECUTED_BOOTSTRAP_CAPSULE_SHA256 is None or _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256 is None:
        raise RuntimeError("production command requires sealed bootstrap authority")
    boundary = _ReceiptBoundary(lambda: None)
    with _ReceiptExitStack(boundary) as stack:
        paths = {relative: repository / relative for relative in BOOTSTRAP_SOURCE_PATHS}
        inputs = stack.open_owned(BoundInputs.open, _drain_bound_inputs, paths, policies=_input_policies(paths))
        capsule = stack.open_owned(_executed_capsule_from_bound_inputs, _drain_sealed_capsule, inputs)
        boundary.verify = inputs.verify_coherent
        yield boundary
        if not boundary.committed:
            boundary()


def _bootstrap_command(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def invoke(repository: Path, *args: Any, **kwargs: Any) -> Any:
        with _production_code_authority(repository) as authority:
            result = function(repository, *args, _code_authority=authority, **kwargs)
            # Receipt-producing commands already completed their last
            # acceptance check. Only local FD release remains in this scope.
            authority.committed = function.__name__ != "run_no_build_lifecycle"
            return result
    return invoke


@_bootstrap_command
def run_no_build_lifecycle(repository: Path, *, _code_authority: Any) -> dict[str, Any]:
    """Exercise the complete audited container lifecycle without kernel work.

    This disposable integration check deliberately acquires neither the signing
    key nor any RPM output.  It still proves independent OCI derivation, fresh
    import, effective-spec audit, inert PID1 attestation,
    descriptor-only exec, complete post audit, and scoped cleanup.
    """
    if os.geteuid() == 0:
        raise RuntimeError("no-build lifecycle check must run rootless")
    repository = Path(os.path.abspath(repository))
    paths = gate01_input_paths(repository)
    selected = {
        "toolchain_lock": paths["toolchain_lock"],
        "toolchain_archive": paths["toolchain_archive"],
        **{relative: paths[relative] for relative in BOOTSTRAP_SOURCE_PATHS},
    }
    # A VFS import expands beyond the bounded /tmp tmpfs on the real builder.
    # Keep the disposable store on the Gate 01 filesystem, under an exact
    # invocation-owned hidden directory that is removed before return.
    probe_parent = repository / "build/gate01"
    probe_parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with _PrimaryExitStack() as custody:
        inputs = custody.open_owned(BoundInputs.open, _drain_bound_inputs, selected, policies=_input_policies(selected))
        scope = custody.open_owned(BoundScopedDiff.open, _drain_bound_scoped_diff, repository)
        scope.verify_closure(_EXECUTED_BOOTSTRAP_AUTHORITY)
        temporary_anchor = None
        store: PodmanStore | None = None
        backend: PodmanContainerBackend | None = None
        cleanup_attempted = False

        def cleanup_material() -> None:
            nonlocal cleanup_attempted
            failure = None
            cleanup_attempted = True
            if store is not None:
                try:
                    _remove_podman_store(store)
                except BaseException as error:
                    failure = error
            if temporary_anchor is not None:
                try:
                    temporary_anchor.remove()
                except BaseException as error:
                    if failure is None:
                        failure = error
            if backend is not None:
                try:
                    try:
                        _close_resource_preserving_primary(backend, None, drain=_drain_container_backend)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_container_backend(backend)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException as error:
                    if failure is None:
                        failure = error
            if failure is not None:
                raise RuntimeError("no-build lifecycle cleanup failed") from failure

        try:
            temporary, temporary_anchor = _create_scoped_temporary_tree(probe_parent, prefix=".kernel-lifecycle-")
            runtime, scratch = temporary / "runtime", temporary / "scratch"
            runtime.mkdir(mode=0o700)
            scratch.mkdir(mode=0o700)
            environment = controlled_environment(os.environ, home=runtime, xdg_runtime=runtime, temporary=runtime)
            policy = custody.open_owned(SealedPodmanPolicy.create, _drain_podman_policy)
            capsule = custody.open_owned(_executed_capsule_from_bound_inputs, _drain_sealed_capsule, inputs)
            archive_sha256, manifest_digest = _lifecycle_toolchain_identity(
                inputs.descriptor("toolchain_lock"),
                inputs.descriptor("toolchain_archive"),
            )
            summary_result = run_verifier_capsule(
                capsule.fd,
                "tools.gate01.container_runtime",
                (
                    "oci-summary-fixed", "--archive-sha256", archive_sha256,
                    "--manifest-digest", manifest_digest,
                ),
                descriptors={OCI_ARCHIVE_FD: inputs.descriptor("toolchain_archive")},
                environment=environment,
            )
            if summary_result.returncode != 0:
                raise RuntimeError("no-build OCI semantic derivation failed")
            summary = _load_json_bytes(summary_result.stdout, "OCI semantic summary")
            _validate_locked_oci_summary(summary, archive_sha256=archive_sha256, manifest_digest=manifest_digest)

            store = PodmanStore(
                temporary / "store", environment=environment, policy=policy
            )
            store.initialize()
            store.import_image(
                inputs.descriptor("toolchain_archive"),
                expected_config_digest=summary["config_digest"],
                expected_manifest_digest=manifest_digest,
                expected_oci_identity=summary,
            )
            backend = PodmanContainerBackend(
                store=store,
                image=summary["config_digest"],
                container=f"openmythos-gate01-lifecycle-{os.getpid()}",
                scratch=scratch,
                capsule_descriptor=capsule.fd,
                archive_descriptor=inputs.descriptor("toolchain_archive"),
                archive_sha256=archive_sha256,
                manifest_digest=manifest_digest,
                execution_arguments={
                    "probe": (
                        "/usr/bin/python3", "-I", "-S", "-B",
                        f"/proc/self/fd/{VERIFIER_FD}",
                        "tools.gate01.container_runtime", "lifecycle-exec-check",
                    )
                },
            )
            lifecycle = run_container_lifecycle(
                backend,
                executions=(("probe", {VERIFIER_FD: capsule.fd}),),
                allow_key_role=None,
            )
            probe = backend.execution_results.get("probe")
            if probe is None or _load_json_bytes(
                probe.stdout, "no-build exec result"
            ) != {"verdict": "pass", "verifier_fd": VERIFIER_FD}:
                raise RuntimeError("no-build descriptor exec did not pass")
            inputs.verify_coherent()
            result = {
                "schema_version": 1,
                "bootstrap_authority": _EXECUTED_BOOTSTRAP_AUTHORITY,
                "bootstrap_authority_sha256": _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256,
                "executed_capsule_sha256": capsule.sha256,
                "scoped_diff": scope.manifest,
                "scoped_diff_sha256": scope.sha256,
                "locked_oci_summary": summary,
                "selected_input_sha256": {key: inputs.hashes[key] for key in ("toolchain_lock", "toolchain_archive")},
                "container_contract": backend.contract_record,
                "lifecycle": {
                    "transitions": list(lifecycle.transitions),
                    "semantic_equal": lifecycle.semantic_equal,
                    "raw_equal": lifecycle.raw_equal,
                },
                "non_root_entry_count": summary["non_root_entry_count"],
                "root_entry": summary["root_entry"],
                "rootfs_after": dict(lifecycle.after.record),
                "rootfs_authorized": dict(lifecycle.authorized.record),
                "rootfs_before": dict(lifecycle.before.record),
                "verdict": "pass",
            }
            cleanup_material()
            inputs.verify_coherent()
            _code_authority()
            scope.verify_closure(_EXECUTED_BOOTSTRAP_AUTHORITY)
            result["cleanup"] = {
                "container_removed": True, "store_removed": True,
                "temporary_tree_removed": True, "scope_revalidated_after_cleanup": True,
                "verdict": "pass",
            }
            _validate_no_build_evidence(result, repository=repository, probe_root=temporary, scope=scope, inputs=inputs)
            # The final shared semantic check reads only captured records;
            # recapture original source custody once more before returning.
            inputs.verify_coherent()
            scope.verify_closure(_EXECUTED_BOOTSTRAP_AUTHORITY)
            return result
        finally:
            if not cleanup_attempted:
                _release_primary = sys.exception()
                try:
                    cleanup_material()
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
def _validate_locked_oci_summary(value: Any, *, archive_sha256: str, manifest_digest: str) -> None:
    _evidence_exact(value, {"archive_sha256", "config_digest", "diff_ids", "non_root_entry_count", "layer_digests", "manifest_digest", "root_entry", "semantic_sha256"})
    for field in ("archive_sha256", "semantic_sha256"):
        _evidence_digest(value[field])
    for field in ("config_digest", "manifest_digest"):
        if not isinstance(value[field], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]) is None:
            raise RuntimeError("no-build OCI digest is invalid")
    if value["archive_sha256"] != archive_sha256 or value["manifest_digest"] != manifest_digest or type(value["non_root_entry_count"]) is not int or value["non_root_entry_count"] != 138619:
        raise RuntimeError("no-build OCI locked identity differs")
    for field in ("diff_ids", "layer_digests"):
        if not isinstance(value[field], list) or not value[field] or any(not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in value[field]):
            raise RuntimeError("no-build OCI layer identity is invalid")
    if len(value["diff_ids"]) != len(value["layer_digests"]):
        raise RuntimeError("no-build OCI layer counts differ")
    root = _evidence_exact(value["root_entry"], {"path", "kind", "mode", "uid", "gid", "mtime_ns", "size", "content_sha256", "symlink_target", "xattrs", "hardlink_group"})
    for field in ("mode", "uid", "gid", "mtime_ns", "size"):
        _evidence_integer(root[field])
    if {key: item for key, item in root.items() if key != "mtime_ns"} != {"path": "/", "kind": "directory", "mode": 493, "uid": 0, "gid": 0, "size": 0, "content_sha256": None, "symlink_target": None, "xattrs": [], "hardlink_group": None}:
        raise RuntimeError("no-build OCI root semantics differ")


def _validate_no_build_evidence(value: Any, *, repository: Path, probe_root: Path, scope: BoundScopedDiff, inputs: BoundInputs) -> None:
    _evidence_exact(value, {"schema_version", "bootstrap_authority", "bootstrap_authority_sha256", "executed_capsule_sha256", "scoped_diff", "scoped_diff_sha256", "locked_oci_summary", "selected_input_sha256", "container_contract", "lifecycle", "non_root_entry_count", "root_entry", "rootfs_after", "rootfs_authorized", "rootfs_before", "verdict", "cleanup"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["verdict"] != "pass" or not _evidence_same(value["cleanup"], {"container_removed": True, "store_removed": True, "temporary_tree_removed": True, "scope_revalidated_after_cleanup": True, "verdict": "pass"}):
        raise RuntimeError("no-build completion evidence differs")
    if not _evidence_same(value["bootstrap_authority"], _EXECUTED_BOOTSTRAP_AUTHORITY) or value["bootstrap_authority_sha256"] != _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256 or _object_sha256(value["bootstrap_authority"]) != value["bootstrap_authority_sha256"] or value["executed_capsule_sha256"] != _EXECUTED_BOOTSTRAP_CAPSULE_SHA256 or value["executed_capsule_sha256"] != value["bootstrap_authority"]["capsule_sha256"]:
        raise RuntimeError("no-build executed authority differs")
    if value["scoped_diff_sha256"] != scope.sha256 or _object_sha256(value["scoped_diff"]) != scope.sha256 or value["selected_input_sha256"] != {key: inputs.hashes[key] for key in ("toolchain_lock", "toolchain_archive")}:
        raise RuntimeError("no-build scoped source or input authority differs")
    archive_sha256, manifest_digest = _lifecycle_toolchain_identity(inputs.descriptor("toolchain_lock"), inputs.descriptor("toolchain_archive"))
    summary = value["locked_oci_summary"]
    _validate_locked_oci_summary(summary, archive_sha256=archive_sha256, manifest_digest=manifest_digest)
    if not _evidence_same(value["non_root_entry_count"], summary["non_root_entry_count"]) or not _evidence_same(value["root_entry"], summary["root_entry"]):
        raise RuntimeError("no-build OCI summary cross-fields differ")
    fixture = next((row["current"] for row in scope.manifest["entries"] if row["path_hex"] == b"tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json".hex()), None)
    if fixture is None or fixture["type"] != "regular" or fixture["mode"] != "0644" or fixture["sha256"] != value["container_contract"]["canonical_fixture_sha256"]:
        raise RuntimeError("no-build normalized fixture differs from scoped authority")
    lifecycle = _evidence_exact(value["lifecycle"], {"transitions", "semantic_equal", "raw_equal"})
    role = {**lifecycle, "before": value["rootfs_before"], "authorized": value["rootfs_authorized"], "after": value["rootfs_after"], "live": value["container_contract"]["live_attestation"]}
    _validate_runtime_evidence(
        {"schema_version": 1, "expected": summary, "probe": role},
        {"schema_version": 1, "key_scope": {"probe": False}, "stores_distinct": True, "repository_mounted": False, "probe": value["container_contract"]},
        {"oci_rootfs": summary}, repository=repository, builder="probe",
        expected_uid=os.geteuid(), expected_gid=os.getegid(), probe_root=probe_root,
    )


def _builder_outer_contract(builder: str) -> dict[str, str]:
    if builder in {"builder-a", "canonical"}:
        return {"tz": "UTC", "umask": "0022"}
    if builder == "builder-b":
        return {"tz": "Pacific/Honolulu", "umask": "0077"}
    raise ValueError("builder must be builder-a, builder-b, or canonical")


def _validate_outer_environment(builder: str) -> dict[str, str]:
    """Require the launcher's closed, genuinely varied outer environment."""
    contract = _builder_outer_contract(builder)
    expected = {
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": contract["tz"],
    }
    if dict(os.environ) != expected:
        raise RuntimeError("outer builder environment is not exact")
    observed_umask = os.umask(0o777)
    os.umask(observed_umask)
    if observed_umask != int(contract["umask"], 8):
        raise RuntimeError("outer builder umask is not exact")
    return contract
def _read_json_descriptor(descriptor: int, description: str) -> dict[str, Any]:
    return _load_json_bytes(_read_descriptor(descriptor), description)


def _validate_build_execution_result(
    value: Mapping[str, Any],
    *,
    artifact_identities: Mapping[str, Mapping[str, Any]],
    expected_staged_sha256: Mapping[str, str],
) -> None:
    """Bind the wrapper's result to the supervisor-held inputs and RPM slots."""
    if set(value) != {
        "artifact_identities", "elapsed_seconds", "staged_input_sha256"
    }:
        raise RuntimeError("build execution result schema is not exact")
    elapsed = value.get("elapsed_seconds")
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not math.isfinite(elapsed)
        or elapsed < 0
    ):
        raise RuntimeError("build execution result duration is invalid")
    staged = value.get("staged_input_sha256")
    if staged != dict(expected_staged_sha256):
        raise RuntimeError("build execution result staged inputs differ")
    reported = value.get("artifact_identities")
    if not isinstance(reported, dict) or set(reported) != set(
        ARTIFACT_FD_ROLES
    ):
        raise RuntimeError("build execution result artifact set is not exact")
    for role in ARTIFACT_FD_ROLES:
        record = reported.get(role)
        held = artifact_identities.get(role)
        if (
            not isinstance(record, dict)
            or set(record) != {"filename", "sha256", "size"}
            or not isinstance(held, Mapping)
            or record.get("filename") != EXPECTED_RPM_FILENAMES[role]
            or record.get("sha256") != held.get("sha256")
            or record.get("size") != held.get("size")
        ):
            raise RuntimeError(
                f"build execution result artifact identity differs: {role}"
            )


def _initialize_tracked_store(
    stores: list[Any],
    root: Path,
    environment: Mapping[str, str],
    policy: SealedPodmanPolicy,
    *,
    store_factory: Callable[..., Any] = PodmanStore,
) -> Any:
    """Register a store before initialization can create partial state."""
    store = store_factory(root, environment=environment, policy=policy)
    stores.append(store)
    store.initialize()
    return store


_BUILD_CLEANUP_BASENAMES = frozenset({
    "kernel-runtime", "kernel-build-scratch", "kernel-inspection-scratch",
    ".kernel-candidate", "kernel", "kernel.receipt.json",
})


def _safe_cleanup_build_state(
    *,
    builder_root: Path,
    stores: Sequence[PodmanStore],
    ordinary_paths: Sequence[Path],
    scratch_bindings: Mapping[Path, BoundScratch] | None = None,
) -> None:
    failures: BaseException | None = None
    index = 0
    while index < len(stores):
        store = stores[index]
        index += 1
        try:
            _remove_podman_store(store)
        except BaseException as error:
            if failures is None:
                failures = error
    allowed = _BUILD_CLEANUP_BASENAMES
    index = 0
    while index < len(ordinary_paths):
        path = ordinary_paths[index]
        index += 1
        try:
            binding = scratch_bindings.get(path) if scratch_bindings is not None else None
            if binding is None:
                _remove_scoped_path(path, builder_root, allowed)
            elif not binding.closed:
                _require_direct_child(path, builder_root, allowed)
                binding.verify()
                try:
                    _remove_children_at(binding.descriptor)
                except BaseException as error:
                    if failures is None:
                        failures = error
                binding.verify()
                os.rmdir(binding.name, dir_fd=binding.parent_descriptor)
                if os.fstat(binding.descriptor).st_nlink != 0:
                    raise RuntimeError("bound scratch cleanup did not remove original root")
                try:
                    os.stat(binding.name, dir_fd=binding.parent_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError("bound scratch name reappeared during cleanup")
                try:
                    _close_resource_preserving_primary(binding, None, drain=_drain_bound_scratch)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_scratch(binding)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
        except BaseException as error:
            if failures is None:
                failures = error
    if failures:
        raise RuntimeError("scoped build cleanup failed") from failures


def _scan_bound_scratch(capsule: int, key: int, binding: BoundScratch, environment: Mapping[str, str]) -> None:
    binding.verify()
    _scan_tree_with_capsule(capsule, key, binding.descriptor, environment)
    binding.verify()


def _set_public_tree_directory_modes(root: Path) -> None:
    """Set every allowlisted public directory to its exact committed mode."""
    _files, relative_directories = _expected_tree_paths(PUBLIC_OUTPUT_FILES)
    directories = [root]
    directories.extend(
        root / relative
        for relative in sorted(
            relative_directories,
            key=lambda value: (len(Path(value).parts), value),
        )
    )
    for directory in directories:
        named = directory.lstat()
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _stat_identity(named) != _stat_identity(opened)
                or opened.st_uid != os.geteuid()
                or opened.st_gid != os.getegid()
            ):
                raise RuntimeError("public output directory is unsafe")
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o755:
                raise RuntimeError("public output directory mode is not exact")
        finally:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _validate_public_tree_authorities(
    root: Path,
    expected_sha256: Mapping[str, str],
    *,
    expected_uid: int,
    expected_gid: int,
    allowed_files: Mapping[str, str] = PUBLIC_OUTPUT_FILES,
) -> dict[str, str]:
    """Bind every committed public byte to its supervisor-held authority."""
    if set(expected_sha256) != set(allowed_files) or any(
        re.fullmatch(r"[0-9a-f]{64}", str(value)) is None
        for value in expected_sha256.values()
    ):
        raise RuntimeError("public output authority set is not exact")
    with _bound_public_tree(root, allowed_files, expected_uid=expected_uid, expected_gid=expected_gid) as (files, records):
        observed = {record["path"]: record["sha256"] for record in records if record.get("type") == "file"}
        if observed != dict(expected_sha256):
            raise RuntimeError("public output bytes differ from held authority")
        if dict(allowed_files) == PUBLIC_OUTPUT_FILES:
            _validate_public_roles(files.descriptor, repository=root.parents[3], builder=root.parent.name, expected_uid=expected_uid, expected_gid=expected_gid)
    return observed


class _BuilderWorkspace:
    """Held path-chain and exclusive lock for one builder transaction."""

    def __init__(
        self,
        repository: Path,
        builder_root: Path,
        directory_descriptors: tuple[int, int, int, int],
        directory_statuses: tuple[os.stat_result, ...],
        lock_descriptor: int,
        lock_status: os.stat_result,
    ) -> None:
        self.repository = repository
        self.builder_root = builder_root
        self._directory_descriptors = directory_descriptors
        self._directory_statuses = directory_statuses
        self._lock_descriptor = lock_descriptor
        self._lock_status = lock_status
        self._closed = False

    @staticmethod
    def _open_child_directory(
        parent: int, name: str, *, create: bool
    ) -> int:
        if create:
            try:
                os.mkdir(name, 0o755, dir_fd=parent)
            except FileExistsError:
                pass
        try:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
        except OSError as error:
            raise RuntimeError("builder workspace directory is unsafe") from error
        try:
            opened = os.fstat(descriptor)
            mode = stat.S_IMODE(opened.st_mode)
            if (
                not stat.S_ISDIR(named.st_mode)
                or _stat_identity(named) != _stat_identity(opened)
                or opened.st_uid != os.geteuid()
                or mode & 0o022
            ):
                raise RuntimeError("builder workspace directory is unsafe")
            # Avoid changing ctime on an already-normalized shared ancestor.  A
            # comparison holds builder A's complete path-chain anchor while it
            # opens builder B; an unconditional fchmod of build/ or gate01/ would
            # make that legitimate second open look like a concurrent mutation.
            if mode != 0o755:
                os.fchmod(descriptor, 0o755)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o755:
                raise RuntimeError("builder workspace directory mode is not exact")
            result, descriptor = descriptor, -1
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

    @classmethod
    def open(
        cls,
        repository: Path,
        builder: str,
        *,
        exclusive: bool = True,
        create: bool = True,
    ) -> "_BuilderWorkspace":
        repository = _validated_repository(repository)
        if builder not in {"builder-a", "builder-b", "canonical"}:
            raise ValueError("builder workspace identity is invalid")
        descriptors: list[int] = []
        lock_descriptor = -1
        try:
            repo_named = repository.lstat()
            repo_descriptor = os.open(
                repository,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                descriptors.append(repo_descriptor)
            except BaseException as primary:
                _release_primary = primary
                try:
                    os.close(repo_descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            if _stat_identity(repo_named) != _stat_identity(
                os.fstat(repo_descriptor)
            ):
                raise RuntimeError("builder workspace repository changed")
            parent = repo_descriptor
            for component in ("build", "gate01", builder):
                parent = cls._open_child_directory(
                    parent, component, create=create
                )
                try:
                    descriptors.append(parent)
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(parent)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            builder_root = repository / "build/gate01" / builder
            lock_flags = (
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            if create:
                try:
                    lock_descriptor = os.open(
                        "kernel-build.lock",
                        lock_flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=descriptors[-1],
                    )
                except FileExistsError:
                    pass
            if lock_descriptor < 0:
                try:
                    lock_descriptor = os.open(
                        "kernel-build.lock", lock_flags,
                        dir_fd=descriptors[-1],
                    )
                except OSError as error:
                    raise RuntimeError("builder lock is unsafe") from error
            named_lock = os.stat(
                "kernel-build.lock",
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
            lock_status = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_status.st_mode)
                or lock_status.st_nlink != 1
                or lock_status.st_uid != os.geteuid()
                or stat.S_IMODE(lock_status.st_mode) != 0o600
                or _stat_identity(named_lock) != _stat_identity(lock_status)
            ):
                raise RuntimeError("builder lock metadata is unsafe")
            try:
                fcntl.flock(
                    lock_descriptor,
                    (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                    | fcntl.LOCK_NB,
                )
            except OSError as error:
                raise RuntimeError(
                    f"kernel build is already active for {builder}"
                ) from error
            statuses = tuple(os.fstat(descriptor) for descriptor in descriptors)
            result = cls(
                repository,
                builder_root,
                tuple(descriptors),
                statuses,
                lock_descriptor,
                lock_status,
            )
            result.verify_coherent()
            return result
        except BaseException as primary:
            closing, lock_descriptor = lock_descriptor, -1
            try:
                _close_descriptors(closing, primary=primary)
            finally:
                _close_descriptor_sequence(descriptors, primary, reverse=True)
            raise

    def verify_coherent(self) -> None:
        if self._closed:
            raise RuntimeError("builder workspace is closed")
        descriptors = self._directory_descriptors
        names = ("build", "gate01", self.builder_root.name)
        current_statuses = tuple(os.fstat(value) for value in descriptors)
        for index, (initial, current) in enumerate(
            zip(self._directory_statuses, current_statuses, strict=True)
        ):
            if _stat_identity(initial) != _stat_identity(current):
                raise RuntimeError("builder workspace path identity changed")
            # Children beneath the builder root change during a build; its
            # ancestors must remain continuously stable.
            if index < len(current_statuses) - 1 and _stat_version(
                initial
            ) != _stat_version(current):
                raise RuntimeError("builder workspace ancestor changed")
        for index, name in enumerate(names):
            named = os.stat(
                name,
                dir_fd=descriptors[index],
                follow_symlinks=False,
            )
            if _stat_identity(named) != _stat_identity(current_statuses[index + 1]):
                raise RuntimeError("builder workspace path identity changed")
        current_lock = os.fstat(self._lock_descriptor)
        named_lock = os.stat(
            "kernel-build.lock",
            dir_fd=descriptors[-1],
            follow_symlinks=False,
        )
        if (
            _stat_version(current_lock) != _stat_version(self._lock_status)
            or _stat_identity(named_lock) != _stat_identity(current_lock)
        ):
            raise RuntimeError("builder workspace lock changed")

    def close(self) -> None:
        if self._closed:
            return
        lock = self._lock_descriptor
        directories = self._directory_descriptors
        failures: BaseException | None = None
        self._closed = True
        self._lock_descriptor, self._directory_descriptors = -1, ()
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        except BaseException as error:
            if failures is None:
                failures = error
        try:
            _numeric_failure = None
            _numeric_fd = lock
            if _numeric_fd >= 0:
                try:
                    os.close(_numeric_fd)
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
            if _numeric_failure is not None:
                raise RuntimeError("bound descriptor release failed") from _numeric_failure
        except BaseException as error:
            if failures is None:
                failures = error
        finally:
            try:
                _numeric_failure = None
                _numeric_values = directories
                if isinstance(_numeric_values, list):
                    while _numeric_values:
                        _numeric_fd = _numeric_values.pop()
                        if _numeric_fd >= 0:
                            try:
                                os.close(_numeric_fd)
                            except BaseException as _numeric_error:
                                if _numeric_failure is None:
                                    _numeric_failure = _numeric_error
                else:
                    _numeric_index = len(_numeric_values)
                    while _numeric_index:
                        _numeric_index -= 1
                        _numeric_fd = _numeric_values[_numeric_index]
                        if _numeric_fd >= 0:
                            try:
                                os.close(_numeric_fd)
                            except BaseException as _numeric_error:
                                if _numeric_failure is None:
                                    _numeric_failure = _numeric_error
                if _numeric_failure is not None:
                    raise RuntimeError("bound descriptor release failed") from _numeric_failure
            except BaseException as error:
                if failures is None:
                    failures = error
        if failures:
            raise RuntimeError("builder workspace cleanup failed") from failures

    def __enter__(self) -> "_BuilderWorkspace":
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object | None,
    ) -> None:
        _release_primary = exception
        try:
            self.close()
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


_drain_builder_workspace = _BuilderWorkspace.close


def _drain_builder_resource(resource: Any) -> None:
    """The finite builder owner set, with no opaque attribute inference."""
    if isinstance(resource, SealedPodmanPolicy):
        _drain_podman_policy(resource)
    elif isinstance(resource, BoundScratch):
        _drain_bound_scratch(resource)
    elif isinstance(resource, BoundInputs):
        _drain_bound_inputs(resource)
    elif isinstance(resource, SealedCapsule):
        _drain_sealed_capsule(resource)
    elif isinstance(resource, SealedSecret):
        _drain_sealed_secret(resource)
    elif isinstance(resource, _DescriptorResource):
        _drain_descriptor_resource(resource)
    elif isinstance(resource, ArtifactSlots):
        _drain_artifact_slots(resource)
    elif isinstance(resource, AnonymousOutputs):
        _drain_anonymous_outputs(resource)
    elif isinstance(resource, ArtifactSet):
        _drain_artifact_set(resource)
    else:
        raise RuntimeError("builder cleanup owner has no concrete drain contract")


@_bootstrap_command
def run_builder(repository: Path, builder: str, *, _code_authority: Any) -> dict[str, Any]:
    """Run the full descriptor-custody kernel RPM proof for one builder."""
    if os.geteuid() == 0:
        raise RuntimeError("kernel builder must run rootless")
    outer_environment = _validate_outer_environment(builder)
    repository = _validated_repository(repository)
    builder_root = repository / "build/gate01" / builder
    final = builder_root / "kernel"
    receipt_path = builder_root / "kernel.receipt.json"
    candidate = builder_root / ".kernel-candidate"
    runtime = builder_root / "kernel-runtime"
    build_scratch = builder_root / "kernel-build-scratch"
    inspection_scratch = builder_root / "kernel-inspection-scratch"
    build_store_path = builder_root / "kernel-podman-build"
    inspection_store_path = builder_root / "kernel-podman-inspect"
    scoped_names = {
        "kernel", "kernel.receipt.json", ".kernel-candidate", "kernel-runtime",
        "kernel-build-scratch", "kernel-inspection-scratch",
        "kernel-podman-build", "kernel-podman-inspect",
    }
    for path in (
        final, receipt_path, candidate, runtime, build_scratch,
        inspection_scratch, build_store_path, inspection_store_path,
    ):
        _require_direct_child(path, builder_root, scoped_names)

    resources: list[Any] = []
    stores: list[PodmanStore] = []
    scratch_bindings: dict[Path, BoundScratch] = {}
    ordinary = [
        candidate, final, receipt_path, runtime,
        build_scratch, inspection_scratch,
    ]
    accepted = False
    started_at = time.monotonic()
    workspace = _BuilderWorkspace.open(repository, builder)
    try:
        if workspace.builder_root != builder_root:
            raise RuntimeError("builder workspace authority differs")
        podman_policy = SealedPodmanPolicy.create()
        try:
            resources.append(podman_policy)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(podman_policy, None, drain=_drain_podman_policy)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_podman_policy(podman_policy)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        # An invocation intentionally replaces only this builder's prior accepted
        # transaction. The sibling cache, secrets, and other builders are untouched.
        for path in (receipt_path, final, candidate, runtime, build_scratch, inspection_scratch):
            _remove_scoped_path(path, builder_root, scoped_names)
        for path in (build_store_path, inspection_store_path):
            if path.exists() or path.is_symlink():
                # A stale store is removed through a temporary exact store handle.
                stale_runtime = runtime
                stale_runtime.mkdir(mode=0o700, exist_ok=True)
                stale_env = controlled_environment(
                    {}, home=stale_runtime, xdg_runtime=stale_runtime,
                    temporary=stale_runtime,
                )
                stale = PodmanStore(
                    path, environment=stale_env, policy=podman_policy
                )
                stores.append(stale)
                _remove_podman_store(stale)
                stores.remove(stale)
                shutil.rmtree(stale_runtime)

        runtime.mkdir(mode=0o700)
        backing = runtime / "anonymous"
        backing.mkdir(mode=0o700)
        build_scratch.mkdir(mode=0o700)
        inspection_scratch.mkdir(mode=0o700)
        for scratch_path in (build_scratch, inspection_scratch):
            binding = BoundScratch.open(scratch_path)
            try:
                resources.append(binding)
            except BaseException as primary:
                _release_primary = primary
                try:
                    try:
                        _close_resource_preserving_primary(binding, None, drain=_drain_bound_scratch)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_bound_scratch(binding)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            scratch_bindings[scratch_path] = binding
        candidate.mkdir(mode=0o755)
        environment = controlled_environment(
            os.environ,
            home=runtime,
            xdg_runtime=runtime,
            temporary=runtime,
        )

        input_paths = gate01_input_paths(repository)
        inputs = BoundInputs.open(
            input_paths,
            policies=_input_policies(input_paths),
            secret_labels={"private_key"},
        )
        try:
            resources.append(inputs)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(inputs, None, drain=_drain_bound_inputs)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_inputs(inputs)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        capsule = _executed_capsule_from_bound_inputs(inputs)
        try:
            resources.append(capsule)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(capsule, None, drain=_drain_sealed_capsule)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_sealed_capsule(capsule)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

        audit_descriptor_map = {
            target: inputs.descriptor(label)
            for label, target in INPUT_AUDIT_FD_ROLES.items()
        }
        audit_result = run_verifier_capsule(
            capsule.fd,
            "tools.gate01.kernel_build",
            ("audit-inputs-fixed",),
            descriptors={
                **audit_descriptor_map,
                PUBLIC_CERTIFICATE_FD: inputs.descriptor("public_certificate"),
            },
            environment=environment,
        )
        if audit_result.returncode != 0:
            raise RuntimeError("exact input descriptor audit failed")
        input_audit = _load_json_bytes(audit_result.stdout, "input audit")

        oci_result = run_verifier_capsule(
            capsule.fd,
            "tools.gate01.container_runtime",
            (
                "oci-summary-fixed",
                "--archive-sha256", input_audit["toolchain_archive_sha256"],
                "--manifest-digest", input_audit["toolchain_manifest_digest"],
            ),
            descriptors={OCI_ARCHIVE_FD: inputs.descriptor("toolchain_archive")},
            environment=environment,
        )
        if oci_result.returncode != 0:
            raise RuntimeError("independent OCI semantic derivation failed")
        oci_summary = _load_json_bytes(oci_result.stdout, "OCI semantic summary")
        if oci_summary.get("non_root_entry_count") != 138619:
            raise RuntimeError("locked OCI rootfs path count is not exact")
        input_audit["toolchain_config_expected"] = oci_summary["config_digest"]

        public_inputs = {}
        for role, label in {
            "source": "source_archive", "config": "config",
            "certificate": "public_certificate", "spec": "spec",
        }.items():
            resource = copy_public_to_sealed_memfd(inputs, label)
            try:
                resources.append(resource)
            except BaseException as primary:
                _release_primary = primary
                try:
                    try:
                        _close_resource_preserving_primary(resource, None, drain=_drain_builder_resource)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_builder_resource(resource)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            public_inputs[role] = resource
        sealed_key = copy_secret_to_sealed_memfd(inputs, "private_key")
        try:
            resources.append(sealed_key)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(sealed_key, None, drain=_drain_sealed_secret)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_sealed_secret(sealed_key)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        source_capsule_value = {
            "schema_version": 1,
            "files": inputs.hashes,
            "input_audit": input_audit,
            "oci_rootfs": oci_summary,
            "private_key": {"bound": True, "digest_recorded": False, "mode": "0600"},
            "tcb": (
                "trusted clean initial launch; trusted host kernel/filesystem and audited "
                "absolute runtime tools; exclusive non-malicious build UID/process set"
            ),
            "out_of_scope": (
                "pre-entry loader compromise, ptrace or proc-fd theft, active same-UID "
                "compromise, and coordinated replacement after receipt return"
            ),
            "bootstrap_authority_sha256": _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256,
            "bootstrap_authority": _EXECUTED_BOOTSTRAP_AUTHORITY,
            "executed_capsule_sha256": _EXECUTED_BOOTSTRAP_CAPSULE_SHA256,
            "verifier_capsule_sha256": capsule.sha256,
        }
        source_capsule_bytes = _canonical_json(source_capsule_value)
        source_capsule = seal_public_bytes(source_capsule_bytes, "source-capsule")
        try:
            resources.append(source_capsule)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(source_capsule, None, drain=_drain_sealed_capsule)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_sealed_capsule(source_capsule)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

        build_store = _initialize_tracked_store(
            stores, build_store_path, environment, podman_policy
        )
        build_store.import_image(
            inputs.descriptor("toolchain_archive"),
            expected_config_digest=oci_summary["config_digest"],
            expected_manifest_digest=input_audit["toolchain_manifest_digest"],
            expected_oci_identity=oci_summary,
        )
        artifact_slots = ArtifactSlots.create(backing)
        try:
            resources.append(artifact_slots)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(artifact_slots, None, drain=_drain_artifact_slots)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_artifact_slots(artifact_slots)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        build_outputs = AnonymousOutputs.create(backing, ("result", "log"))
        try:
            resources.append(build_outputs)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(build_outputs, None, drain=_drain_anonymous_outputs)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_anonymous_outputs(build_outputs)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        build_backend = PodmanContainerBackend(
            store=build_store,
            image=oci_summary["config_digest"],
            container=f"openmythos-{builder}-kernel-build",
            scratch=build_scratch,
            scratch_binding=scratch_bindings[build_scratch],
            capsule_descriptor=capsule.fd,
            archive_descriptor=inputs.descriptor("toolchain_archive"),
            archive_sha256=input_audit["toolchain_archive_sha256"],
            manifest_digest=input_audit["toolchain_manifest_digest"],
            execution_arguments={
                "probe": ("/usr/bin/gcc", "--version"),
                "build": (
                    "/usr/bin/python3", "-I", "-S", "-B",
                    f"/proc/self/fd/{VERIFIER_FD}",
                    "tools.gate01.kernel_build", "build-exec",
                    "--config-sha256", input_audit["config_sha256"],
                ),
            },
            execution_stdout={"build": build_outputs.descriptor("log")},
        )
        build_lifecycle = run_container_lifecycle(
            build_backend,
            executions=(
                ("probe", {}),
                (
                    "build",
                    {
                        VERIFIER_FD: capsule.fd,
                        PUBLIC_CERTIFICATE_FD: public_inputs["certificate"].fd,
                        SOURCE_ARCHIVE_FD: public_inputs["source"].fd,
                        CONFIG_FD: public_inputs["config"].fd,
                        SPEC_FD: public_inputs["spec"].fd,
                        BUILD_KEY_FD: sealed_key.fd,
                        BUILD_RESULT_FD: build_outputs.descriptor("result"),
                        **{
                            descriptor: artifact_slots.descriptor(role)
                            for role, descriptor in ARTIFACT_FD_ROLES.items()
                        },
                    },
                ),
            ),
            allow_key_role="build",
        )
        compiler_version = build_backend.execution_results["probe"].stdout.splitlines()[0]
        if compiler_version.decode("utf-8") != input_audit["commands"]["gcc"]:
            raise RuntimeError("compiler probe differs from the locked command identity")
        artifacts = artifact_slots.transition_to_read_only(
            process_probe=lambda expected: _assert_artifact_writer_custody(
                expected, tuple(artifact_slots._descriptors.values())
            )
        )
        try:
            resources.append(artifacts)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(artifacts, None, drain=_drain_artifact_set)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_artifact_set(artifacts)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        build_result_fds = build_outputs.reopen_read_only()
        build_result = _read_json_descriptor(
            build_result_fds["result"], "build execution result"
        )
        _validate_build_execution_result(
            build_result,
            artifact_identities=artifacts.identities,
            expected_staged_sha256={
                "certificate": inputs.hashes["public_certificate"],
                "config": inputs.hashes["config"],
                "source": inputs.hashes["source_archive"],
                "spec": inputs.hashes["spec"],
            },
        )
        build_log_descriptor = build_result_fds["log"]

        # Build scratch is complete, container gone, and signing store still
        # available only for the final rootfs record already captured.
        _scan_bound_scratch(
            capsule.fd, sealed_key.fd, scratch_bindings[build_scratch], environment
        )
        _remove_podman_store(build_store)
        stores.remove(build_store)

        inspection_store = _initialize_tracked_store(
            stores, inspection_store_path, environment, podman_policy
        )
        inspection_store.import_image(
            inputs.descriptor("toolchain_archive"),
            expected_config_digest=oci_summary["config_digest"],
            expected_manifest_digest=input_audit["toolchain_manifest_digest"],
            expected_oci_identity=oci_summary,
        )
        inspection_outputs = AnonymousOutputs.create(
            backing, ("rpm_manifest", "installed_files", "result")
        )
        try:
            resources.append(inspection_outputs)
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(inspection_outputs, None, drain=_drain_anonymous_outputs)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_anonymous_outputs(inspection_outputs)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        inspector_backend = PodmanContainerBackend(
            store=inspection_store,
            image=oci_summary["config_digest"],
            container=f"openmythos-{builder}-kernel-inspect",
            scratch=inspection_scratch,
            scratch_binding=scratch_bindings[inspection_scratch],
            capsule_descriptor=capsule.fd,
            archive_descriptor=inputs.descriptor("toolchain_archive"),
            archive_sha256=input_audit["toolchain_archive_sha256"],
            manifest_digest=input_audit["toolchain_manifest_digest"],
            execution_arguments={
                "inspect": (
                    "/usr/bin/python3", "-I", "-S", "-B",
                    f"/proc/self/fd/{VERIFIER_FD}",
                    "tools.gate01.rpm_artifacts", "inspect-fixed-fds",
                    "--extract-root", "/tmp/work/extracted",
                    "--spec-sha256", inputs.hashes["spec"],
                    "--source-sha256", input_audit["source_archive_sha256"],
                    "--config-sha256", input_audit["config_sha256"],
                    "--certificate-sha256", input_audit["certificate_sha256"],
                ),
            },
        )
        inspection_lifecycle = run_container_lifecycle(
            inspector_backend,
            executions=(
                (
                    "inspect",
                    {
                        VERIFIER_FD: capsule.fd,
                        PUBLIC_CERTIFICATE_FD: public_inputs["certificate"].fd,
                        **{
                            descriptor: artifacts.descriptor(role)
                            for role, descriptor in ARTIFACT_FD_ROLES.items()
                        },
                        **{
                            descriptor: inspection_outputs.descriptor(role)
                            for role, descriptor in EVIDENCE_FD_ROLES.items()
                        },
                    },
                ),
            ),
            allow_key_role=None,
        )
        evidence_fds = inspection_outputs.reopen_read_only()
        inspection_result = _read_json_descriptor(
            evidence_fds["result"], "RPM inspection result"
        )
        rpm_manifest_sha256 = _hash_descriptor(evidence_fds["rpm_manifest"])
        installed_files_sha256 = _hash_descriptor(
            evidence_fds["installed_files"]
        )
        if (
            inspection_result.get("rpm_manifest_sha256") != rpm_manifest_sha256
            or inspection_result.get("installed_files_sha256")
            != installed_files_sha256
        ):
            raise RuntimeError("inspector result does not bind its evidence descriptors")
        rpm_manifest_value = _read_json_descriptor(
            evidence_fds["rpm_manifest"], "RPM artifact manifest"
        )
        validate_rpm_manifest(rpm_manifest_value)
        role_by_name = {
            "kernel-openmythos": "meta",
            "kernel-openmythos-core": "core",
            "kernel-openmythos-modules": "modules",
        }
        manifest_artifact_sha256 = {
            "srpm": rpm_manifest_value["source_rpms"][0]["sha256"],
            **{
                role_by_name[package["name"]]: package["sha256"]
                for package in rpm_manifest_value["binary_rpms"]
            },
        }
        if manifest_artifact_sha256 != {
            role: artifacts.identities[role]["sha256"]
            for role in artifacts.identities
        }:
            raise RuntimeError(
                "RPM manifest hashes differ from held artifact descriptors"
            )
        installed_files_value = _read_json_descriptor(
            evidence_fds["installed_files"], "installed-file evidence"
        )
        expected_installed_files = {
            "schema_version": rpm_manifest_value["schema_version"],
            "kernel_release": rpm_manifest_value["kernel_release"],
            "packages": [
                {"nevra": package["nevra"], "files": package["files"]}
                for package in rpm_manifest_value["binary_rpms"]
            ],
        }
        if installed_files_value != expected_installed_files:
            raise RuntimeError(
                "installed-file evidence is not derived from the RPM manifest"
            )
        _scan_bound_scratch(
            capsule.fd, sealed_key.fd, scratch_bindings[inspection_scratch], environment
        )
        _scan_artifacts_with_capsule(capsule.fd, sealed_key.fd, artifacts, environment)
        _remove_podman_store(inspection_store)
        stores.remove(inspection_store)

        # Build the entire candidate before any acceptance scan or receipt.
        candidate_sha256: dict[str, str] = {}
        for role in ("srpm", "core", "modules", "meta"):
            relative = next(
                path for path, kind in PUBLIC_OUTPUT_FILES.items()
                if kind == f"{role}-rpm" or (role == "srpm" and kind == "source-rpm")
            )
            candidate_sha256[relative] = _publish_descriptor(
                artifacts.descriptor(role), candidate / relative,
                expected_sha256=artifacts.identities[role]["sha256"],
            )
        candidate_sha256["rpm-artifacts.json"] = _publish_descriptor(
            evidence_fds["rpm_manifest"], candidate / "rpm-artifacts.json",
            expected_sha256=rpm_manifest_sha256,
        )
        candidate_sha256["installed-files.json"] = _publish_descriptor(
            evidence_fds["installed_files"], candidate / "installed-files.json",
            expected_sha256=installed_files_sha256,
        )
        transcript = {
            "builder": builder,
            "build_rootfs_before": dict(build_lifecycle.before.record),
            "build_rootfs_authorized": dict(build_lifecycle.authorized.record),
            "build_rootfs_after": dict(build_lifecycle.after.record),
            "inspection_rootfs_before": dict(inspection_lifecycle.before.record),
            "inspection_rootfs_authorized": dict(
                inspection_lifecycle.authorized.record
            ),
            "inspection_rootfs_after": dict(inspection_lifecycle.after.record),
            "phases": [
                "input-bind", "oci-derive", "build-create-audit-start-attest-exec",
                "writer-close", "inspection-create-audit-start-attest-exec",
                "complete-scan", "cleanup", "receipt-last",
            ],
        }
        candidate_sha256["build.log"] = _publish_build_log(
            build_log_descriptor, candidate / "build.log", transcript
        )
        candidate_sha256["compiler-version.txt"] = _write_public_file(
            candidate / "compiler-version.txt", compiler_version + b"\n"
        )
        candidate_sha256["source-capsule.json"] = _write_public_file(
            candidate / "source-capsule.json", source_capsule_bytes
        )
        rootfs_value = {
            "schema_version": 1,
            "expected": oci_summary,
            "build": {
                "before": dict(build_lifecycle.before.record),
                "authorized": dict(build_lifecycle.authorized.record),
                "live": build_backend.live_record,
                "after": dict(build_lifecycle.after.record),
                "transitions": list(build_lifecycle.transitions),
                "semantic_equal": build_lifecycle.semantic_equal,
                "raw_equal": build_lifecycle.raw_equal,
            },
            "inspection": {
                "before": dict(inspection_lifecycle.before.record),
                "authorized": dict(inspection_lifecycle.authorized.record),
                "live": inspector_backend.live_record,
                "after": dict(inspection_lifecycle.after.record),
                "transitions": list(inspection_lifecycle.transitions),
                "semantic_equal": inspection_lifecycle.semantic_equal,
                "raw_equal": inspection_lifecycle.raw_equal,
            },
        }
        candidate_sha256["rootfs-audit.json"] = _write_public_file(
            candidate / "rootfs-audit.json", _canonical_json(rootfs_value)
        )
        contract_value = {
            "schema_version": 1,
            "build": build_backend.contract_record,
            "inspection": inspector_backend.contract_record,
            "key_scope": {"probe": False, "build": True, "inspection": False},
            "stores_distinct": True,
            "repository_mounted": False,
        }
        candidate_sha256["container-contract.json"] = _write_public_file(
            candidate / "container-contract.json", _canonical_json(contract_value)
        )
        leakage_value = {
            "schema_version": 1,
            "verdict": "pass",
            "key_identity_digest_recorded": False,
            "roots": ["build-scratch", "inspection-scratch", "candidate"],
            "held_artifacts": sorted(ARTIFACT_FD_ROLES),
        }
        candidate_sha256["leakage-scan.json"] = _write_public_file(
            candidate / "leakage-scan.json", _canonical_json(leakage_value)
        )
        report_value = {
            "schema_version": 2,
            "acceptance": "pending-detached-receipt",
            "builder_id": builder,
            "outer_environment": outer_environment,
            "declared_environment": {
                "source_date_epoch": SOURCE_DATE_EPOCH,
                "tz": "UTC", "locale": "C.UTF-8", "parallelism": 4,
                "build_host": "openmythos-builder",
                "build_user": "openmythos",
                "rpm_buildhost": "openmythos-builder.invalid",
            },
            "artifact_identity": {
                "binary_nevras": sorted(
                    package["nevra"]
                    for package in rpm_manifest_value["binary_rpms"]
                ),
                "installed_files_sha256": installed_files_sha256,
                "kernel_release": rpm_manifest_value["kernel_release"],
                "rpm_manifest_sha256": rpm_manifest_sha256,
                "rpm_sha256": {
                    role: artifacts.identities[role]["sha256"]
                    for role in sorted(artifacts.identities)
                },
                "source_nevra": rpm_manifest_value["source_rpms"][0]["nevra"],
            },
            "elapsed_seconds_before_final_scan": round(time.monotonic() - started_at, 3),
            "meta_uname_requirements": inspection_result["meta_uname_requirements"],
            "network_used": False,
            "receipt": "kernel.receipt.json",
            "source_capsule_sha256": source_capsule.sha256,
            "toolchain_manifest_digest": input_audit["toolchain_manifest_digest"],
        }
        candidate_sha256["build-report.json"] = _write_public_file(
            candidate / "build-report.json", _canonical_json(report_value)
        )
        _set_public_tree_directory_modes(candidate)

        # The complete scanner sees all private scratch, every held RPM, every
        # public evidence/log byte, and uses the exact sealed signing key.
        _scan_tree_with_capsule(capsule.fd, sealed_key.fd, candidate, environment)
        # Build/inspection roots were already scanned after their final writers;
        # re-open them now to bind the common final boundary as well.
        _scan_bound_scratch(capsule.fd, sealed_key.fd, scratch_bindings[build_scratch], environment)
        _scan_bound_scratch(capsule.fd, sealed_key.fd, scratch_bindings[inspection_scratch], environment)
        _scan_artifacts_with_capsule(capsule.fd, sealed_key.fd, artifacts, environment)

        # All fallible ephemeral cleanup completes before the transaction marker.
        _safe_cleanup_build_state(
            builder_root=builder_root,
            stores=stores,
            ordinary_paths=(build_scratch, inspection_scratch),
            scratch_bindings=scratch_bindings,
        )
        stores.clear()
        ordinary = [candidate, final, receipt_path, runtime]
        # Runtime contains only already-unlinked FDs and public control files.
        _remove_scoped_path(runtime, builder_root, {"kernel-runtime"})
        ordinary.remove(runtime)

        inputs.verify_coherent()
        for role, descriptor in artifacts._descriptors.items():
            if _hash_descriptor(descriptor) != artifacts.identities[role]["sha256"]:
                raise RuntimeError(f"held artifact changed before receipt: {role}")
        _validate_public_tree_authorities(candidate, candidate_sha256, expected_uid=os.geteuid(), expected_gid=os.getegid())
        receipt_value = create_detached_receipt(
            candidate,
            intended_path=final,
            allowed_files=PUBLIC_OUTPUT_FILES,
            source_capsule_sha256=source_capsule.sha256,
            rpm_manifest_sha256=rpm_manifest_sha256, expected_uid=os.geteuid(), expected_gid=os.getegid()
        )
        def revalidate_inputs_before_receipt() -> None:
            _code_authority()
            workspace.verify_coherent()
            inputs.verify_coherent()
            for role, descriptor in artifacts._descriptors.items():
                if _hash_descriptor(descriptor) != artifacts.identities[role]["sha256"]:
                    raise RuntimeError(
                        f"held artifact changed at receipt boundary: {role}"
                    )
            _validate_public_tree_authorities(final, candidate_sha256, expected_uid=os.geteuid(), expected_gid=os.getegid())

        receipt_sha256 = hashlib.sha256(_canonical_json(receipt_value)).hexdigest()
        publish_candidate(
            candidate,
            final,
            receipt_path,
            receipt_value,
            before_receipt=revalidate_inputs_before_receipt, expected_uid=os.geteuid(), expected_gid=os.getegid()
        )
        accepted = True
        _post_receipt_output({
                    "builder": builder,
                    "receipt": os.fspath(receipt_path),
                    "receipt_sha256": receipt_sha256,
                    "tree_sha256": receipt_value["tree_sha256"],
                    "verdict": "pass",
        })
        return {
            "receipt_sha256": receipt_sha256,
            "tree_sha256": receipt_value["tree_sha256"],
        }
    finally:
        primary = sys.exception()
        cleanup_error: BaseException | None = None
        if not accepted:
            try:
                _safe_cleanup_build_state(
                    builder_root=builder_root,
                    stores=stores,
                    ordinary_paths=ordinary,
                    scratch_bindings=scratch_bindings,
                )
            except BaseException as error:
                cleanup_error = error
                if primary is not None:
                    _add_cleanup_note(primary, "additional builder material cleanup failed")
        try:
            while resources:
                try:
                    resource = resources.pop()
                except BaseException as error:
                    # No aggregate allocation may stand between acquired
                    # owners and cleanup. A failed pop leaves the exact owner
                    # in this private builtin list; detach it without copying.
                    if cleanup_error is None:
                        cleanup_error = error
                    if primary is not None:
                        _add_cleanup_note(primary, "additional builder cleanup ownership transfer failed")
                    resource = resources[-1]
                    del resources[-1]
                try:
                    try:
                        _close_resource_preserving_primary(resource, None, drain=_drain_builder_resource)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_builder_resource(resource)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
                    if primary is not None:
                        _add_cleanup_note(primary, "additional builder resource cleanup failed")
        finally:
            try:
                try:
                    _close_resource_preserving_primary(workspace, None, drain=_drain_builder_workspace)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_builder_workspace(workspace)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                if primary is not None:
                    _add_cleanup_note(primary, "additional builder resource cleanup failed")
            finally:
                workspace = None
        if cleanup_error is not None and primary is None:
            if accepted:
                try:
                    os.write(2, b"warning: post-receipt local cleanup or diagnostic failed\n")
                except BaseException:
                    pass
            else:
                raise cleanup_error


def _validated_repository(repository: Path) -> Path:
    value = Path(os.path.abspath(repository))
    try:
        status = value.lstat()
    except OSError as error:
        raise RuntimeError("repository root is missing") from error
    if value.is_symlink() or not stat.S_ISDIR(status.st_mode) or not (value / ".git").exists():
        raise RuntimeError("repository root is missing or unsafe")
    return value


def _builder_proof_paths(repository: Path, builder: str) -> tuple[Path, Path]:
    if builder not in {"builder-a", "builder-b", "canonical"}:
        raise ValueError("builder proof identity is invalid")
    root = repository / "build/gate01" / builder / "kernel"
    return root, root.parent / "kernel.receipt.json"


def _strict_json_descriptor(descriptor: int, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        encoded = _read_descriptor(descriptor)
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON value")),
        )
    except (UnicodeError, ValueError):
        raise ReceiptError(f"{description} is not valid JSON") from None
    if not isinstance(value, dict):
        raise ReceiptError(f"{description} must be a JSON object")
    if _canonical_json(value) != encoded:
        raise ReceiptError(f"{description} is not canonical JSON")
    return value


def _validate_source_capsule(value: Any) -> dict[str, Any]:
    def exact(record: Any, fields: set[str]) -> dict[str, Any]:
        if not isinstance(record, dict) or set(record) != fields:
            raise ReceiptError("source capsule object schema is not exact")
        return record

    def digest(item: Any, *, prefixed: bool = False) -> None:
        if not isinstance(item, str) or re.fullmatch(("sha256:" if prefixed else "") + r"[0-9a-f]{64}", item) is None:
            raise ReceiptError("source capsule digest field is invalid")

    exact(value, {"schema_version", "files", "input_audit", "oci_rootfs", "private_key", "tcb", "out_of_scope", "bootstrap_authority", "bootstrap_authority_sha256", "executed_capsule_sha256", "verifier_capsule_sha256"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ReceiptError("source capsule schema version is invalid")
    files = exact(value["files"], set(gate01_input_paths(Path("/source-capsule"))) - {"private_key"})
    for identity in files.values():
        digest(identity)
    audit = exact(value["input_audit"], {"certificate_sha256", "commands", "config_sha256", "kernel_release", "source_archive_sha256", "source_date_epoch", "toolchain_archive_sha256", "toolchain_config_expected", "toolchain_image_reference", "toolchain_manifest_digest"})
    for audit_key, file_key in (("certificate_sha256", "public_certificate"), ("config_sha256", "config"), ("source_archive_sha256", "source_archive"), ("toolchain_archive_sha256", "toolchain_archive")):
        if audit[audit_key] != files[file_key]:
            raise ReceiptError("source capsule input identity cross-check failed")
    if audit["kernel_release"] != "6.18.48-1.openmythos.fc44.x86_64" or type(audit["source_date_epoch"]) is not int or audit["source_date_epoch"] != SOURCE_DATE_EPOCH:
        raise ReceiptError("source capsule kernel policy differs")
    commands = exact(audit["commands"], {"gcc", "ld", "make", "python3", "rpm", "rpmbuild"})
    if any(not isinstance(item, str) or not item or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in commands.values()):
        raise ReceiptError("source capsule command identity is invalid")
    oci = exact(value["oci_rootfs"], {"archive_sha256", "config_digest", "diff_ids", "non_root_entry_count", "layer_digests", "manifest_digest", "root_entry", "semantic_sha256"})
    digest(oci["semantic_sha256"])
    digest(oci["manifest_digest"], prefixed=True)
    digest(oci["config_digest"], prefixed=True)
    if oci["archive_sha256"] != files["toolchain_archive"] or oci["config_digest"] != audit["toolchain_config_expected"] or oci["manifest_digest"] != audit["toolchain_manifest_digest"] or type(oci["non_root_entry_count"]) is not int or oci["non_root_entry_count"] != 138619:
        raise ReceiptError("source capsule OCI cross-check failed")
    reference = audit["toolchain_image_reference"]
    if not isinstance(reference, str) or re.fullmatch(r"[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}", reference) is None or reference.split("@", 1)[1] != oci["manifest_digest"]:
        raise ReceiptError("source capsule image reference is invalid")
    for field in ("diff_ids", "layer_digests"):
        if not isinstance(oci[field], list) or not oci[field]:
            raise ReceiptError("source capsule layer authority is invalid")
        for item in oci[field]:
            digest(item, prefixed=True)
    if len(oci["diff_ids"]) != len(oci["layer_digests"]):
        raise ReceiptError("source capsule layer counts differ")
    root = exact(oci["root_entry"], {"path", "kind", "mode", "uid", "gid", "mtime_ns", "size", "content_sha256", "symlink_target", "xattrs", "hardlink_group"})
    if any(type(root[key]) is not int for key in ("mode", "uid", "gid", "mtime_ns", "size")) or root["mtime_ns"] < 0 or {key: root[key] for key in root if key != "mtime_ns"} != {"path": "/", "kind": "directory", "mode": 493, "uid": 0, "gid": 0, "size": 0, "content_sha256": None, "symlink_target": None, "xattrs": [], "hardlink_group": None}:
        raise ReceiptError("source capsule root semantics differ")
    if value["private_key"] != {"bound": True, "digest_recorded": False, "mode": "0600"} or any(type(value["private_key"][key]) is not bool for key in ("bound", "digest_recorded")):
        raise ReceiptError("source capsule key scope is invalid")
    if value["tcb"] != "trusted clean initial launch; trusted host kernel/filesystem and audited absolute runtime tools; exclusive non-malicious build UID/process set" or value["out_of_scope"] != "pre-entry loader compromise, ptrace or proc-fd theft, active same-UID compromise, and coordinated replacement after receipt return":
        raise ReceiptError("source capsule threat model differs")
    authority = exact(value["bootstrap_authority"], {"schema_version", "bootstrap_tcb", "capsule_sha256", "files", "ordered_paths"})
    if type(authority["schema_version"]) is not int or authority["schema_version"] != 1 or authority["bootstrap_tcb"] != "launcher-held-descriptor-open" or authority["ordered_paths"] != list(BOOTSTRAP_SOURCE_PATHS):
        raise ReceiptError("source capsule bootstrap authority differs")
    records = exact(authority["files"], set(BOOTSTRAP_SOURCE_PATHS))
    for relative, record in records.items():
        exact(record, {"mode", "sha256", "size"})
        if record["sha256"] != files[relative] or type(record["size"]) is not int or record["size"] < 0 or record["mode"] != ("0755" if relative.endswith(".sh") else "0644"):
            raise ReceiptError("source capsule executed closure differs")
    for field in ("bootstrap_authority_sha256", "executed_capsule_sha256", "verifier_capsule_sha256"):
        digest(value[field])
    if value["bootstrap_authority_sha256"] != hashlib.sha256(_canonical_json(authority)).hexdigest() or value["executed_capsule_sha256"] != value["verifier_capsule_sha256"] or value["executed_capsule_sha256"] != authority["capsule_sha256"]:
        raise ReceiptError("source capsule execution identity cross-check failed")
    return value


def _evidence_exact(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiptError("public evidence object schema is not exact")
    return value


def _evidence_same(left: Any, right: Any) -> bool:
    # Python value equality aliases JSON false/0 and true/1.
    return _canonical_json(left) == _canonical_json(right)


def _evidence_integer(value: Any, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise ReceiptError("public evidence integer is invalid")


def _evidence_digest(value: Any) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ReceiptError("public evidence digest is invalid")


def _evidence_path(value: Any) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or any(ord(char) < 32 for char in value) or os.fspath(Path(value)) != value or ".." in Path(value).parts:
        raise ReceiptError("public evidence path is not canonical")
    return Path(value)


_RUNTIME_STAT_FIELDS = {
    "dev", "gid", "ino", "mode", "mtime_ns", "ctime_ns",
    "nlink", "size", "type", "uid",
}
_RUNTIME_EVENT_FIELDS = {"cookie", "mask", "name", "watch"}
_RUNTIME_MULTISET_FIELDS = {*_RUNTIME_EVENT_FIELDS, "count"}
_RUNTIME_LIMITS = {
    "max_event_bytes": 65536,
    "max_events": 1024,
    "max_middle_events": 16,
}


def _validate_runtime_stat_evidence(
    value: Any,
    *,
    expected_uid: int,
    expected_gid: int,
    kind: int,
    mode: int | None = None,
    nlink: int | None = None,
) -> dict[str, Any]:
    record = _evidence_exact(value, _RUNTIME_STAT_FIELDS)
    for field in _RUNTIME_STAT_FIELDS:
        _evidence_integer(record[field])
    if (
        record["ino"] == 0
        or record["mode"] > 0o7777
        or record["uid"] != expected_uid
        or record["gid"] != expected_gid
        or record["type"] != kind
        or (mode is not None and record["mode"] != mode)
        or (nlink is not None and record["nlink"] != nlink)
        or (nlink != 0 and record["nlink"] == 0)
    ):
        raise ReceiptError("runtime metadata authority differs")
    return record


def _validate_runtime_listing(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ReceiptError("runtime listing is not a list")
    for name in value:
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in name)
        ):
            raise ReceiptError("runtime listing basename is unsafe")
    if value != sorted(set(value)):
        raise ReceiptError("runtime listing is not sorted and unique")
    return value


def _validate_runtime_event_evidence(
    events: Any,
    multiset: Any,
) -> list[dict[str, Any]]:
    if not isinstance(events, list) or not isinstance(multiset, list):
        raise ReceiptError("runtime events and multiset must be lists")

    def event_key(value: Any, *, counted: bool) -> tuple[int, int, int, str]:
        row = _evidence_exact(value, _RUNTIME_MULTISET_FIELDS if counted else _RUNTIME_EVENT_FIELDS)
        _evidence_integer(row["watch"], 1)
        _evidence_integer(row["mask"])
        _evidence_integer(row["cookie"])
        if not isinstance(row["name"], str):
            raise ReceiptError("runtime event name is not a string")
        if counted:
            _evidence_integer(row["count"], 1)
        return row["watch"], row["mask"], row["cookie"], row["name"]

    counts = Counter(event_key(event, counted=False) for event in events)
    keys = [event_key(row, counted=True) for row in multiset]
    if keys != sorted(set(keys)):
        raise ReceiptError("runtime event multiset is not sorted and unique")
    expected = [
        {"watch": watch, "mask": mask, "cookie": cookie, "name": name, "count": count}
        for (watch, mask, cookie, name), count in sorted(counts.items())
    ]
    if not _evidence_same(multiset, expected):
        raise ReceiptError("runtime event multiset differs from ordered events")
    return events


def _validate_runtime_input_binding(
    value: Any,
    *,
    config_target: Mapping[str, Any],
    conmon_target: Mapping[str, Any] | None,
    expected_uid: int,
    expected_gid: int,
) -> None:
    watcher = _evidence_exact(value, {
        "basenames", "coalesced_parent_watch_count",
        "parent_fields_excluding_time", "persistent_parent_listing",
        "policy", "schema", "stop_projection",
    })
    basenames = _evidence_exact(watcher["basenames"], {"config", "containerenv"})
    _evidence_integer(watcher["coalesced_parent_watch_count"], 1)
    if (
        basenames != {"config": "config.json", "containerenv": ".containerenv"}
        or watcher["coalesced_parent_watch_count"] != 2
        or watcher["parent_fields_excluding_time"] != ["dev", "ino", "type", "mode", "uid", "gid", "nlink", "size"]
        or watcher["persistent_parent_listing"] != "exact"
        or watcher["schema"] != "openmythos-runtime-input-binding-v2"
        or watcher["policy"] != "inotify-reserved-lifecycle-fail-closed-v1"
    ):
        raise ReceiptError("runtime watcher policy differs")
    stop = _evidence_exact(watcher["stop_projection"], {
        "allowed_removed_names", "endpoint_metadata", "event_multiset",
        "observed_events", "post_listing", "post_parent_metadata",
        "pre_listing", "pre_parent_metadata", "reserved_lifecycle",
        "state", "survivor_metadata",
    })
    reserved = _evidence_exact(stop["reserved_lifecycle"], {"initial", "start", "stop"})
    start = _evidence_exact(reserved["start"], {
        "current_present", "event_multiset", "initial_present", "limits",
        "observed_events", "post_listing", "post_parent_metadata",
        "pre_listing", "pre_parent_metadata", "state", "target_after", "target_before",
    })
    reserved_stop = _evidence_exact(reserved["stop"], {
        "current_present", "event_multiset", "limits", "observed_events",
        "post_listing", "post_parent_metadata", "pre_listing",
        "pre_parent_metadata", "state", "target_after", "target_before",
    })
    if (
        type(start["initial_present"]) is not bool
        or start["current_present"] is not True
        or start["state"] != "post-start"
        or reserved_stop["current_present"] is not False
        or reserved_stop["state"] != "post-stop"
    ):
        raise ReceiptError("runtime PID lifecycle state differs")
    for phase in (start, reserved_stop):
        limits = _evidence_exact(phase["limits"], set(_RUNTIME_LIMITS))
        for field, expected in _RUNTIME_LIMITS.items():
            _evidence_integer(limits[field])
            if limits[field] != expected:
                raise ReceiptError("runtime PID event limits differ")

    def runtime_stat(record: Any, kind: int, mode: int | None = None, nlink: int | None = None) -> dict[str, Any]:
        return _validate_runtime_stat_evidence(
            record, expected_uid=expected_uid, expected_gid=expected_gid,
            kind=kind, mode=mode, nlink=nlink,
        )

    target_fields = {"dev", "gid", "ino", "mode", "nlink", "type", "uid"}

    def bind_target(target: Any, record: Mapping[str, Any], label: str) -> None:
        target = _evidence_exact(target, {*target_fields, "present"})
        for field in target_fields:
            _evidence_integer(target[field])
        if target["present"] is not True or any(target[field] != record[field] for field in target_fields):
            raise ReceiptError(f"runtime {label} target identity differs")

    survivors = ["artifacts", "config.json", "secrets", "shm"]
    for field in ("allowed_removed_names", "pre_listing", "post_listing"):
        _validate_runtime_listing(stop[field])
    if (
        stop["state"] != "post-stop"
        or stop["allowed_removed_names"] != ["attach", "ctl", "winsz"]
        or stop["pre_listing"] != ["artifacts", "attach", "config.json", "ctl", "secrets", "shm", "winsz"]
        or stop["post_listing"] != survivors
    ):
        raise ReceiptError("runtime stop state differs")
    for name, record in _evidence_exact(stop["endpoint_metadata"], {"attach", "ctl", "winsz"}).items():
        runtime_stat(record, stat.S_IFSOCK if name == "attach" else stat.S_IFIFO, 0o700 if name == "attach" else 0o640, 1)
        if record["size"] != 0:
            raise ReceiptError("runtime stop endpoint differs")
    for name, pair in _evidence_exact(stop["survivor_metadata"], set(survivors)).items():
        _evidence_exact(pair, {"before", "after"})
        for field in ("before", "after"):
            runtime_stat(pair[field], stat.S_IFREG if name == "config.json" else stat.S_IFDIR, 0o644 if name == "config.json" else 0o700 if name == "shm" else 0o755)
        if not _evidence_same(pair["before"], pair["after"]):
            raise ReceiptError("runtime stop survivor changed")
    bind_target(config_target, stop["survivor_metadata"]["config.json"]["before"], "config")
    for field in ("pre_parent_metadata", "post_parent_metadata"):
        runtime_stat(stop[field], stat.S_IFDIR)
    stable_parent_fields = {"dev", "ino", "type", "mode", "uid", "gid", "nlink"}
    if any(stop["pre_parent_metadata"][field] != stop["post_parent_metadata"][field] for field in stable_parent_fields):
        raise ReceiptError("runtime stop parent changed")

    initial = runtime_stat(reserved["initial"], stat.S_IFREG, nlink=1)
    runtime_stat(start["target_after"], stat.S_IFREG, nlink=1)
    runtime_stat(reserved_stop["target_before"], stat.S_IFREG, nlink=1)
    if not _evidence_same(initial, start["target_after"]):
        raise ReceiptError("runtime PID initial/start metadata differs")
    if not _evidence_same(initial, reserved_stop["target_before"]):
        raise ReceiptError("runtime PID start/stop metadata differs")
    if start["initial_present"]:
        runtime_stat(start["target_before"], stat.S_IFREG, nlink=1)
        if not _evidence_same(initial, start["target_before"]):
            raise ReceiptError("runtime PID initially present metadata differs")
        bind_target(conmon_target, start["target_before"], "PID")
    elif start["target_before"] is not None or conmon_target is not None:
        raise ReceiptError("runtime PID initially absent target is present")
    after_unlink = runtime_stat(reserved_stop["target_after"], stat.S_IFREG, nlink=0)
    if any(initial[field] != after_unlink[field] for field in _RUNTIME_STAT_FIELDS - {"nlink", "ctime_ns"}):
        raise ReceiptError("runtime PID unlinked metadata differs")

    for phase in (start, reserved_stop):
        for field in ("pre_listing", "post_listing"):
            _validate_runtime_listing(phase[field])
        for field in ("pre_parent_metadata", "post_parent_metadata"):
            runtime_stat(phase[field], stat.S_IFDIR)
        if any(phase["pre_parent_metadata"][field] != phase["post_parent_metadata"][field] for field in stable_parent_fields):
            raise ReceiptError("runtime PID parent transition identity differs")
    if any(start["post_parent_metadata"][field] != reserved_stop["pre_parent_metadata"][field] for field in stable_parent_fields | {"size"}):
        raise ReceiptError("runtime PID parent stable interval differs")
    before_listing, after_listing = start["pre_listing"], start["post_listing"]
    if ".containerenv" not in before_listing:
        raise ReceiptError("runtime PID parent lacks containerenv")
    if start["initial_present"]:
        if "conmon.pid" not in before_listing or before_listing != after_listing:
            raise ReceiptError("runtime PID present start listing differs")
    elif "conmon.pid" in before_listing or sorted([*before_listing, "conmon.pid"]) != after_listing:
        raise ReceiptError("runtime PID absent start listing delta differs")
    if (
        reserved_stop["pre_listing"] != after_listing
        or reserved_stop["post_listing"] != [name for name in after_listing if name != "conmon.pid"]
    ):
        raise ReceiptError("runtime PID stop listing delta differs")

    for phase in (stop, start, reserved_stop):
        _validate_runtime_event_evidence(phase["observed_events"], phase["event_multiset"])

    start_events = start["observed_events"]
    if start["initial_present"]:
        if start_events:
            raise ReceiptError("runtime PID present-start events differ")
    else:
        masks = [event["mask"] for event in start_events]
        middle = masks[1:-1]
        if (
            len(masks) < 2
            or masks[0] != 256
            or masks[-1] != 8
            or masks.count(256) != 1
            or masks.count(8) != 1
            or len(middle) > _RUNTIME_LIMITS["max_middle_events"]
            or any(mask not in {2, 4} for mask in middle)
        ):
            raise ReceiptError("runtime PID start event grammar differs")
        if any(
            event["name"] != "conmon.pid"
            or event["cookie"] != 0
            or event["watch"] != start_events[0]["watch"]
            for event in start_events
        ):
            raise ReceiptError("runtime PID start event identity differs")

    stop_events = stop["observed_events"]
    sequences = {"attach": [512], "ctl": [8, 512], "winsz": [8, 512], "conmon.pid": [512]}
    if len(stop_events) != 6 or any(
        event["cookie"] != 0 or event["name"] not in sequences
        for event in stop_events
    ):
        raise ReceiptError("runtime stop event identity differs")
    for name, masks in sequences.items():
        if [event["mask"] for event in stop_events if event["name"] == name] != masks:
            raise ReceiptError("runtime stop event grammar differs")
    config_watches = {event["watch"] for event in stop_events if event["name"] != "conmon.pid"}
    pid_events = [event for event in stop_events if event["name"] == "conmon.pid"]
    pid_watch = pid_events[0]["watch"]
    if len(config_watches) != 1 or pid_watch in config_watches:
        raise ReceiptError("runtime stop watches differ")
    if not start["initial_present"] and start_events[0]["watch"] != pid_watch:
        raise ReceiptError("runtime PID start/stop watch differs")
    pid_multiset = [row for row in stop["event_multiset"] if row["name"] == "conmon.pid"]
    if (
        not _evidence_same(reserved_stop["observed_events"], pid_events)
        or not _evidence_same(reserved_stop["event_multiset"], pid_multiset)
    ):
        raise ReceiptError("runtime PID stop projection differs")


def _validate_runtime_evidence(
    rootfs: Any, contract: Any, capsule: Mapping[str, Any], *,
    repository: Path, builder: str, expected_uid: int, expected_gid: int,
    probe_root: Path | None = None,
) -> None:
    roles = ("build", "inspection") if probe_root is None else ("probe",)
    _evidence_exact(rootfs, {"schema_version", "expected", *roles})
    _evidence_exact(contract, {"schema_version", *roles, "key_scope", "stores_distinct", "repository_mounted"})
    for record in (rootfs, contract):
        _evidence_integer(record["schema_version"], 1)
        if record["schema_version"] != 1:
            raise ReceiptError("runtime evidence schema version differs")
    key_scope = {"probe": False, "build": True, "inspection": False} if probe_root is None else {"probe": False}
    if not _evidence_same(rootfs["expected"], capsule["oci_rootfs"]) or contract["key_scope"] != key_scope or any(type(item) is not bool for item in contract["key_scope"].values()) or contract["stores_distinct"] is not True or contract["repository_mounted"] is not False:
        raise ReceiptError("runtime evidence authority or key scope differs")
    expected = capsule["oci_rootfs"]
    authority = {key: expected[key] for key in ("archive_sha256", "config_digest", "diff_ids", "manifest_digest", "semantic_sha256")}
    policy = {"containers_conf_sha256": hashlib.sha256(_PODMAN_CONTAINERS_CONF).hexdigest(), "storage_conf_sha256": hashlib.sha256(_PODMAN_STORAGE_CONF).hexdigest()}
    environment = ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "SOURCE_DATE_EPOCH=1787899659", "HOME=/tmp", "HOSTNAME=openmythos-builder"]
    transitions = ["CREATED", "CREATED_INIT", "CONFIG_AUDITED", "CREATED_INIT_AUDITED", "STARTED_UNATTESTED", "LIVE_ATTESTED", "AUTHORIZED_ROOTFS_AUDITED", "WORK_AUTHORIZED", "STOPPED", "REMOVED"]
    scratch_ids: set[tuple[int, int]] = set()
    store_ids: set[tuple[int, int]] = set()

    def integers(record: Mapping[str, Any]) -> None:
        for value in record.values():
            _evidence_integer(value)

    def raw_stat(record: Any) -> None:
        _evidence_exact(record, {"dev", "ino", "nlink", "mode", "uid", "gid", "rdev", "size", "mtime_ns", "ctime_ns"})
        integers(record)
        if not record["ino"] or not record["nlink"] or stat.S_IFMT(record["mode"]) != stat.S_IFDIR or record["rdev"] != 0:
            raise ReceiptError("root anchor metadata differs")

    def binding(record: Any) -> tuple[int, int]:
        _evidence_exact(record, {"dev", "gid", "ino", "mode", "parent_dev", "parent_ino", "uid"})
        integers(record)
        if record["uid"] != expected_uid or record["gid"] != expected_gid or record["mode"] != 0o700 or not record["ino"] or not record["parent_ino"]:
            raise ReceiptError("runtime directory binding differs")
        return record["dev"], record["ino"]

    for role in roles:
        lifecycle = _evidence_exact(rootfs[role], {"before", "authorized", "live", "after", "transitions", "semantic_equal", "raw_equal"})
        backend = _evidence_exact(contract[role], {"canonical_fixture_sha256", "container_id", "environment", "hooks_present", "mount_destinations", "namespace_types", "pid1", "root_read_only", "config_sha256", "scratch_binding", "runtime_input_binding", "store_bindings", "image_identity", "vfs_normalization", "live_attestation", "sealed_policy_sha256"})
        if not _evidence_same(lifecycle["before"], lifecycle["authorized"]) or not _evidence_same(lifecycle["before"], lifecycle["after"]) or lifecycle["transitions"] != transitions or lifecycle["semantic_equal"] is not True or lifecycle["raw_equal"] is not True or not _evidence_same(lifecycle["live"], backend["live_attestation"]):
            raise ReceiptError("runtime lifecycle cross-fields differ")
        if backend["canonical_fixture_sha256"] != "ca99bb49d1e51ab415dcccf2f14f1026f7cf87911c62e0491cc619633f9d7b30" or backend["environment"] != environment or backend["hooks_present"] is not False or backend["root_read_only"] is not True or backend["pid1"] != ["/usr/bin/sleep", "infinity"] or backend["namespace_types"] != ["pid", "network", "ipc", "uts", "mount", "cgroup"] or backend["mount_destinations"] != ["/tmp", "/proc", "/dev", "/sys", "/tmp/work", "/dev/pts", "/dev/mqueue", "/dev/shm", "/run/.containerenv", "/sys/fs/cgroup"] or backend["sealed_policy_sha256"] != policy:
            raise ReceiptError("runtime fixed policy differs")
        _evidence_digest(backend["config_sha256"])
        if not isinstance(backend["container_id"], str) or re.fullmatch(r"[0-9a-f]{64}", backend["container_id"]) is None:
            raise ReceiptError("runtime container ID differs")
        scratch = backend["scratch_binding"]
        identity = binding(scratch)
        if identity in scratch_ids or identity in store_ids:
            raise ReceiptError("runtime scratch identities alias")
        scratch_ids.add(identity)
        store = _evidence_exact(backend["store_bindings"], {"directories", "reported_paths"})
        directories = _evidence_exact(store["directories"], {"store-base", "store-graphroot", "store-runroot", "store-tmpdir"})
        for record in directories.values():
            identity = binding(record)
            if identity in store_ids or identity in scratch_ids:
                raise ReceiptError("runtime store identities alias")
            store_ids.add(identity)
        for name in ("store-graphroot", "store-runroot", "store-tmpdir"):
            if (directories[name]["parent_dev"], directories[name]["parent_ino"]) != (directories["store-base"]["dev"], directories["store-base"]["ino"]):
                raise ReceiptError("runtime store parent linkage differs")
        parent = repository / "build/gate01" / builder
        base = parent / ("kernel-podman-build" if role == "build" else "kernel-podman-inspect")
        scratch_path = parent / ("kernel-build-scratch" if role == "build" else "kernel-inspection-scratch")
        if probe_root is not None:
            base, scratch_path = probe_root / "store", probe_root / "scratch"
        reported = _evidence_exact(store["reported_paths"], {"OCIConfigPath", "StaticDir", "ConmonPidFile", "rootfs"})
        for label, item in reported.items():
            _evidence_exact(item, {"label", "path", "relative", "root", "target"})
            root = base / ("runroot" if label == "ConmonPidFile" else "root")
            path = _evidence_path(item["path"])
            if item["label"] != label or item["root"] != str(root) or not isinstance(item["relative"], str) or not item["relative"] or item["relative"] != path.relative_to(root).as_posix() or path == root:
                raise ReceiptError("runtime reported path linkage differs")
            target = item["target"]
            if target is None and label == "ConmonPidFile":
                continue
            _evidence_exact(target, {"dev", "gid", "ino", "mode", "nlink", "present", "type", "uid"})
            integers({key: value for key, value in target.items() if key != "present"})
            if target["present"] is not True or target["type"] != (stat.S_IFREG if label in {"OCIConfigPath", "ConmonPidFile"} else stat.S_IFDIR) or target["uid"] != expected_uid or target["gid"] != expected_gid or target["mode"] > 0o7777 or not target["ino"] or not target["nlink"]:
                raise ReceiptError("runtime reported target metadata differs")
        container_id = backend["container_id"]
        static_path = base / "root/vfs-containers" / container_id / "userdata"
        expected_paths = {
            "OCIConfigPath": static_path / "config.json",
            "StaticDir": static_path,
            "ConmonPidFile": base / "runroot/vfs-containers" / container_id / "userdata/conmon.pid",
        }
        if any(reported[label]["path"] != str(path) for label, path in expected_paths.items()):
            raise ReceiptError("runtime reported paths do not bind container ID")
        image = _evidence_exact(backend["image_identity"], {"basis", "podman_digest", "oci_authority", "materialized_root_verified"})
        if image["oci_authority"] != authority or image["materialized_root_verified"] is not True or (image["podman_digest"], image["basis"]) not in ((None, "held-archive-and-materialized-root"), (expected["manifest_digest"], "podman-manifest-and-held-archive")):
            raise ReceiptError("runtime imported-image authority differs")
        _validate_runtime_input_binding(
            backend["runtime_input_binding"],
            config_target=reported["OCIConfigPath"]["target"],
            conmon_target=reported["ConmonPidFile"]["target"],
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        phase = _evidence_exact(lifecycle["before"], {"executable_files", "executable_files_sha256", "materialized_non_root_entry_count", "non_root_entry_count", "raw_sha256", "root_anchor", "root_entry", "runtime_projections", "semantic_sha256", "oci_authority"})
        for name, count in (("non_root_entry_count", 138619), ("materialized_non_root_entry_count", 138620)):
            _evidence_integer(phase[name])
            if phase[name] != count:
                raise ReceiptError("runtime rootfs cardinality differs")
        for name in ("executable_files_sha256", "raw_sha256", "semantic_sha256"):
            _evidence_digest(phase[name])
        if not _evidence_same(phase["oci_authority"], authority) or not _evidence_same(phase["root_entry"], expected["root_entry"]):
            raise ReceiptError("runtime rootfs OCI linkage differs")
        anchor = _evidence_exact(phase["root_anchor"], {"basename", "parent", "name", "root"})
        for name in ("parent", "name", "root"):
            raw_stat(anchor[name])
        if any(anchor["root"][key] != phase["root_entry"][key] for key in ("uid", "gid", "mtime_ns")) or stat.S_IMODE(anchor["root"]["mode"]) != phase["root_entry"]["mode"]:
            raise ReceiptError("runtime raw and semantic root metadata differ")
        if anchor["name"] != anchor["root"] or anchor["basename"] != Path(reported["rootfs"]["path"]).name or any(reported["rootfs"]["target"][key] != anchor["root"][key] for key in ("dev", "ino")) or reported["rootfs"]["target"]["mode"] != stat.S_IMODE(anchor["root"]["mode"]):
            raise ReceiptError("runtime root anchor linkage differs")
        projections = _evidence_exact(phase["runtime_projections"], {"/run/.containerenv"})
        projection = _evidence_exact(projections["/run/.containerenv"], set(expected["root_entry"]))
        for key in ("mode", "uid", "gid", "mtime_ns", "size"):
            _evidence_integer(projection[key])
        _evidence_digest(projection["content_sha256"])
        if projection["path"] != "/run/.containerenv" or projection["kind"] != "file" or projection["mode"] > 0o7777 or projection["symlink_target"] is not None or projection["hardlink_group"] is not None or not isinstance(projection["xattrs"], list):
            raise ReceiptError("runtime projection semantic fields differ")
        xattr_names: list[str] = []
        for item in projection["xattrs"]:
            if not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str) or not item[0] or "\0" in item[0]:
                raise ReceiptError("runtime projection xattr schema differs")
            value = _evidence_exact(item[1], {"hex"})["hex"]
            if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-f]{2})*", value) is None:
                raise ReceiptError("runtime projection xattr value differs")
            xattr_names.append(item[0])
        if xattr_names != sorted(set(xattr_names)):
            raise ReceiptError("runtime projection xattrs are not canonical")
        executables = phase["executable_files"]
        if not isinstance(executables, dict) or not executables or _object_sha256(executables) != phase["executable_files_sha256"]:
            raise ReceiptError("runtime executable index digest differs")
        for path, executable in executables.items():
            _evidence_path(path)
            _evidence_exact(executable, {"content_sha256", "dev", "gid", "ino", "mode", "size", "uid"})
            _evidence_digest(executable["content_sha256"])
            integers({key: value for key, value in executable.items() if key != "content_sha256"})
            if executable["mode"] > 0o7777 or not executable["mode"] & 0o111 or not executable["ino"] or not executable["size"]:
                raise ReceiptError("runtime executable index metadata differs")
        live = _evidence_exact(lifecycle["live"], {"host", "inside"})
        validate_live_process_record(live["host"], expected_uid=expected_uid, expected_gid=expected_gid)
        inside = _evidence_exact(live["inside"], {"root_read_only", "nonce", "process_set", "scratch_device", "scratch_inode", "scratch_options", "verdict"})
        _evidence_digest(inside["nonce"])
        for key in ("scratch_device", "scratch_inode"):
            _evidence_integer(inside[key])
        processes = inside["process_set"]
        if not isinstance(processes, list) or len(processes) != 2 or any(type(pid) is not int for pid in processes) or processes[0] != 1 or processes[1] <= 1 or inside["root_read_only"] is not True or inside["verdict"] != "pass" or inside["scratch_device"] != scratch["dev"] or inside["scratch_inode"] != scratch["ino"] or inside["scratch_options"] != ["nodev", "nosuid", "relatime", "rw"]:
            raise ReceiptError("runtime inside attestation differs")
        for executable in (live["host"]["exe"], *live["host"]["mapped_files"].values()):
            view = {("content_sha256" if key == "sha256" else key): value for key, value in executable.items() if key not in {"path", "ranges"}}
            if executables.get(executable["path"]) != view:
                raise ReceiptError("runtime live executable differs from rootfs index")
        graph = live["host"]["mount_graph"]
        if graph["root_device"] != f"{os.major(anchor['root']['dev'])}:{os.minor(anchor['root']['dev'])}":
            raise ReceiptError("runtime mount root device differs")
        specification = {"root": {"path": reported["rootfs"]["path"]}, "mounts": [{"destination": "/tmp/work", "source": str(scratch_path)}, {"destination": "/run/.containerenv", "source": str(Path(reported["ConmonPidFile"]["path"]).parent / ".containerenv")}], "linux": {"maskedPaths": list(EXPECTED_MASKED_PATHS), "readonlyPaths": list(EXPECTED_READONLY_PATHS)}}
        validate_live_mount_graph(graph, expected_uid=expected_uid, expected_gid=expected_gid, specification=specification, ownership_projection=_projection_from_record(live["host"]["ownership_projection"]))
        from tools.gate01.oci_rootfs import _NORMALIZATION_SCHEMA_FIELDS
        normalization = _evidence_exact(backend["vfs_normalization"], _NORMALIZATION_SCHEMA_FIELDS)
        if not isinstance(normalization["directory_mtimes"], dict) or not isinstance(normalization["runtime_bind_targets"], dict) or not isinstance(normalization["hardlinks"], list) or not set(normalization["runtime_bind_targets"]) <= {"/run/.containerenv"}:
            raise ReceiptError("runtime normalization schema differs")
        for path, item in normalization["directory_mtimes"].items():
            _evidence_path(path)
            _evidence_exact(item, {"from_mtime_ns", "to_mtime_ns"})
            integers(item)
            if item["from_mtime_ns"] == item["to_mtime_ns"] or path in executables or path in projections or (path == "/" and item["to_mtime_ns"] != expected["root_entry"]["mtime_ns"]):
                raise ReceiptError("runtime directory normalization differs")
        for item in normalization["runtime_bind_targets"].values():
            _evidence_exact(item, {"from_mode", "from_mtime_ns", "to_mode", "to_mtime_ns"})
            integers(item)
            if item["to_mode"] != projection["mode"] or item["to_mtime_ns"] != projection["mtime_ns"] or item["from_mode"] > 0o7777:
                raise ReceiptError("runtime normalization destination differs")
        repaired: set[str] = set()
        for item in normalization["hardlinks"]:
            _evidence_exact(item, {"field", "path", "representative", "before", "result", "displaced"})
            path, representative = _evidence_path(item["path"]), _evidence_path(item["representative"])
            if item["field"] != "hardlink_group" or str(path) in repaired or path == representative or any(str(value) in executables or str(value) in projections or str(value) == "/" for value in (path, representative)):
                raise ReceiptError("runtime hardlink normalization differs")
            repaired.add(str(path))
            for name in ("before", "result"):
                _evidence_exact(item[name], {"dev", "ino", "nlink"})
                integers(item[name])
                if not item[name]["ino"] or not item[name]["nlink"]:
                    raise ReceiptError("runtime hardlink normalization metadata differs")
            if item["before"]["dev"] != item["result"]["dev"] or item["before"]["ino"] == item["result"]["ino"] or item["result"]["nlink"] < 2:
                raise ReceiptError("runtime hardlink normalization result differs")
        root_row = {**anchor["root"], "path": "/", "name": anchor["basename"], "parent_dev": anchor["parent"]["dev"], "parent_ino": anchor["parent"]["ino"]}
        _validate_normalization_operations(normalization, root_row, final_raw_sha256=phase["raw_sha256"], final_entry_count=phase["materialized_non_root_entry_count"] + 1)


def _validate_normalization_operations(normalization: Mapping[str, Any], final_root: Mapping[str, Any], *, final_raw_sha256: str, final_entry_count: int) -> None:
    from tools.gate01.oci_rootfs import RawEntry, _NORMALIZATION_SCHEMA_FIELDS, _REPAIR_WATCH_PROFILE, _decode_normalization_ledger
    _evidence_exact(normalization, _NORMALIZATION_SCHEMA_FIELDS)
    if type(normalization["schema_version"]) is not int or normalization["schema_version"] != 3 or normalization["watch_profile"] != _REPAIR_WATCH_PROFILE:
        raise ReceiptError("normalization evidence version differs")
    _evidence_digest(final_raw_sha256)
    _evidence_integer(final_entry_count, 1)
    _evidence_exact(final_root, set(RawEntry.__dataclass_fields__))
    initial = _decode_normalization_ledger(normalization["initial_raw_ledger"])
    if len(initial) != final_entry_count:
        raise ReceiptError("normalization whole-ledger cardinality differs")
    groups = normalization["repair_groups"]
    if not isinstance(groups, dict) or not isinstance(normalization["hardlinks"], list) or not isinstance(normalization["directory_mtimes"], dict) or not isinstance(normalization["runtime_bind_targets"], dict):
        raise ReceiptError("normalization authority schema differs")
    for label, fields in (("directory_mtimes", {"from_mtime_ns", "to_mtime_ns"}), ("runtime_bind_targets", {"from_mode", "to_mode", "from_mtime_ns", "to_mtime_ns"})):
        for path, item in normalization[label].items():
            _evidence_path(path)
            _evidence_exact(item, fields)
            for number in item.values():
                _evidence_integer(number)
    members: set[str] = set()
    expected_targets: list[str] = []
    representatives: dict[str, str] = {}
    for representative, paths in sorted(groups.items()):
        _evidence_path(representative)
        if not isinstance(paths, list) or len(paths) < 2 or any(not isinstance(path, str) for path in paths) or paths != sorted(set(paths)) or representative != paths[0] or members.intersection(paths):
            raise ReceiptError("normalization authorized group membership differs")
        for path in paths:
            _evidence_path(path)
            if path not in initial or not stat.S_ISLNK(initial[path].mode):
                raise ReceiptError("normalization group member is absent or not a symlink")
            representatives[path] = representative
        members.update(paths)
        source = initial[representative]
        targets = [path for path in paths if (initial[path].dev, initial[path].ino) != (source.dev, source.ino)]
        if not targets:
            raise ReceiptError("normalization authorized group is already intact")
        expected_targets.extend(targets)
    if [item.get("path") for item in normalization["hardlinks"] if isinstance(item, dict)] != expected_targets or len(normalization["hardlinks"]) != len(expected_targets):
        raise ReceiptError("normalization repair order or coverage differs")
    classes: dict[tuple[int, int], set[str]] = {}
    if groups:
        for path, row in initial.items():
            if stat.S_ISLNK(row.mode): classes.setdefault((row.dev, row.ino), set()).add(path)
    displaced_state: dict[tuple[int, int], dict[str, Any]] = {}
    raw_stat_fields = {"dev", "ino", "nlink", "mode", "uid", "gid", "rdev", "size", "mtime_ns", "ctime_ns"}
    for item in normalization["hardlinks"]:
        _evidence_exact(item, {"field", "path", "representative", "before", "result", "displaced"})
        path = item["path"]
        original = initial[path]
        representative = representatives[path]
        source = initial[representative]
        if not classes[(source.dev, source.ino)] <= set(groups[representative]):
            raise ReceiptError("normalization representative aliases cross authorized groups")
        if item["field"] != "hardlink_group" or item["representative"] != representative:
            raise ReceiptError("normalization representative authority differs")
        for field in ("before", "result"):
            _evidence_exact(item[field], {"dev", "ino", "nlink"})
            for number in item[field].values(): _evidence_integer(number, 1)
        if item["before"] != {field: getattr(original, field) for field in ("dev", "ino", "nlink")} or item["result"] != {"dev": source.dev, "ino": source.ino, "nlink": len(groups[representative])}:
            raise ReceiptError("normalization original/result inode authority differs")
        identity = (original.dev, original.ino)
        aliases = classes[identity]
        if not aliases <= set(groups[representative]):
            raise ReceiptError("normalization displaced aliases cross authorized groups")
        displaced = _evidence_exact(item["displaced"], {"aliases_before", "aliases_after", "before", "result"})
        previous = displaced_state.get(identity, {field: getattr(original, field) for field in raw_stat_fields})
        before, result = displaced["before"], displaced["result"]
        for raw in (before, result):
            _evidence_exact(raw, raw_stat_fields)
            for number in raw.values(): _evidence_integer(number)
        if displaced["aliases_before"] != sorted(aliases) or displaced["aliases_after"] != sorted(aliases - {path}) or before != previous or result["nlink"] != len(aliases) - 1 or any(before[field] != result[field] for field in raw_stat_fields - {"nlink", "ctime_ns"}):
            raise ReceiptError("normalization displaced alias transition differs")
        aliases.remove(path)
        classes[(source.dev, source.ino)].add(path)
        displaced_state[identity] = result
    operations = normalization["raw_operations"]
    if not isinstance(operations, list):
        raise ReceiptError("normalization raw operations are missing")
    raw_fields = {"path", "name", "parent_dev", "parent_ino", "dev", "ino", "nlink", "mode", "uid", "gid", "rdev", "size", "mtime_ns", "ctime_ns"}
    last: dict[str, dict[str, Any]] = {}
    directory_paths, runtime_paths, repaired_paths = set(), set(), set()
    repairs = {item["path"]: item for item in normalization["hardlinks"]}
    parents = {str(Path(path).parent) for path in repairs}
    reconstructed = dict(initial) if operations else initial
    expected_order = ([("symlink_hardlink", None)] if repairs else []) + [("runtime_bind_target", path) for path in sorted(normalization["runtime_bind_targets"])] + [("directory_mtime", path) for path in sorted(normalization["directory_mtimes"], key=lambda value: (value.count("/"), value), reverse=True)]
    observed_order = []
    for operation in operations:
        _evidence_exact(operation, {"operation", "entries"})
        kind, entries = operation["operation"], operation["entries"]
        if kind not in {"directory_mtime", "runtime_bind_target", "symlink_hardlink"} or not isinstance(entries, dict) or not entries:
            raise ReceiptError("normalization raw operation differs")
        if kind != "symlink_hardlink" and len(entries) != 1:
            raise ReceiptError("normalization metadata operation is not singular")
        observed_order.append((kind, None if kind == "symlink_hardlink" else next(iter(entries))))
        if kind == "symlink_hardlink" and set(entries) != members | parents:
            raise ReceiptError("normalization repair raw coverage is not exact")
        for path, change in entries.items():
            _evidence_path(path)
            _evidence_exact(change, {"before", "result"})
            before, result = change["before"], change["result"]
            for record in (before, result):
                _evidence_exact(record, raw_fields)
                if record["path"] != path or not isinstance(record["name"], str) or (path != "/" and record["name"] != Path(path).name):
                    raise ReceiptError("normalization raw path binding differs")
                for field in raw_fields - {"path", "name"}:
                    _evidence_integer(record[field])
            if path not in reconstructed or before == result or before != _json_safe(reconstructed[path]):
                raise ReceiptError("normalization raw operation chain differs")
            allowed = {"ctime_ns"}
            if kind == "directory_mtime":
                if path not in normalization["directory_mtimes"] or path in directory_paths or stat.S_IFMT(before["mode"]) != stat.S_IFDIR or before["mtime_ns"] == result["mtime_ns"] or before["mtime_ns"] != normalization["directory_mtimes"][path]["from_mtime_ns"] or result["mtime_ns"] != normalization["directory_mtimes"][path]["to_mtime_ns"]:
                    raise ReceiptError("normalization directory operation differs")
                directory_paths.add(path)
                allowed.add("mtime_ns")
            elif kind == "runtime_bind_target":
                if path not in normalization["runtime_bind_targets"] or path in runtime_paths or stat.S_IFMT(before["mode"]) != stat.S_IFREG:
                    raise ReceiptError("normalization runtime operation differs")
                declared = normalization["runtime_bind_targets"][path]
                if (before["mode"], before["mtime_ns"]) == (result["mode"], result["mtime_ns"]):
                    raise ReceiptError("normalization runtime operation is a no-op")
                if before["mode"] != stat.S_IFREG | declared["from_mode"] or result["mode"] != stat.S_IFREG | declared["to_mode"] or before["mtime_ns"] != declared["from_mtime_ns"] or result["mtime_ns"] != declared["to_mtime_ns"]:
                    raise ReceiptError("normalization runtime result differs")
                runtime_paths.add(path)
                allowed.update({"mode", "mtime_ns"})
            elif stat.S_IFMT(before["mode"]) == stat.S_IFDIR:
                if path not in parents:
                    raise ReceiptError("normalization unrelated parent changed")
                allowed.update({"size", "mtime_ns"})
            elif stat.S_IFMT(before["mode"]) == stat.S_IFLNK:
                allowed.add("nlink")
                if path in repairs:
                    declared = repairs[path]
                    if any(before[field] != declared["before"][field] or result[field] != declared["result"][field] for field in ("dev", "ino", "nlink")):
                        raise ReceiptError("normalization hardlink result differs")
                    allowed.add("ino")
                    repaired_paths.add(path)
                elif not any(result["dev"] == item["result"]["dev"] and result["ino"] == item["result"]["ino"] and result["nlink"] == item["result"]["nlink"] for item in repairs.values()):
                    raise ReceiptError("normalization unrelated symlink changed")
            else:
                raise ReceiptError("normalization ordinary file changed")
            if any(before[field] != result[field] for field in raw_fields - allowed):
                raise ReceiptError("normalization unauthorized raw field changed")
            last[path] = result
            reconstructed[path] = RawEntry(**result)
    if observed_order != expected_order:
        raise ReceiptError("normalization exact operation order differs")
    if directory_paths != set(normalization["directory_mtimes"]) or runtime_paths != set(normalization["runtime_bind_targets"]) or repaired_paths != set(repairs):
        raise ReceiptError("normalization operations do not cover declared delta")
    if any(getattr(reconstructed["/"], field) != value for field, value in final_root.items()):
        raise ReceiptError("normalization root result differs from accepted anchor")
    for representative, paths in groups.items():
        source = initial[representative]
        if any((reconstructed[path].dev, reconstructed[path].ino, reconstructed[path].nlink) != (source.dev, source.ino, len(paths)) for path in paths):
            raise ReceiptError("normalization terminal group differs")
    actual_hash = _object_sha256(reconstructed) if operations else normalization["initial_raw_ledger"]["sha256"]
    if actual_hash != final_raw_sha256:
        raise ReceiptError("normalization reconstructed whole-audit hash differs")


def _validate_auxiliary_evidence(
    descriptor: Callable[[str], int], *, repository: Path, builder: str,
    manifest: Mapping[str, Any], capsule: Mapping[str, Any],
    expected_uid: int, expected_gid: int,
) -> None:
    rootfs = _strict_json_descriptor(descriptor("rootfs-audit.json"), "rootfs audit")
    contract = _strict_json_descriptor(descriptor("container-contract.json"), "container contract")
    _validate_runtime_evidence(rootfs, contract, capsule, repository=repository, builder=builder, expected_uid=expected_uid, expected_gid=expected_gid)
    leakage = _strict_json_descriptor(descriptor("leakage-scan.json"), "leakage scan")
    if leakage != {"schema_version": 1, "verdict": "pass", "key_identity_digest_recorded": False, "roots": ["build-scratch", "inspection-scratch", "candidate"], "held_artifacts": sorted(ARTIFACT_FD_ROLES)} or type(leakage["schema_version"]) is not int or leakage["key_identity_digest_recorded"] is not False:
        raise ReceiptError("leakage scan evidence differs")
    if _read_descriptor(descriptor("compiler-version.txt")) != (capsule["input_audit"]["commands"]["gcc"] + "\n").encode("utf-8"):
        raise ReceiptError("compiler version differs from audited input")
    report = _strict_json_descriptor(descriptor("build-report.json"), "build report")
    _evidence_exact(report, {"schema_version", "acceptance", "builder_id", "outer_environment", "declared_environment", "artifact_identity", "elapsed_seconds_before_final_scan", "meta_uname_requirements", "network_used", "receipt", "source_capsule_sha256", "toolchain_manifest_digest"})
    _evidence_integer(report["schema_version"])
    elapsed = report["elapsed_seconds_before_final_scan"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise ReceiptError("build report elapsed interval is invalid")
    expected_identity = {
        "binary_nevras": sorted(package["nevra"] for package in manifest["binary_rpms"]),
        "installed_files_sha256": _hash_descriptor(descriptor("installed-files.json")),
        "kernel_release": manifest["kernel_release"], "rpm_manifest_sha256": _hash_descriptor(descriptor("rpm-artifacts.json")),
        "rpm_sha256": {"srpm": manifest["source_rpms"][0]["sha256"], **{{"kernel-openmythos": "meta", "kernel-openmythos-core": "core", "kernel-openmythos-modules": "modules"}[package["name"]]: package["sha256"] for package in manifest["binary_rpms"]}},
        "source_nevra": manifest["source_rpms"][0]["nevra"],
    }
    if report["schema_version"] != 2 or report["acceptance"] != "pending-detached-receipt" or report["builder_id"] != builder or report["outer_environment"] != _builder_outer_contract(builder) or report["declared_environment"] != {"source_date_epoch": SOURCE_DATE_EPOCH, "tz": "UTC", "locale": "C.UTF-8", "parallelism": 4, "build_host": "openmythos-builder", "build_user": "openmythos", "rpm_buildhost": "openmythos-builder.invalid"} or report["artifact_identity"] != expected_identity or report["meta_uname_requirements"] != sorted([f"kernel-openmythos-core-uname-r = {manifest['kernel_release']}", f"kernel-openmythos-modules-uname-r = {manifest['kernel_release']}"]) or report["network_used"] is not False or report["receipt"] != "kernel.receipt.json" or report["source_capsule_sha256"] != _hash_descriptor(descriptor("source-capsule.json")) or report["toolchain_manifest_digest"] != capsule["input_audit"]["toolchain_manifest_digest"]:
        raise ReceiptError("build report cross-field authority differs")
    transcript = {"builder": builder, "phases": ["input-bind", "oci-derive", "build-create-audit-start-attest-exec", "writer-close", "inspection-create-audit-start-attest-exec", "complete-scan", "cleanup", "receipt-last"]}
    for role in ("build", "inspection"):
        for phase in ("before", "authorized", "after"):
            transcript[f"{role}_rootfs_{phase}"] = rootfs[role][phase]
    log = _read_descriptor(descriptor("build.log"))
    header = b"OPENMYTHOS_GATE01_SUPERVISOR=" + json.dumps(transcript, sort_keys=True).encode("utf-8") + b"\n"
    footer = b"\nOPENMYTHOS_GATE01_SUPERVISOR_COMPLETE\n"
    if not log.startswith(header) or not log.endswith(footer) or len(log) <= len(header) + len(footer):
        raise ReceiptError("build log supervisor transcript differs")


def _validate_bound_builder(
    repository: Path,
    builder: str,
    tree: BoundAcceptedTree,
) -> dict[str, Any]:
    root = repository / "build/gate01" / builder / "kernel"
    if tree.final != root:
        raise ReceiptError(f"{builder} accepted-tree path differs")
    result = _validate_public_roles(tree.descriptor, repository=repository, builder=builder, expected_uid=tree.expected_uid, expected_gid=tree.expected_gid)
    if tree.receipt.get("rpm_manifest_sha256") != result["manifest_sha256"] or tree.receipt.get("source_capsule_sha256") != result["source_capsule_sha256"]:
        raise ReceiptError("receipt does not bind canonical evidence")
    tree.verify_coherent()
    return {**result, "receipt_sha256": tree.receipt_sha256, "tree_sha256": tree.receipt["tree_sha256"]}


def _validate_public_roles(
    descriptor: Callable[[str], int], *, repository: Path, builder: str,
    expected_uid: int, expected_gid: int,
) -> dict[str, Any]:
    manifest_relative = "rpm-artifacts.json"
    installed_relative = "installed-files.json"
    source_capsule_relative = "source-capsule.json"
    manifest = _strict_json_descriptor(
        descriptor(manifest_relative), f"{builder} RPM manifest"
    )
    validate_rpm_manifest(manifest)
    manifest_sha256 = _hash_descriptor(descriptor(manifest_relative))
    source_capsule_sha256 = _hash_descriptor(descriptor(source_capsule_relative))

    expected_rpm_hashes = {
        "srpm": manifest["source_rpms"][0]["sha256"],
        **{
            {
                "kernel-openmythos": "meta",
                "kernel-openmythos-core": "core",
                "kernel-openmythos-modules": "modules",
            }[package["name"]]: package["sha256"]
            for package in manifest["binary_rpms"]
        },
    }
    rpm_relative = {
        "srpm": f"rpmbuild/SRPMS/{EXPECTED_RPM_FILENAMES['srpm']}",
        **{
            role: f"rpmbuild/RPMS/x86_64/{EXPECTED_RPM_FILENAMES[role]}"
            for role in ("core", "modules", "meta")
        },
    }
    rpm_sha256 = {
        role: _hash_descriptor(descriptor(relative))
        for role, relative in sorted(rpm_relative.items())
    }
    if rpm_sha256 != expected_rpm_hashes:
        raise ReceiptError(f"{builder} RPM bytes differ from inspector manifest")

    installed = _strict_json_descriptor(
        descriptor(installed_relative), f"{builder} installed-file evidence"
    )
    expected_installed = {
        "schema_version": manifest["schema_version"],
        "kernel_release": manifest["kernel_release"],
        "packages": [
            {"nevra": package["nevra"], "files": package["files"]}
            for package in manifest["binary_rpms"]
        ],
    }
    if installed != expected_installed:
        raise ReceiptError(
            f"{builder} installed-file evidence is not derived from its manifest"
        )
    source_capsule = _validate_source_capsule(_strict_json_descriptor(descriptor(source_capsule_relative), "source capsule"))
    source_roles = {"/kernel-openmythos.spec": "spec", "/linux-6.18.48.tar.xz": "source_archive", "/6.18.48-x86_64.config": "config", "/module-signing.pem": "public_certificate"}
    source_file_hashes = {item["path"]: item["digest"] for item in manifest["source_rpms"][0]["security_metadata"]["files"]}
    if source_file_hashes != {path: source_capsule["files"][role] for path, role in source_roles.items()}:
        raise ReceiptError("source RPM security files differ from source capsule inputs")
    core_config = [item for package in manifest["binary_rpms"] if package["name"] == "kernel-openmythos-core" for item in package["files"] if item["path"] == f"/usr/lib/modules/{manifest['kernel_release']}/config"]
    if len(core_config) != 1 or core_config[0]["sha256"] != source_capsule["files"]["config"]:
        raise ReceiptError("core packaged config differs from capsule config")
    _validate_auxiliary_evidence(descriptor, repository=repository, builder=builder, manifest=manifest, capsule=source_capsule, expected_uid=expected_uid, expected_gid=expected_gid)
    return {
        "builder": builder,
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "source_capsule": source_capsule,
        "source_capsule_sha256": source_capsule_sha256,
        "meta_descriptor": descriptor(rpm_relative["meta"]),
        "rpm_sha256": rpm_sha256,
    }


class _ReceiptBoundary:
    def __init__(self, verify: Callable[[], None]) -> None:
        self.verify = verify
        self.committed = False

    def __call__(self) -> None:
        self.verify()


class _PrimaryExitStack(ExitStack):
    """Callbacks are cleanup owners, never replacements for a body failure."""

    def open_owned(self, factory: Callable[..., Any], drain: Callable[[Any], None], /, *args: Any, **kwargs: Any) -> Any:
        """Acquire inside this guard; callers pass only non-owning arguments."""
        resource = None
        try:
            resource = factory(*args, **kwargs)
            self.adopt_close(resource, drain=drain)
            return resource
        except BaseException as primary:
            if resource is not None:
                try:
                    _close_resource_preserving_primary(resource, primary, drain=drain)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            drain(resource)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    if primary is None:
                        raise
                    _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise

    def adopt_close(self, resource: Any, *, drain: Callable[[Any], None] | None = None) -> Any:
        """Own the object before even binding its fallible close method."""
        close = None
        try:
            close = resource.close
            def release(_type: Any, exception: BaseException | None, _traceback: Any) -> bool:
                if drain is not None:
                    try:
                        _close_resource_preserving_primary(resource, exception, drain=drain)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                drain(resource)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        if exception is None:
                            raise
                        _add_cleanup_note(exception, "additional bound descriptor cleanup failed")
                    return False
                try:
                    close()
                except BaseException:
                    if exception is None:
                        raise
                    _add_cleanup_note(exception, "additional bound descriptor cleanup failed")
                return False
            self.push(release)
        except BaseException as primary:
            if drain is not None:
                try:
                    _close_resource_preserving_primary(resource, primary, drain=drain)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            drain(resource)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    if primary is None:
                        raise
                    _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
                raise
            try:
                if close is None:
                    resource.close()
                else:
                    close()
            except BaseException:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise
        return resource

    def enter_context(self, context: Any) -> Any:
        enter = type(context).__enter__
        release = type(context).__exit__
        value = enter(context)
        try:
            self._push_cm_exit(context, release)
        except BaseException as primary:
            try:
                release(context, type(primary), primary, primary.__traceback__)
            except BaseException:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise
        return value

    def callback(self, callback: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Callable[..., Any]:
        try:
            def release(_type: Any, exception: BaseException | None, _traceback: Any) -> bool:
                try:
                    if not args and not kwargs:
                        callback()
                    else:
                        callback(*args, **kwargs)
                except BaseException:
                    if exception is None:
                        raise
                    _add_cleanup_note(exception, "additional bound descriptor cleanup failed")
                return False
            self.push(release)
        except BaseException as primary:
            try:
                if not args and not kwargs:
                    callback()
                else:
                    callback(*args, **kwargs)
            except BaseException:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise
        return callback


class _ReceiptExitStack(_PrimaryExitStack):
    def __init__(self, boundary: _ReceiptBoundary) -> None:
        super().__init__()
        self.boundary = boundary

    def __exit__(self, exception_type: Any, exception: Any, traceback: Any) -> bool:
        release = super().__exit__
        if self.boundary.committed:
            try:
                release(exception_type, exception, traceback)
            except BaseException:
                _post_receipt_warning()
            return False
        return release(exception_type, exception, traceback)


@contextmanager
def _proof_locks(
    repository: Path,
    *,
    builders: Iterable[str],
    output_role: str,
) -> Iterable[_ReceiptBoundary]:
    if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", output_role) is None:
        raise ValueError("proof output lock role is invalid")
    workspaces: list[_BuilderWorkspace] = []
    output_descriptor = -1
    boundary_verified = False
    boundary: _ReceiptBoundary | None = None
    try:
        # Complete clean initial setup before the held reader boundary begins.
        # All later path-chain changes are detected by every workspace anchor.
        _comparison_directory(repository)
        gate = repository / "build/gate01"
        output_path = gate / f".kernel-{output_role}.lock"
        output_flags = (
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        try:
            output_descriptor = os.open(
                output_path,
                output_flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            try:
                output_descriptor = os.open(output_path, output_flags)
            except OSError as error:
                raise RuntimeError("proof output lock is unsafe") from error
        output_status = os.fstat(output_descriptor)
        named_output = output_path.lstat()
        if (
            not stat.S_ISREG(output_status.st_mode)
            or output_status.st_nlink != 1
            or output_status.st_uid != os.geteuid()
            or stat.S_IMODE(output_status.st_mode) != 0o600
            or _stat_identity(named_output) != _stat_identity(output_status)
        ):
            raise RuntimeError("proof output lock metadata is unsafe")
        try:
            fcntl.flock(
                output_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except OSError as error:
            raise RuntimeError("proof output is already active") from error

        for builder in sorted(set(builders)):
            workspace = _BuilderWorkspace.open(repository, builder, exclusive=False, create=False)
            try:
                workspaces.append(workspace)
            except BaseException as primary:
                _release_primary = primary
                try:
                    try:
                        _close_resource_preserving_primary(workspace, None, drain=_drain_builder_workspace)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_builder_workspace(workspace)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
        def verify_boundary() -> None:
            nonlocal boundary_verified
            for workspace in workspaces:
                workspace.verify_coherent()
            current_output = os.fstat(output_descriptor)
            named_output = output_path.lstat()
            if (
                _stat_version(current_output) != _stat_version(output_status)
                or _stat_identity(named_output) != _stat_identity(current_output)
            ):
                raise RuntimeError("proof output lock changed")
            boundary_verified = True

        boundary = _ReceiptBoundary(verify_boundary)
        yield boundary
        # Non-publication callers still receive a final coherence check.  A
        # publication caller invokes this inside its rollback-capable final
        # callback; no fallible acceptance check may run after that boundary.
        if not boundary_verified:
            verify_boundary()
    finally:
        primary = sys.exception()
        failure: BaseException | None = None
        try:
            while workspaces:
                try:
                    workspace = workspaces.pop()
                except BaseException as error:
                    if failure is None:
                        failure = error
                    if primary is not None:
                        _add_cleanup_note(primary, "additional proof cleanup ownership transfer failed")
                    workspace = workspaces[-1]
                    del workspaces[-1]
                try:
                    try:
                        _close_resource_preserving_primary(workspace, None, drain=_drain_builder_workspace)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_builder_workspace(workspace)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException as error:
                    if primary is not None:
                        _add_cleanup_note(primary, "additional proof workspace cleanup failed")
                    if failure is None:
                        failure = error
        finally:
            if output_descriptor >= 0:
                descriptor, output_descriptor = output_descriptor, -1
                try:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except BaseException as error:
                        if primary is not None:
                            _add_cleanup_note(primary, "additional proof output unlock failed")
                        if failure is None:
                            failure = error
                finally:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if primary is not None:
                            _add_cleanup_note(primary, "additional proof output close failed")
                        if failure is None:
                            failure = error
        if failure is not None:
            if boundary is not None and boundary.committed:
                try:
                    os.write(2, b"warning: post-receipt local cleanup or diagnostic failed\n")
                except BaseException:
                    pass
            elif primary is None:
                raise RuntimeError("proof lock cleanup failed") from failure


def _comparison_directory(repository: Path) -> Path:
    gate = repository / "build/gate01"
    gate.mkdir(mode=0o755, parents=True, exist_ok=True)
    value = gate / "compare"
    value.mkdir(mode=0o755, exist_ok=True)
    status = value.lstat()
    if value.is_symlink() or not stat.S_ISDIR(status.st_mode):
        raise RuntimeError("comparison directory is unsafe")
    return value


@_bootstrap_command
def run_comparison(repository: Path, *, _code_authority: Any) -> dict[str, Any]:
    """Revalidate both complete builder transactions and publish their proof."""
    _require_fixed_descriptor_absent(BUILD_KEY_FD, "private-key")
    repository = _validated_repository(repository)
    with _proof_locks(
        repository,
        builders=("builder-a", "builder-b"),
        output_role="rpm-comparison",
    ) as verify_locks, _ReceiptExitStack(verify_locks) as stack:
        trees = {}
        for builder in ("builder-a", "builder-b"):
            root, receipt = _builder_proof_paths(repository, builder)
            trees[builder] = stack.open_owned(
                BoundAcceptedTree.open, _drain_bound_accepted_tree,
                root, receipt, allowed_files=PUBLIC_OUTPUT_FILES, expected_uid=os.geteuid(), expected_gid=os.getegid()
            )
        left = _validate_bound_builder(repository, "builder-a", trees["builder-a"])
        right = _validate_bound_builder(repository, "builder-b", trees["builder-b"])
        if left["source_capsule"] != right["source_capsule"] or left["source_capsule_sha256"] != right["source_capsule_sha256"]:
            raise ReceiptError("A/B source capsules are not identical")
        comparison = compare_rpm_manifests(left["manifest"], right["manifest"])
        if comparison["verdict"] != "pass":
            raise RuntimeError("kernel RPM hard comparison failed")
        if comparison["advisory_binary_rpm_hash_differences"]:
            raise RuntimeError(
                "binary RPM difference lacks a documented RPM-header cause"
            )
        receipt_inputs = {
            "builder-a-receipt": left["receipt_sha256"],
            "builder-a-rpm-manifest": left["manifest_sha256"],
            "builder-a-tree": left["tree_sha256"],
            "builder-a-source-capsule": left["source_capsule_sha256"],
            "builder-b-receipt": right["receipt_sha256"],
            "builder-b-rpm-manifest": right["manifest_sha256"],
            "builder-b-tree": right["tree_sha256"],
            "builder-b-source-capsule": right["source_capsule_sha256"],
        }
        result = {
            **comparison,
            "builders": {
                builder: {
                    "receipt_sha256": record["receipt_sha256"],
                    "rpm_manifest_sha256": record["manifest_sha256"],
                    "tree_sha256": record["tree_sha256"],
                    "source_capsule_sha256": record["source_capsule_sha256"],
                }
                for builder, record in (
                    ("builder-a", left), ("builder-b", right)
                )
            },
            "receipt_input_sha256": receipt_inputs,
        }
        for tree in trees.values():
            tree.verify_coherent()
        compare_root = _comparison_directory(repository)
        output = compare_root / "kernel-rpms.json"
        receipt_path = compare_root / "kernel-rpms.receipt.json"

        def revalidate_trees_before_receipt() -> None:
            _code_authority()
            for tree in trees.values():
                tree.verify_coherent()
            verify_locks()

        publish_evidence_file(
            _canonical_json(result),
            final=output,
            receipt=receipt_path,
            kind="kernel-rpm-comparison",
            input_sha256=receipt_inputs,
            before_receipt=revalidate_trees_before_receipt, expected_uid=os.geteuid(), expected_gid=os.getegid()
        )
        verify_locks.committed = True
        return result


def _parse_meta_requirements(value: bytes) -> list[str]:
    expected = sorted(
        (
            "kernel-openmythos-core-uname-r = "
            "6.18.48-1.openmythos.fc44.x86_64",
            "kernel-openmythos-modules-uname-r = "
            "6.18.48-1.openmythos.fc44.x86_64",
        )
    )
    expected_value = {"requirements": expected}
    if value != _canonical_json(expected_value):
        raise RuntimeError("meta-package uname requirements are not exact")
    return expected


def _require_fixed_descriptor_absent(descriptor: int, description: str) -> None:
    try:
        os.fstat(descriptor)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise RuntimeError(
            f"could not verify absent {description} FD"
        ) from error
    if descriptor_flags & fcntl.FD_CLOEXEC:
        return
    raise RuntimeError(f"unexpected inheritable {description} FD is available")


def _meta_execution_descriptors(meta_descriptor: int, capsule_descriptor: int) -> dict[int, int]:
    """Return the exact keyless descriptor map accepted by the meta query."""
    try:
        status = os.fstat(meta_descriptor)
        flags = fcntl.fcntl(meta_descriptor, fcntl.F_GETFL)
    except OSError as error:
        raise RuntimeError("meta-package descriptor is not usable") from error
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError("meta-package descriptor is not a regular file")
    if flags & getattr(os, "O_PATH", 0):
        raise RuntimeError("meta-package descriptor is not readable")
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise RuntimeError("meta-package descriptor must be read-only")
    try:
        os.pread(meta_descriptor, 1, 0)
    except OSError as error:
        raise RuntimeError("meta-package descriptor is not readable") from error
    _require_sealed_regular_descriptor(capsule_descriptor, "meta verifier")
    return {VERIFIER_FD: capsule_descriptor, ARTIFACT_FD_ROLES["meta"]: meta_descriptor}


def _remove_children_at(parent_descriptor: int) -> None:
    """Bound listing retries precede a scalar, attempt-all child drain."""
    failure = None
    names = None
    remaining = 3
    while names is None and remaining:
        remaining -= 1
        try:
            pending_names = os.listdir(parent_descriptor)
            pending_names.sort()
            names = pending_names
        except BaseException as error:
            if failure is None:
                failure = error
    if names is not None:
        index = 0
        while index < len(names):
            name = names[index]
            index += 1
            try:
                _remove_entry_at(parent_descriptor, name)
            except BaseException as error:
                if failure is None:
                    failure = error
    if failure is not None:
        raise RuntimeError("cleanup child removal failed") from failure


def _remove_entry_at(parent_descriptor: int, name: str) -> None:
    status = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if stat.S_ISDIR(status.st_mode):
        child = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            if _stat_identity(os.fstat(child)) != _stat_identity(status):
                raise RuntimeError("cleanup directory identity changed")
            _remove_children_at(child)
        finally:
            primary = sys.exception()
            failure = None
            closing, child = child, -1
            try:
                os.close(closing)
            except BaseException as error:
                failure = error
            finally:
                try:
                    if _stat_identity(os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)) != _stat_identity(status):
                        raise RuntimeError("cleanup directory name changed")
                    os.rmdir(name, dir_fd=parent_descriptor)
                except BaseException as error:
                    if failure is None:
                        failure = error
            if failure is not None:
                if primary is None:
                    raise RuntimeError("cleanup directory release failed") from failure
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
    else:
        os.unlink(name, dir_fd=parent_descriptor)


class _ScopedTemporaryTree:
    """Descriptor-held invocation tree removable after a pathname swap."""

    def __init__(
        self,
        path: Path,
        parent_descriptor: int,
        parent_status: os.stat_result,
        parent_names: tuple[str, ...],
        root_descriptor: int,
        root_status: os.stat_result,
    ) -> None:
        self.path = path
        self._parent_descriptor = parent_descriptor
        self._parent_status = parent_status
        self._parent_names = parent_names
        self._root_descriptor = root_descriptor
        self._root_status = root_status
        self._closed = False

    @classmethod
    def open(cls, path: Path) -> "_ScopedTemporaryTree":
        path = Path(os.path.abspath(path))
        parent, parent_status = _open_parent_directory(path)
        root = -1
        try:
            named = os.stat(
                path.name, dir_fd=parent, follow_symlinks=False
            )
            root = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            opened = os.fstat(root)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _stat_identity(named) != _stat_identity(opened)
                or stat.S_IMODE(opened.st_mode) != 0o700
                or opened.st_uid != os.geteuid()
                or opened.st_gid != os.getegid()
            ):
                raise RuntimeError("scoped temporary tree is unsafe")
            return cls(
                path,
                parent,
                parent_status,
                tuple(sorted(os.listdir(parent))),
                root,
                opened,
            )
        except BaseException:
            _release_fd_0 = root
            _release_fd_1 = parent
            root = parent = -1
            _close_descriptors(_release_fd_0, _release_fd_1, primary=sys.exception())
            raise

    def remove(self) -> None:
        if self._closed:
            return
        changed = False
        failures: BaseException | None = None
        try:
            names = None
            remaining = 3
            while names is None and remaining:
                remaining -= 1
                try:
                    names = os.listdir(self._parent_descriptor)
                except BaseException as error:
                    if failures is None:
                        failures = error
            if names is None:
                raise RuntimeError("meta cleanup parent listing failed") from failures
            if (
                _stat_version(os.fstat(self._parent_descriptor))
                != _stat_version(self._parent_status)
                or len(names) != len(self._parent_names)
            ):
                changed = True
            index = 0
            while index < len(names):
                if names[index] not in self._parent_names:
                    changed = True
                index += 1
            try:
                named = os.stat(
                    self.path.name,
                    dir_fd=self._parent_descriptor,
                    follow_symlinks=False,
                )
                if _stat_identity(named) != _stat_identity(self._root_status):
                    changed = True
            except OSError:
                changed = True

            original_count = 0
            original_at_path = False
            index = 0
            while index < len(names):
                name = names[index]
                index += 1
                if name != self.path.name and (
                    name in self._parent_names
                    or not name.startswith(self.path.name + ".")
                ):
                    continue
                try:
                    status = os.stat(
                        name,
                        dir_fd=self._parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    changed = True
                    continue
                if _stat_identity(status) == _stat_identity(self._root_status):
                    original_count += 1
                    if name == self.path.name:
                        original_at_path = True
                    try:
                        _remove_entry_at(self._parent_descriptor, name)
                    except BaseException as error:
                        if failures is None:
                            failures = error
            if original_count != 1:
                changed = True
            # Preserve the reviewed exact invocation-name replacement rule.
            # Only the temporary-tree owner has this additional authority;
            # Podman store cleanup deliberately does not share it.
            if self.path.name in names and not original_at_path:
                try:
                    _remove_entry_at(self._parent_descriptor, self.path.name)
                except BaseException as error:
                    if failures is None:
                        failures = error
            if original_count == 0:
                try:
                    _remove_children_at(self._root_descriptor)
                except BaseException as error:
                    if failures is None:
                        failures = error
            try:
                os.fsync(self._parent_descriptor)
            except BaseException as error:
                if failures is None:
                    failures = error
        finally:
            try:
                _release_primary = sys.exception()
                try:
                    try:
                        _close_resource_preserving_primary(self, None, drain=_drain_scoped_temporary_tree)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_scoped_temporary_tree(self)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            except BaseException as error:
                if failures is None:
                    failures = error
        if changed:
            failures = RuntimeError('meta cleanup path changed')
        if failures:
            raise RuntimeError("meta cleanup path changed or removal failed") from failures

    def verify_setup_coherent(self) -> None:
        """Reject any change after the newly created inode was first anchored."""
        if self._closed:
            raise RuntimeError("scoped temporary tree is closed")
        current_parent = os.fstat(self._parent_descriptor)
        current_root = os.fstat(self._root_descriptor)
        try:
            named = os.stat(
                self.path.name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise RuntimeError("meta runtime setup path changed") from error
        if (
            _stat_version(current_parent) != _stat_version(self._parent_status)
            or tuple(sorted(os.listdir(self._parent_descriptor)))
            != self._parent_names
            or _stat_version(current_root) != _stat_version(self._root_status)
            or _stat_identity(named) != _stat_identity(current_root)
        ):
            raise RuntimeError("meta runtime setup path changed")

    def close(self) -> None:
        if self._closed:
            return
        _release_fd_0 = self._root_descriptor
        _release_fd_1 = self._parent_descriptor
        self._closed = True
        self._root_descriptor = self._parent_descriptor = -1
        _numeric_failure = None
        _numeric_fd = _release_fd_0
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = _release_fd_1
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bound descriptor release failed") from _numeric_failure


_drain_scoped_temporary_tree = _ScopedTemporaryTree.close


def _create_scoped_temporary_tree(
    parent: Path,
    *,
    prefix: str = ".kernel-meta-runtime-",
    set_mode: Callable[[Path, int], None] | None = None,
    open_tree: Callable[[Path], object] | None = None,
) -> tuple[Path, _ScopedTemporaryTree]:
    """Create and anchor a temporary tree without an unguarded failure gap."""
    if (
        not prefix
        or len(prefix) > 80
        or re.fullmatch(r"[A-Za-z0-9._-]+", prefix) is None
    ):
        raise ValueError("scoped temporary prefix is unsafe")
    parent = Path(os.path.abspath(parent))
    parent_descriptor, parent_status = _open_parent_directory(
        parent / ".temporary-child-anchor"
    )
    try:
        parent_names = tuple(sorted(os.listdir(parent_descriptor)))
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != os.geteuid()
            or stat.S_IMODE(parent_status.st_mode) & 0o022
        ):
            raise RuntimeError("scoped temporary parent is unsafe")
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(parent_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    path: Path | None = None
    owned_name: str | None = None
    anchor: _ScopedTemporaryTree | None = None
    root_descriptor = -1
    anchor_parent_descriptor = -1
    setup_changed = False
    try:
        for _attempt in range(128):
            name = prefix + os.urandom(12).hex()
            try:
                os.mkdir(name, 0o700, dir_fd=parent_descriptor)
                owned_name = name
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("could not allocate scoped temporary directory")
        path = parent / name
        observed_names = tuple(sorted(os.listdir(parent_descriptor)))
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        root_descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        root_status = os.fstat(root_descriptor)
        current_parent = os.fstat(parent_descriptor)
        anchor_parent_descriptor = os.dup(parent_descriptor)
        anchor = _ScopedTemporaryTree(
            path,
            anchor_parent_descriptor,
            current_parent,
            observed_names,
            root_descriptor,
            root_status,
        )
        anchor_parent_descriptor = -1
        root_descriptor = -1
        if (
            _stat_identity(parent_status) != _stat_identity(current_parent)
            or observed_names
            != tuple(sorted((*parent_names, name)))
            or not stat.S_ISDIR(named.st_mode)
            or _stat_identity(named) != _stat_identity(root_status)
            or stat.S_IMODE(root_status.st_mode) != 0o700
            or root_status.st_uid != os.geteuid()
            or root_status.st_gid != os.getegid()
        ):
            setup_changed = True
            raise RuntimeError("meta runtime setup path changed")
        if set_mode is not None:
            set_mode(path, 0o700)
        if open_tree is not None:
            open_tree(path)
        try:
            anchor.verify_setup_coherent()
        except BaseException:
            setup_changed = True
            raise
        closing, parent_descriptor = parent_descriptor, -1
        os.close(closing)
        return path, anchor
    except BaseException as setup_error:
        cleanup_failures: BaseException | None = None
        if anchor is not None:
            try:
                anchor.remove()
            except BaseException as cleanup_error:
                if cleanup_failures is None:
                    cleanup_failures = cleanup_error
        else:
            first = root_descriptor
            second = anchor_parent_descriptor
            root_descriptor = anchor_parent_descriptor = -1
            try:
                _close_descriptors(first, second)
            except BaseException as cleanup_error:
                cleanup_failures = cleanup_error
        if parent_descriptor >= 0:
            try:
                names = None
                remaining = 3
                while names is None and remaining:
                    remaining -= 1
                    try:
                        names = os.listdir(parent_descriptor)
                    except BaseException as cleanup_error:
                        if cleanup_failures is None:
                            cleanup_failures = cleanup_error
                # The random invocation basename is the cleanup namespace.
                # A dot-delimited derivative may hold its escaped inode, but a
                # concurrently created sibling sharing only the command prefix
                # is outside this invocation's removal authority.
                index = 0
                while names is not None and index < len(names):
                    entry = names[index]
                    index += 1
                    if (
                        owned_name is not None
                        and entry not in parent_names
                        and (
                            entry == owned_name
                            or entry.startswith(owned_name + ".")
                        )
                    ):
                        try:
                            _remove_entry_at(parent_descriptor, entry)
                        except BaseException as cleanup_error:
                            if cleanup_failures is None:
                                cleanup_failures = cleanup_error
            except BaseException as cleanup_error:
                if cleanup_failures is None:
                    cleanup_failures = cleanup_error
            finally:
                try:
                    os.fsync(parent_descriptor)
                except BaseException as cleanup_error:
                    if cleanup_failures is None:
                        cleanup_failures = cleanup_error
                _release_primary = sys.exception()
                try:
                    os.close(parent_descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        if cleanup_failures:
            _add_cleanup_note(setup_error, "additional meta runtime setup cleanup failed")
        if setup_changed:
            _add_cleanup_note(setup_error, "meta runtime setup changed")
        raise


def _cleanup_meta_resources(
    store: PodmanStore | None,
    capsule: SealedCapsule | None,
    temporary: Path | _ScopedTemporaryTree,
    *,
    remove_store: Callable[[PodmanStore], None] = _remove_podman_store,
    remove_tree: Callable[[Path], None] = shutil.rmtree,
    description: str = "meta proof",
) -> None:
    """Attempt every scoped cleanup and fail if any resource remains suspect."""
    failures: BaseException | None = None
    if store is not None:
        try:
            remove_store(store)
        except BaseException as error:
            if failures is None:
                failures = error
    if capsule is not None:
        try:
            try:
                _close_resource_preserving_primary(capsule, None, drain=_drain_sealed_capsule)
            except BaseException as _drain_primary:
                _drain_attempts = 2
                while _drain_attempts:
                    _drain_attempts -= 1
                    try:
                        _drain_sealed_capsule(capsule)
                        break
                    except BaseException:
                        _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                raise
        except BaseException as error:
            if failures is None:
                failures = error
    try:
        if isinstance(temporary, _ScopedTemporaryTree):
            temporary.remove()
        else:
            remove_tree(temporary)
    except BaseException as error:
        if failures is None:
            failures = error
    if failures:
        raise RuntimeError(f"{description} cleanup failed or binding changed") from failures


def _query_meta_requirements_in_fresh_container(
    repository: Path, meta_descriptor: int, builder: str
) -> dict[str, Any]:
    """Query one held meta RPM in a new keyless, fully audited container."""
    paths = gate01_input_paths(repository)
    selected = {
        "toolchain_lock": paths["toolchain_lock"],
        "toolchain_archive": paths["toolchain_archive"],
        **{relative: paths[relative] for relative in BOOTSTRAP_SOURCE_PATHS},
    }
    temporary_path, temporary = _create_scoped_temporary_tree(
        _comparison_directory(repository),
        prefix=f".kernel-meta-runtime-{builder}-",
    )
    store: PodmanStore | None = None
    capsule: SealedCapsule | None = None
    policy: SealedPodmanPolicy | None = None
    backend: PodmanContainerBackend | None = None
    try:
        runtime = temporary_path / "runtime"
        scratch = temporary_path / "scratch"
        runtime.mkdir(mode=0o700)
        scratch.mkdir(mode=0o700)
        environment = controlled_environment(
            {}, home=runtime, xdg_runtime=runtime,
            temporary=runtime,
        )
        policy = SealedPodmanPolicy.create()
        with _owned_resource(BoundInputs.open, _drain_bound_inputs,
            selected, policies=_input_policies(selected)
        ) as inputs:
            capsule = _executed_capsule_from_bound_inputs(inputs)
            archive_sha256, manifest_digest = _lifecycle_toolchain_identity(
                inputs.descriptor("toolchain_lock"),
                inputs.descriptor("toolchain_archive"),
            )
            summary_result = run_verifier_capsule(
                capsule.fd,
                "tools.gate01.container_runtime",
                (
                    "oci-summary-fixed", "--archive-sha256", archive_sha256,
                    "--manifest-digest", manifest_digest,
                ),
                descriptors={OCI_ARCHIVE_FD: inputs.descriptor("toolchain_archive")},
                environment=environment,
            )
            if summary_result.returncode != 0:
                raise RuntimeError("meta proof OCI semantic derivation failed")
            summary = _load_json_bytes(summary_result.stdout, "OCI semantic summary")
            if summary.get("non_root_entry_count") != 138619:
                raise RuntimeError("locked OCI rootfs path count is not exact")
            store = PodmanStore(
                temporary_path / "store", environment=environment, policy=policy
            )
            store.initialize()
            store.import_image(
                inputs.descriptor("toolchain_archive"),
                expected_config_digest=summary["config_digest"],
                expected_manifest_digest=manifest_digest,
                expected_oci_identity=summary,
            )
            backend = PodmanContainerBackend(
                store=store,
                image=summary["config_digest"],
                container=f"openmythos-gate01-meta-{builder}-{os.getpid()}",
                scratch=scratch,
                capsule_descriptor=capsule.fd,
                archive_descriptor=inputs.descriptor("toolchain_archive"),
                archive_sha256=archive_sha256,
                manifest_digest=manifest_digest,
                execution_arguments={
                    "meta": (
                        "/usr/bin/python3", "-I", "-S", "-B",
                        f"/proc/self/fd/{VERIFIER_FD}",
                        "tools.gate01.rpm_artifacts", "meta-fixed-fd",
                    )
                },
            )
            lifecycle = run_container_lifecycle(
                backend,
                executions=(("meta", _meta_execution_descriptors(meta_descriptor, capsule.fd)),),
                allow_key_role=None,
            )
            query = backend.execution_results.get("meta")
            if query is None:
                raise RuntimeError("meta-package query result is absent")
            requirements = _parse_meta_requirements(query.stdout)
            inputs.verify_coherent()
            result = {
                "requirements": requirements,
                "rootfs_before": dict(lifecycle.before.record),
                "rootfs_authorized": dict(lifecycle.authorized.record),
                "rootfs_after": dict(lifecycle.after.record),
                "lifecycle": {
                    "transitions": list(lifecycle.transitions),
                    "semantic_equal": lifecycle.semantic_equal,
                    "raw_equal": lifecycle.raw_equal,
                },
                "container_contract": backend.contract_record,
            }
        return result
    finally:
        primary = sys.exception()
        failure = None
        try:
            _cleanup_meta_resources(store, capsule, temporary)
        except BaseException as error:
            failure = error
        finally:
            try:
                if backend is not None:
                    try:
                        _close_resource_preserving_primary(backend, None, drain=_drain_container_backend)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_container_backend(backend)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
            except BaseException as error:
                if failure is None:
                    failure = error
            finally:
                try:
                    if policy is not None:
                        try:
                            _close_resource_preserving_primary(policy, None, drain=_drain_podman_policy)
                        except BaseException as _drain_primary:
                            _drain_attempts = 2
                            while _drain_attempts:
                                _drain_attempts -= 1
                                try:
                                    _drain_podman_policy(policy)
                                    break
                                except BaseException:
                                    _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                            raise
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            if primary is None:
                raise RuntimeError("meta proof cleanup failed") from failure
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


@_bootstrap_command
def run_meta_requirements(repository: Path, builder: str, *, _code_authority: Any) -> dict[str, Any]:
    _require_fixed_descriptor_absent(BUILD_KEY_FD, "private-key")
    repository = _validated_repository(repository)
    with _proof_locks(
        repository, builders=(builder,), output_role="meta-requirements"
    ) as verify_locks:
        root, receipt = _builder_proof_paths(repository, builder)
        with _ReceiptExitStack(verify_locks) as stack:
            tree = stack.open_owned(BoundAcceptedTree.open, _drain_bound_accepted_tree,
                root, receipt, allowed_files=PUBLIC_OUTPUT_FILES, expected_uid=os.geteuid(), expected_gid=os.getegid()
            )
            proof = _validate_bound_builder(repository, builder, tree)
            meta = _query_meta_requirements_in_fresh_container(
                repository, proof["meta_descriptor"], builder
            )
            expected_requirements = _parse_meta_requirements(
                _canonical_json({"requirements": meta.get("requirements")})
            )
            receipt_inputs = {
                "builder-receipt": proof["receipt_sha256"],
                "builder-tree": proof["tree_sha256"],
                "meta-rpm": proof["rpm_sha256"]["meta"],
            }
            result = {
                "schema_version": 1,
                "builder": builder,
                "builder_receipt_sha256": proof["receipt_sha256"],
                "builder_tree_sha256": proof["tree_sha256"],
                "container_contract": meta.get("container_contract"),
                "meta_rpm_sha256": proof["rpm_sha256"]["meta"],
                "receipt_input_sha256": receipt_inputs,
                "requirements": expected_requirements,
                "rootfs_after": meta.get("rootfs_after"),
                "rootfs_before": meta.get("rootfs_before"),
                "verdict": "pass",
            }
            tree.verify_coherent()
            compare_root = _comparison_directory(repository)
            output = compare_root / "meta-requirements.json"
            receipt_path = compare_root / "meta-requirements.receipt.json"
            publish_evidence_file(
                _canonical_json(result),
                final=output,
                receipt=receipt_path,
                kind="meta-requirements",
                input_sha256=receipt_inputs,
                before_receipt=lambda: (
                    tree.verify_coherent(), verify_locks(), _code_authority()
                ), expected_uid=os.geteuid(), expected_gid=os.getegid()
            )
            verify_locks.committed = True
            return result
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--repo", required=True, type=Path)
    run.add_argument("builder", choices=("builder-a", "builder-b", "canonical"))
    compare = subparsers.add_parser("compare")
    compare.add_argument("--repo", required=True, type=Path)
    meta = subparsers.add_parser("meta-requirements")
    meta.add_argument("--repo", required=True, type=Path)
    meta.add_argument(
        "--builder",
        required=True,
        choices=("builder-a", "builder-b", "canonical"),
    )
    build_exec = subparsers.add_parser("build-exec")
    build_exec.add_argument("--config-sha256", required=True)
    subparsers.add_parser("audit-inputs-fixed")
    lifecycle = subparsers.add_parser("lifecycle-check")
    lifecycle.add_argument("--repository", required=True, type=Path)
    return parser


def _consume_bootstrap_authority(
    capsule_descriptor: int, authority_descriptor: int
) -> dict[str, Any]:
    """Validate and retain the sealed authority for the bytes executing us."""
    _require_sealed_regular_descriptor(capsule_descriptor, "bootstrap capsule")
    _require_sealed_regular_descriptor(authority_descriptor, "bootstrap authority")
    capsule_sha256 = _hash_descriptor(capsule_descriptor)
    authority = _json_object_descriptor(
        authority_descriptor, "bootstrap authority"
    )
    if set(authority) != {
        "bootstrap_tcb", "capsule_sha256", "files", "ordered_paths",
        "schema_version",
    }:
        raise RuntimeError("bootstrap authority schema is not exact")
    if (
        authority["schema_version"] != 1
        or authority["bootstrap_tcb"] != "launcher-held-descriptor-open"
        or authority["capsule_sha256"] != capsule_sha256
        or not isinstance(authority["files"], dict)
        or set(authority["files"]) != set(BOOTSTRAP_SOURCE_PATHS)
        or authority["ordered_paths"] != list(BOOTSTRAP_SOURCE_PATHS)
    ):
        raise RuntimeError("bootstrap authority differs from executed capsule")
    for relative, record in authority["files"].items():
        expected_mode = (
            "0755" if relative == "scripts/gate01/build-kernel.sh" else "0644"
        )
        if (
            not isinstance(record, dict)
            or set(record) != {"mode", "sha256", "size"}
            or record["mode"] != expected_mode
            or not isinstance(record["size"], int)
            or record["size"] < 0
            or not isinstance(record["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        ):
            raise RuntimeError("bootstrap source record is malformed")
    return authority


def sealed_main(argv: list[str] | None = None) -> int:
    """Only production entry: validate fixed sealed authority descriptors."""
    global _EXECUTED_BOOTSTRAP_AUTHORITY
    global _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256
    global _EXECUTED_BOOTSTRAP_CAPSULE_SHA256
    values = list(sys.argv[1:] if argv is None else argv)
    expected_prefix = [
        "--bootstrap-capsule-fd", str(BOOTSTRAP_CAPSULE_FD),
        "--bootstrap-authority-fd", str(BOOTSTRAP_AUTHORITY_FD),
    ]
    if values[:4] != expected_prefix:
        raise RuntimeError("sealed bootstrap descriptor arguments are not exact")
    if _EXECUTED_BOOTSTRAP_AUTHORITY is not None:
        raise RuntimeError("sealed bootstrap authority was already consumed")
    authority = _consume_bootstrap_authority(
        BOOTSTRAP_CAPSULE_FD, BOOTSTRAP_AUTHORITY_FD
    )
    _EXECUTED_BOOTSTRAP_AUTHORITY = authority
    _EXECUTED_BOOTSTRAP_AUTHORITY_SHA256 = _hash_descriptor(
        BOOTSTRAP_AUTHORITY_FD
    )
    _EXECUTED_BOOTSTRAP_CAPSULE_SHA256 = authority["capsule_sha256"]
    return main(values[4:])


def _post_receipt_output(value: Mapping[str, Any]) -> None:
    """Best-effort diagnostics without buffered bytes at interpreter shutdown."""
    def emit() -> None:
        text = json.dumps(_json_safe(value), sort_keys=True) + "\n"
        try:
            descriptor = sys.stdout.fileno()
        except (AttributeError, OSError):
            descriptor = None
        if type(descriptor) is not int:
            # In-memory test/application streams have no kernel buffer to
            # reflush during process teardown.
            sys.stdout.write(text)
            sys.stdout.flush()
            return
        try:
            pending = memoryview(text.encode("utf-8"))
            while pending:
                written = os.write(descriptor, pending)
                if written <= 0:
                    raise OSError(errno.EIO, "short success diagnostic write")
                pending = pending[written:]
        except BaseException:
            # Also make any earlier Python-buffer residue harmless. Closing
            # the stream itself can retry a failing flush and exit with 120.
            sink = -1
            try:
                sink = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
                os.dup2(sink, descriptor)
                if sink == descriptor:
                    sink = -1
            except BaseException:
                pass
            finally:
                if sink >= 0:
                    closing, sink = sink, -1
                    try:
                        os.close(closing)
                    except BaseException:
                        pass
            raise
    _best_effort_release(emit)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "run":
        run_builder(arguments.repo, arguments.builder)
        return 0
    if arguments.command == "compare":
        result = run_comparison(arguments.repo)
        _post_receipt_output(result)
        return 0
    if arguments.command == "meta-requirements":
        result = run_meta_requirements(arguments.repo, arguments.builder)
        _post_receipt_output(result)
        return 0
    if arguments.command == "build-exec":
        return _build_exec(arguments.config_sha256)
    if arguments.command == "audit-inputs-fixed":
        return _audit_inputs_fixed()
    if arguments.command == "lifecycle-check":
        result = run_no_build_lifecycle(arguments.repository)
        print(json.dumps(_json_safe(result), sort_keys=True), flush=True)
        return 0
    raise AssertionError(arguments.command)


if __name__ == "__main__":
    raise SystemExit(main())
