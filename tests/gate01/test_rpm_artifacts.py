from __future__ import annotations

import copy
import base64
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import tools.gate01.rpm_artifacts as rpm_artifacts
from tools.gate01.rpm_artifacts import (
    compare_rpm_manifests,
    load_rpm_manifest,
    normalize_source_package_identity,
    _extract_validated_cpio,
    _snapshot_rpm,
    _validate_cpio_archive,
    _validate_extracted_tree,
    _validate_modules_order,
    _validate_pre_extraction_paths,
    _verify_module_signature,
    _extract_validated_cpio_descriptor,
    _inspect_bound_payload_file,
    _validate_cpio_archive_descriptor,
    _validate_source_rpm_payload,
    _validate_meta_requirements_descriptor,
    validate_builder_isolation_plan,
    validate_final_proof_boundary,
    validate_frozen_helper_tree,
    validate_imported_image_identity,
    validate_retained_rpm_set,
    validate_rpm_manifest,
)


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests/gate01/fixtures"
VALID = FIXTURES / "rpm-manifest-valid.json"
DUPLICATE = FIXTURES / "rpm-manifest-duplicate-nevra.json"


def _newc_entry(
    name: str,
    *,
    mode: int,
    data: bytes = b"",
    inode: int = 1,
    links: int = 1,
    uid: int = 0,
    gid: int = 0,
    mtime: int = 1787899659,
) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    fields = (
        inode,
        mode,
        uid,
        gid,
        links,
        mtime,
        len(data),
        0,
        0,
        0,
        0,
        len(encoded_name),
        0,
    )
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    prefix = header + encoded_name
    prefix += b"\0" * (-len(prefix) % 4)
    return prefix + data + (b"\0" * (-len(data) % 4))


def _newc_archive(entries: list[bytes]) -> bytes:
    trailer = _newc_entry("TRAILER!!!", mode=0, inode=0, mtime=0)
    return b"".join([*entries, trailer]) + b"\0" * 512


def _create_test_certificate(directory: Path, name: str) -> tuple[Path, Path]:
    key = directory / f"{name}.key"
    certificate = directory / f"{name}.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=OpenMythos Gate 01 Development Module Key",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return key, certificate


def _create_test_signed_module(
    directory: Path, key: Path, certificate: Path, *, digest: str = "sha256"
) -> Path:
    content = directory / "unsigned-module"
    signature = directory / "module-signature.der"
    module = directory / "test.ko"
    content.write_bytes(b"test ELF module bytes\n")
    subprocess.run(
        [
            "openssl",
            "cms",
            "-sign",
            "-binary",
            "-noattr",
            "-nocerts",
            "-md",
            digest,
            "-in",
            str(content),
            "-signer",
            str(certificate),
            "-inkey",
            str(key),
            "-outform",
            "DER",
            "-out",
            str(signature),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    signature_bytes = signature.read_bytes()
    module.write_bytes(
        content.read_bytes()
        + signature_bytes
        + bytes((0, 0, 2, 0, 0, 0, 0, 0))
        + len(signature_bytes).to_bytes(4, "big")
        + b"~Module signature appended~\n"
    )
    return module


def _test_der(tag: int, *parts: bytes) -> bytes:
    value = b"".join(parts)
    size = len(value)
    length = bytes((size,)) if size < 128 else bytes((0x80 | ((size.bit_length() + 7) // 8),)) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes((tag,)) + length + value


def _test_der_parts(value: bytes) -> list[bytes]:
    def extent(offset: int) -> tuple[int, int]:
        size = value[offset + 1]
        start = offset + 2
        if size & 0x80:
            count = size & 0x7f
            size = int.from_bytes(value[start:start + count], "big")
            start += count
        return start, start + size
    offset, limit = extent(0)
    result = []
    while offset < limit:
        _, end = extent(offset)
        result.append(value[offset:end])
        offset = end
    assert offset == limit == len(value)
    return result


def _test_module_cms(module: Path, signature: bytes) -> None:
    module.write_bytes(b"test ELF module bytes\n" + signature + bytes((0, 0, 2, 0, 0, 0, 0, 0)) + len(signature).to_bytes(4, "big") + b"~Module signature appended~\n")


def _test_rpm_tag_output(tags: tuple[str, ...], values: dict[str, list[object]]) -> str:
    return "".join(name + "\n" + ("1\n" + str(len(values[name])) + "\n" + "".join(json.dumps(value) + "\n" for value in values[name]) if values.get(name) else "0\n0\n") for name in tags)


class RpmManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_rpm_manifest(VALID)

    def test_reviewed_spec_buildrequires_equal_exact_srpm_security_contract(self) -> None:
        spec = (REPO / "os/kernel/packaging/kernel-openmythos.spec").read_text(encoding="utf-8")
        observed = sorted(name.strip() for line in spec.splitlines() if line.startswith("BuildRequires:") for name in line.split(":", 1)[1].split(","))
        expected = sorted(item["name"] for item in rpm_artifacts._security_dependencies("srpm")["requires"] if not item["name"].startswith("rpmlib("))
        self.assertEqual(observed, expected)

    def test_architecture_records_explicit_complete_module_signing_policy(self) -> None:
        architecture = (REPO / "docs/superpowers/specs/2026-08-31-openmythos-os-architecture-design.md").read_text(encoding="utf-8")
        self.assertTrue("CONFIG_MODULE_SIG_ALL=n" in architecture, "architecture still contradicts explicit signing")
        self.assertTrue("sign-file sha256" in architecture)
        self.assertTrue("every installed uncompressed module" in architecture)

    def test_all_executable_closures_and_plan_map_include_bootstrap_and_fixture(self) -> None:
        from tools.gate01 import kernel_bootstrap, kernel_build
        expected = tuple(path for path in kernel_bootstrap.BOOTSTRAP_SOURCE_PATHS if path.endswith(".py"))
        self.assertEqual(rpm_artifacts.FROZEN_HELPER_PATHS, expected)
        self.assertEqual(kernel_build.VERIFIER_RELATIVE_PATHS, expected)
        plan = (REPO / "docs/superpowers/plans/2026-09-03-stone-boot-proof.md").read_text(encoding="utf-8")
        self.assertTrue("tools/gate01/kernel_bootstrap.py" in plan)
        self.assertTrue("tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json" in plan)
        fixture = REPO / "tests/gate01/fixtures/oci-config-podman-5.7-crun-1.21.json"
        self.assertEqual(stat.S_IMODE(fixture.stat().st_mode), 0o644)
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), "ca99bb49d1e51ab415dcccf2f14f1026f7cf87911c62e0491cc619633f9d7b30")

    def test_manifest_requires_security_metadata_for_every_package(self) -> None:
        for index in range(4):
            with self.subTest(package=index):
                value = copy.deepcopy(self.manifest)
                packages = [*value["source_rpms"], *value["binary_rpms"]]
                packages[index].pop("security_metadata", None)
                with self.assertRaisesRegex(ValueError, "RPM .*missing=<redacted>"):
                    validate_rpm_manifest(value)

    def test_equal_installed_bytes_with_different_security_metadata_fail_comparison(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["binary_rpms"][1]["security_metadata"]["payload"]["compressed_sha256"] = "e" * 64
        result = compare_rpm_manifests(self.manifest, changed)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["rpm_security_metadata"], "fail")

    def test_security_metadata_rejects_each_dependency_script_and_file_policy_mutation(self) -> None:
        for index, package in enumerate([*self.manifest["source_rpms"], *self.manifest["binary_rpms"]]):
            role = ("srpm", "meta", "core", "modules")[index]
            baseline = package["security_metadata"]
            for family in ("requires", "provides", "conflicts", "obsoletes", "recommends", "suggests", "supplements", "enhances", "order"):
                for mutation in ("extra", "missing", "flags"):
                    with self.subTest(role=role, family=family, mutation=mutation):
                        value = copy.deepcopy(baseline)
                        records = value["dependencies"][family]
                        if mutation == "extra" or not records:
                            records.append({"name": "unapproved", "flags": 0, "version": ""})
                        elif mutation == "missing":
                            records.pop()
                        else:
                            records[0]["flags"] ^= 1
                        with self.assertRaises(ValueError):
                            rpm_artifacts._validate_security_metadata(value, role)
            for mutation in ("script", "interpreter", "flags", "trigger", "capability", "context"):
                with self.subTest(role=role, mutation=mutation):
                    value = copy.deepcopy(baseline)
                    if mutation in ("trigger", "capability", "context"):
                        value["forbidden_tags"].append({"trigger": "FILETRIGGERINDEX", "capability": "FILECAPS", "context": "FILECONTEXTS"}[mutation])
                    else:
                        value["scripts"]["POSTIN"] = {"body": "", "argv": ["/bin/sh"], "flags": None}
                        value["scripts"]["POSTIN"][{"script": "body", "interpreter": "argv", "flags": "flags"}[mutation]] = {"script": "touch /tmp/unapproved", "interpreter": ["/usr/bin/python3"], "flags": 1}[mutation]
                    with self.assertRaises(ValueError):
                        rpm_artifacts._validate_security_metadata(value, role)
            if baseline["files"]:
                for field, bad in (("flags", 1), ("verify_flags", 0), ("rdev", 1), ("device", 2), ("inode", 0), ("digest", ""), ("raw_mode", 0o104755)):
                    with self.subTest(role=role, field=field):
                        value = copy.deepcopy(baseline)
                        record = next(record for record in value["files"] if stat.S_ISREG(record["raw_mode"]))
                        record[field] = bad
                        with self.assertRaises(ValueError):
                            rpm_artifacts._validate_security_metadata(value, role)

    def test_valid_manifest_has_exact_sorted_package_set(self) -> None:
        validate_rpm_manifest(self.manifest)
        self.assertEqual(len(self.manifest["source_rpms"]), 1)
        self.assertEqual(
            [package["name"] for package in self.manifest["binary_rpms"]],
            [
                "kernel-openmythos",
                "kernel-openmythos-core",
                "kernel-openmythos-modules",
            ],
        )

    def test_duplicate_nevra_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate NEVRA"):
            validate_rpm_manifest(load_rpm_manifest(DUPLICATE))

    def test_source_rpm_header_identity_is_normalized_to_src(self) -> None:
        header = {
            "name": "kernel-openmythos",
            "epoch": "0",
            "version": "6.18.48",
            "release": "1.openmythos.fc44",
            "architecture": "x86_64",
            "nevra": "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64",
            "sha256": "a" * 64,
            "source_package": "1",
            "source_rpm": "(none)",
        }

        normalized = normalize_source_package_identity(
            header, "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
        )

        self.assertEqual(normalized["architecture"], "src")
        self.assertEqual(
            normalized["nevra"],
            "kernel-openmythos-6.18.48-1.openmythos.fc44.src",
        )
        self.assertNotIn("source_package", normalized)
        self.assertNotIn("source_rpm", normalized)

    def test_renamed_binary_meta_rpm_cannot_be_normalized_as_source(self) -> None:
        header = {
            "name": "kernel-openmythos",
            "epoch": "0",
            "version": "6.18.48",
            "release": "1.openmythos.fc44",
            "architecture": "x86_64",
            "nevra": "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64",
            "sha256": "a" * 64,
            "source_package": "0",
            "source_rpm": "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm",
        }
        with self.assertRaisesRegex(ValueError, "genuine source RPM"):
            normalize_source_package_identity(
                header, "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
            )

    def test_wrong_source_or_binary_architecture_is_rejected(self) -> None:
        cases = (("source_rpms", 0, "x86_64"), ("binary_rpms", 1, "aarch64"))
        for collection, index, architecture in cases:
            with self.subTest(collection=collection):
                manifest = copy.deepcopy(self.manifest)
                manifest[collection][index]["architecture"] = architecture
                with self.assertRaisesRegex(ValueError, "architecture"):
                    validate_rpm_manifest(manifest)

    def test_wrong_kernel_release_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["kernel_release"] = "6.18.47-1.openmythos.fc44.x86_64"
        with self.assertRaisesRegex(ValueError, "kernel release"):
            validate_rpm_manifest(manifest)

    def test_core_or_modules_path_outside_release_tree_is_rejected(self) -> None:
        cases = (
            (1, "/etc/openmythos-kernel"),
            (
                2,
                "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64/../escape.ko",
            ),
        )
        for package_index, path in cases:
            with self.subTest(path=path):
                manifest = copy.deepcopy(self.manifest)
                manifest["binary_rpms"][package_index]["files"][0]["path"] = path
                with self.assertRaisesRegex(ValueError, "release tree"):
                    validate_rpm_manifest(manifest)

    def test_private_key_suffix_or_content_marker_is_rejected(self) -> None:
        suffix_manifest = copy.deepcopy(self.manifest)
        suffix_manifest["binary_rpms"][1]["files"][0]["path"] += ".key"
        with self.assertRaisesRegex(ValueError, "private-key suffix"):
            validate_rpm_manifest(suffix_manifest)

        marker_manifest = copy.deepcopy(self.manifest)
        marker_manifest["binary_rpms"][1]["files"][0][
            "private_key_marker"
        ] = True
        with self.assertRaisesRegex(ValueError, "PRIVATE KEY"):
            validate_rpm_manifest(marker_manifest)

    def test_module_signature_contract_is_enforced(self) -> None:
        cases = (
            ("signer", "Somebody Else", "signer"),
            ("sig_id", "X.509", "sig_id"),
            ("vermagic", "6.18.47 SMP", "vermagic"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["binary_rpms"][2]["files"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    validate_rpm_manifest(manifest)

    def test_vermagic_release_token_must_match_exactly(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        module = manifest["binary_rpms"][2]["files"][0]
        module["vermagic"] = (
            "6.18.48-1.openmythos.fc44.x86_64-evil SMP preempt mod_unload"
        )
        with self.assertRaisesRegex(ValueError, "vermagic"):
            validate_rpm_manifest(manifest)

    def test_module_symlink_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        module = manifest["binary_rpms"][2]["files"][0]
        for field in ("sha256", "private_key_marker", "signer", "sig_id", "vermagic"):
            del module[field]
        module.update(
            {
                "type": "symlink",
                "mode": "0777",
                "size": len("../other.ko"),
                "link_target": "../other.ko",
            }
        )
        with self.assertRaisesRegex(ValueError, "module symlink"):
            validate_rpm_manifest(manifest)

    def test_module_signature_is_verified_against_pinned_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key, certificate = _create_test_certificate(directory, "expected")
            _, wrong_certificate = _create_test_certificate(directory, "wrong-same-cn")
            module = _create_test_signed_module(directory, key, certificate)

            _verify_module_signature(module, certificate)

            original = module.read_bytes()
            module.write_bytes(b"X" + original[1:])
            with self.assertRaisesRegex(ValueError, "cryptographic signature"):
                _verify_module_signature(module, certificate)
            module.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "cryptographic signature"):
                _verify_module_signature(module, wrong_certificate)

    def test_core_and_modules_payloads_cannot_be_empty_or_incomplete(self) -> None:
        cases = []
        empty_core = copy.deepcopy(self.manifest)
        empty_core["binary_rpms"][1]["files"] = []
        cases.append((empty_core, "core payload"))
        no_modules = copy.deepcopy(self.manifest)
        no_modules["binary_rpms"][2]["files"] = [
            record
            for record in no_modules["binary_rpms"][2]["files"]
            if not record["path"].endswith(".ko")
        ]
        cases.append((no_modules, "non-empty module set"))
        missing_metadata = copy.deepcopy(self.manifest)
        missing_metadata["binary_rpms"][2]["files"] = [
            record
            for record in missing_metadata["binary_rpms"][2]["files"]
            if not record["path"].endswith("/modules.order")
        ]
        cases.append((missing_metadata, "modules metadata"))
        for manifest, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    validate_rpm_manifest(manifest)

    def test_required_core_and_module_metadata_must_be_nonempty(self) -> None:
        for package_index, path_suffix in (
            (1, "/vmlinuz"),
            (2, "/modules.alias"),
        ):
            with self.subTest(path_suffix=path_suffix):
                manifest = copy.deepcopy(self.manifest)
                record = next(
                    item
                    for item in manifest["binary_rpms"][package_index]["files"]
                    if item["path"].endswith(path_suffix)
                )
                record["size"] = 0
                with self.assertRaisesRegex(ValueError, "nonempty regular file"):
                    validate_rpm_manifest(manifest)

    def test_required_module_metadata_must_be_regular_file(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        record = next(
            item
            for item in manifest["binary_rpms"][2]["files"]
            if item["path"].endswith("/modules.alias")
        )
        for field in ("sha256", "private_key_marker"):
            del record[field]
        record.update(
            {
                "type": "symlink",
                "mode": "0777",
                "size": len("modules.alias.bin"),
                "link_target": "modules.alias.bin",
            }
        )
        with self.assertRaisesRegex(ValueError, "metadata.*regular"):
            validate_rpm_manifest(manifest)

    def test_modules_order_must_exactly_cover_packaged_modules(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        module_path = f"{release}/kernel/drivers/virtio/virtio_net.ko"
        headers = [
            {
                "path": module_path,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            order = root / release.removeprefix("/") / "modules.order"
            order.parent.mkdir(parents=True)
            order.write_text("kernel/drivers/virtio/virtio_net.ko\n", encoding="utf-8")
            _validate_modules_order(root, headers)

            order.write_text("kernel/drivers/virtio/not-packaged.ko\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "modules.order"):
                _validate_modules_order(root, headers)

    def test_payload_ownership_and_mode_are_exact(self) -> None:
        cases = (("user", "daemon", "root:root"), ("mode", "0666", "mode"))
        for field, value, message in cases:
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["binary_rpms"][1]["files"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    validate_rpm_manifest(manifest)

    def test_compressed_modules_are_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["binary_rpms"][2]["files"][0]["path"] += ".zst"
        with self.assertRaisesRegex(ValueError, "compressed module"):
            validate_rpm_manifest(manifest)

    def test_pre_extraction_rejects_payload_below_symlink(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        headers = [
            {
                "path": f"{release}/pivot",
                "raw_mode": 0o120777,
                "size": 0,
                "user": "root",
                "group": "root",
                "link_target": f"{release}/kernel",
            },
            {
                "path": f"{release}/pivot/escaped.ko",
                "raw_mode": 0o100644,
                "size": 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            },
        ]
        listing = "\n".join(header["path"] for header in headers) + "\n"

        with mock.patch(
            "tools.gate01.rpm_artifacts._run_text", return_value=listing
        ):
            with self.assertRaisesRegex(ValueError, "below payload symlink"):
                _validate_pre_extraction_paths(Path("payload.rpm"), headers, listing_override=[header["path"] for header in headers])

    def test_cpio_stream_rejects_dot_dot_entry_before_extraction(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        headers = [
            {
                "path": f"{release}/safe",
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        archive = _newc_archive(
            [_newc_entry("../escape", mode=stat.S_IFREG | 0o644, data=b"x")]
        )
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "payload.cpio"
            spool.write_bytes(archive)
            with self.assertRaisesRegex(ValueError, "CPIO path"):
                _validate_cpio_archive(spool, headers)

    def test_validated_cpio_spool_extracts_only_after_validation(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        path = f"{release}/safe"
        headers = [
            {
                "path": path,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 4,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        archive = _newc_archive(
            [_newc_entry("." + path, mode=stat.S_IFREG | 0o644, data=b"safe")]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "payload.cpio"
            destination = root / "extracted"
            spool.write_bytes(archive)
            _validate_cpio_archive(spool, headers)
            _extract_validated_cpio(spool, destination)
            self.assertEqual(
                (destination / path.removeprefix("/")).read_bytes(), b"safe"
            )

    def test_extracted_tree_rejects_extra_or_retyped_implicit_directories(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        path = f"{release}/vmlinuz"
        headers = [
            {
                "path": path,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 4,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            payload = root / path.removeprefix("/")
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"boot")
            payload.chmod(0o644)
            _validate_extracted_tree(root, headers)

            extra = root / "usr/lib/modules/unexpected-empty-directory"
            extra.mkdir()
            with self.assertRaisesRegex(ValueError, "extracted RPM tree"):
                _validate_extracted_tree(root, headers)
            extra.rmdir()

            original = root / "usr/lib"
            moved = root / "usr/lib-real"
            original.rename(moved)
            original.symlink_to("lib-real", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "extracted RPM tree"):
                _validate_extracted_tree(root, headers)

    def test_rpm_snapshot_is_non_symlink_read_only_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.rpm"
            snapshot = root / "snapshot.rpm"
            source.write_bytes(b"first RPM identity")
            digest = _snapshot_rpm(source, snapshot)

            source.write_bytes(b"replacement RPM")
            self.assertEqual(snapshot.read_bytes(), b"first RPM identity")
            self.assertEqual(digest, "3be71083bee2475ce082558c5827b581ef2446e9087178aef29aca0f2186e73a")
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o444)

            symlink = root / "symlink.rpm"
            symlink.symlink_to(source.name)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                _snapshot_rpm(symlink, root / "rejected.rpm")

    def test_rpm_fifo_inputs_fail_closed_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            fifo = root / "payload.rpm"
            os.mkfifo(fifo)
            commands = (
                (
                    "from pathlib import Path; "
                    "from tools.gate01.rpm_artifacts import _snapshot_rpm; "
                    "import sys; _snapshot_rpm(Path(sys.argv[1]), Path(sys.argv[2]))",
                    [str(fifo), str(root / "snapshot.rpm")],
                ),
                (
                    "import os, sys; "
                    "from tools.gate01.rpm_artifacts import _retained_file_digest; "
                    "fd=os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY); "
                    "_retained_file_digest(fd, sys.argv[2])",
                    [str(root), fifo.name],
                ),
            )
            for program, arguments in commands:
                with self.subTest(program=program):
                    result = subprocess.run(
                        [sys.executable, "-c", program, *arguments],
                        cwd=REPO,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=2,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"regular", result.stderr)

    def test_frozen_python_bootstrap_ignores_hostile_ambient_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            frozen = root / "frozen"
            hostile = root / "hostile"
            marker = root / "sitecustomize-ran"
            output = root / "runtime.json"
            hostile.mkdir()
            (hostile / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            for relative in (
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
            ):
                destination = frozen / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, destination)

            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONHOME": str(root / "missing-python-home"),
                    "PYTHONPATH": str(hostile),
                    "PYTHONUSERBASE": str(hostile),
                    "PYTHONSTARTUP": str(hostile / "sitecustomize.py"),
                }
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(frozen / "tools/gate01/rpm_artifacts.py"),
                    "bootstrap",
                    "--root",
                    str(frozen),
                    "--",
                    "-m",
                    "tools.gate01.rpm_artifacts",
                    "audit-runtime",
                    "--expected-root",
                    str(frozen),
                    "--output",
                    str(output),
                ],
                cwd=hostile,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse(marker.exists())
            runtime = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                runtime["flags"],
                {
                    "dont_write_bytecode": 1,
                    "ignore_environment": 1,
                    "isolated": 1,
                    "no_site": 1,
                    "no_user_site": 1,
                    "safe_path": True,
                },
            )
            self.assertEqual(runtime["frozen_root"], str(frozen))
            self.assertEqual(runtime["sys_path"][0], str(frozen))
            self.assertNotIn(str(hostile), runtime["sys_path"])

            rejected = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(frozen / "tools/gate01/rpm_artifacts.py"),
                    "bootstrap",
                    "--root",
                    str(frozen),
                    "--",
                    "-c",
                    "raise SystemExit(0)",
                ],
                cwd=hostile,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stderr, b"RPM artifact validation failed\n")

    def test_kernel_build_entrypoint_and_launcher_are_isolated_and_thin(self) -> None:
        driver = (REPO / "scripts/gate01/build-kernel.sh").read_text(
            encoding="utf-8"
        )
        self.assertTrue(driver.startswith("#!/bin/bash -p\nset -Eeuo pipefail\n"))
        self.assertIn("/usr/bin/env -i", driver)
        self.assertIn("/usr/bin/python3 -I -S -B", driver)
        self.assertIn("tools/gate01/kernel_bootstrap.py", driver)
        self.assertIn('exec 60<"$bootstrap"', driver)
        self.assertIn("/proc/self/fd/60", driver)
        for forbidden in (
            "podman", "rpm2cpio", "rpmbuild", "module-signing.key",
            "kernel.receipt", "scan-fixed-fds", "mount ",
        ):
            self.assertNotIn(forbidden, driver)

        result = subprocess.run(
            [
                "/usr/bin/python3", "-I", "-S", "-B",
                str(REPO / "tools/gate01/kernel_build.py"), "--help",
            ],
            cwd=REPO,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
            },
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"requires sealed bootstrap entry", result.stderr)

    def test_launcher_rejects_hostile_startup_environment_before_supervisor(self) -> None:
        driver = REPO / "scripts/gate01/build-kernel.sh"
        for variable in (
            "BASH_ENV", "ENV", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
            "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE", "PYTHONSTARTUP",
            "PYTHONINSPECT", "PYTHONWARNINGS", "PYTHONBREAKPOINT",
            "PYTHONHASHSEED", "PYTHONSAFEPATH", "BASH_FUNC_injected%%",
        ):
            environment = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
                variable: "/hostile/value",
            }
            result = subprocess.run(
                ["/bin/bash", "-p", str(driver), "not-a-builder"],
                cwd=REPO,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.subTest(variable=variable):
                self.assertEqual(result.returncode, 2)
                self.assertIn(variable.encode(), result.stderr)

    def test_launcher_executes_stub_with_only_exact_arguments_and_environment(self) -> None:
        from tools.gate01.kernel_bootstrap import BOOTSTRAP_SOURCE_PATHS
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name) / "physical-repository"
            driver = root / "scripts/gate01/build-kernel.sh"
            supervisor = root / "tools/gate01/kernel_build.py"
            for relative in BOOTSTRAP_SOURCE_PATHS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / relative, destination)
                destination.chmod(0o755 if relative.endswith(".sh") else 0o644)
            supervisor.write_text(
                "import fcntl, hashlib, json, os, sys\n"
                "def sealed_main():\n"
                " mode = os.umask(0o777)\n"
                " os.umask(mode)\n"
                " authority=json.loads(os.pread(62,os.fstat(62).st_size,0))\n"
                " assert authority['capsule_sha256']==hashlib.sha256(os.pread(61,os.fstat(61).st_size,0)).hexdigest()\n"
                " assert fcntl.fcntl(61,fcntl.F_GET_SEALS)==15 and fcntl.fcntl(62,fcntl.F_GET_SEALS)==15\n"
                " try: os.fstat(60)\n"
                " except OSError: bootstrap_closed=True\n"
                " else: bootstrap_closed=False\n"
                " print(json.dumps({'argv': sys.argv[5:], 'closure': authority['ordered_paths'], 'bootstrap_closed': bootstrap_closed, "
                "'environment': dict(os.environ), 'entry': __file__, "
                "'umask': f'{mode:04o}'}, sort_keys=True))\n"
                " return 0\n",
                encoding="utf-8",
            )
            hostile_cwd = Path(directory_name) / "hostile-cwd"
            hostile_cwd.mkdir()
            for arguments, expected_command, expected_tz, expected_umask in (
                (["builder-a"], ["run", "--repo", str(root), "builder-a"], "UTC", "0022"),
                (["builder-b"], ["run", "--repo", str(root), "builder-b"], "Pacific/Honolulu", "0077"),
                (["canonical"], ["run", "--repo", str(root), "canonical"], "UTC", "0022"),
                (["build", "builder-a"], ["run", "--repo", str(root), "builder-a"], "UTC", "0022"),
                (["compare"], ["compare", "--repo", str(root)], "UTC", "0022"),
                (["meta-requirements", "builder-a"], ["meta-requirements", "--repo", str(root), "--builder", "builder-a"], "UTC", "0022"),
                (["lifecycle-check"], ["lifecycle-check", "--repository", str(root)], "UTC", "0022"),
            ):
                result = subprocess.run(
                    [driver, *arguments],
                    cwd=hostile_cwd,
                    env={
                        "PATH": "/attacker/bin",
                        "HOME": "/attacker/home",
                        "LANG": "hostile",
                        "UNDECLARED_INPUT": "must-be-removed",
                    },
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with self.subTest(arguments=arguments):
                    self.assertEqual(
                        result.returncode, 0, result.stderr.decode()
                    )
                    observed = json.loads(result.stdout)
                    self.assertEqual(
                        observed["argv"],
                        expected_command,
                    )
                    self.assertEqual(observed["closure"], list(BOOTSTRAP_SOURCE_PATHS))
                    self.assertTrue(observed["bootstrap_closed"])
                    self.assertTrue(observed["entry"].startswith("/proc/self/fd/61/"))
                    self.assertEqual(
                        observed["environment"],
                        {
                            "HOME": "/tmp",
                            "LANG": "C.UTF-8",
                            "LC_ALL": "C.UTF-8",
                            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                            "TZ": expected_tz,
                        },
                    )
                    self.assertEqual(observed["umask"], expected_umask)

    def test_launcher_rejects_root_before_repository_python_dispatch(self) -> None:
        driver = (REPO / "scripts/gate01/build-kernel.sh").read_text(
            encoding="utf-8"
        )
        guard = driver.index("EUID")
        supervisor = driver.index("tools/gate01/kernel_bootstrap.py")
        dispatch = driver.index("/usr/bin/python3")
        self.assertLess(guard, supervisor)
        self.assertLess(guard, dispatch)

    def test_retained_rpm_rebinding_detects_post_inspection_changes(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        source_filename = "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
        binary_filenames = [
            "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm",
            "kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm",
            "kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm",
        ]
        payloads = [b"source RPM", b"meta RPM", b"core RPM", b"modules RPM"]
        manifest["source_rpms"][0]["sha256"] = hashlib.sha256(payloads[0]).hexdigest()
        for package, payload in zip(
            manifest["binary_rpms"], payloads[1:], strict=True
        ):
            package["sha256"] = hashlib.sha256(payload).hexdigest()

        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            rpm_root = root / "RPMS"
            rpm_dir = rpm_root / "x86_64"
            srpm_dir = root / "SRPMS"
            rpm_dir.mkdir(parents=True)
            srpm_dir.mkdir()
            (srpm_dir / source_filename).write_bytes(payloads[0])
            for filename, payload in zip(binary_filenames, payloads[1:], strict=True):
                (rpm_dir / filename).write_bytes(payload)

            validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)

            core = rpm_dir / binary_filenames[1]
            core.write_bytes(b"replacement core RPM")
            with self.assertRaisesRegex(ValueError, "retained RPM"):
                validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)
            core.write_bytes(payloads[2])

            (rpm_dir / "unexpected.rpm").write_bytes(b"extra RPM")
            with self.assertRaisesRegex(ValueError, "retained RPM set"):
                validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)
            (rpm_dir / "unexpected.rpm").unlink()

            (rpm_root / "aarch64").mkdir()
            with self.assertRaisesRegex(ValueError, "retained RPM root"):
                validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)
            (rpm_root / "aarch64").rmdir()

            original_digest = rpm_artifacts._hash_bound_file
            mutated = False

            def mutate_checked_directory(record: dict[str, object]) -> str:
                nonlocal mutated
                digest = original_digest(record)
                if Path(record["path"]).name == binary_filenames[0] and not mutated:
                    (srpm_dir / "late-replacement.rpm").write_bytes(b"late RPM")
                    mutated = True
                return digest

            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=mutate_checked_directory,
            ):
                with self.assertRaisesRegex(ValueError, "retained SRPM set changed"):
                    validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)
            (srpm_dir / "late-replacement.rpm").unlink()

            mutated = False

            def mutate_hashed_source(record: dict[str, object]) -> str:
                nonlocal mutated
                digest = original_digest(record)
                if Path(record["path"]).name == source_filename and not mutated:
                    (srpm_dir / source_filename).write_bytes(b"mutated RPM")
                    mutated = True
                return digest

            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=mutate_hashed_source,
            ):
                with self.assertRaisesRegex(ValueError, "bound proof file bytes changed"):
                    validate_retained_rpm_set(rpm_dir, srpm_dir, manifest)

    def test_final_boundary_rejects_stable_rpm_mismatches_and_source_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            source = root / "source"
            frozen = root / "frozen"
            snapshots = root / "snapshots"
            helper_paths = rpm_artifacts.FROZEN_HELPER_PATHS
            proof_paths = (
                "scripts/gate01/build-kernel.sh",
                "os/kernel/packaging/kernel-openmythos.spec",
                *helper_paths,
            )
            for index, relative in enumerate(proof_paths):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"proof-source-{index}\n".encode())
            for relative in helper_paths:
                path = frozen / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / relative, path)
                path.chmod(0o444)
            for directory in sorted(
                (path for path in frozen.rglob("*") if path.is_dir()), reverse=True
            ):
                directory.chmod(0o555)
            frozen.chmod(0o555)

            spec_snapshot = snapshots / "kernel-openmythos.spec"
            driver_snapshot = snapshots / "build-kernel.sh"
            snapshots.mkdir()
            shutil.copy2(
                source / "os/kernel/packaging/kernel-openmythos.spec",
                spec_snapshot,
            )
            shutil.copy2(source / "scripts/gate01/build-kernel.sh", driver_snapshot)
            spec_snapshot.chmod(0o444)
            driver_snapshot.chmod(0o555)
            source_lines = [
                f"{hashlib.sha256((source / relative).read_bytes()).hexdigest()}  {relative}"
                for relative in proof_paths
            ]
            before_manifest = root / "proof-source-before.sha256"
            final_manifest = root / "proof-source-final.sha256"
            manifest_text = "\n".join(source_lines) + "\n"
            before_manifest.write_text(manifest_text, encoding="utf-8")
            final_manifest.write_text(manifest_text, encoding="utf-8")
            rpm_manifest = root / "rpm-artifacts.json"
            manifest = copy.deepcopy(self.manifest)
            rpm_dir = root / "RPMS/x86_64"
            srpm_dir = root / "SRPMS"
            rpm_dir.mkdir(parents=True)
            srpm_dir.mkdir()
            source_filename = (
                "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
            )
            binary_filenames = [
                "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm",
                "kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm",
                "kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm",
            ]
            payloads = [b"source RPM", b"meta RPM", b"core RPM", b"modules RPM"]
            manifest["source_rpms"][0]["sha256"] = hashlib.sha256(
                payloads[0]
            ).hexdigest()
            for package, payload in zip(
                manifest["binary_rpms"], payloads[1:], strict=True
            ):
                package["sha256"] = hashlib.sha256(payload).hexdigest()
            (srpm_dir / source_filename).write_bytes(payloads[0])
            for filename, payload in zip(binary_filenames, payloads[1:], strict=True):
                (rpm_dir / filename).write_bytes(payload)
            rpm_manifest.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            live_spec = source / "os/kernel/packaging/kernel-openmythos.spec"
            live_spec_bytes = live_spec.read_bytes()
            boundary_arguments = {
                "rpm_dir": rpm_dir,
                "srpm_dir": srpm_dir,
                "rpm_manifest_path": rpm_manifest,
                "expected_rpm_manifest_sha256": hashlib.sha256(
                    rpm_artifacts._canonical_json_bytes(manifest)
                ).hexdigest(),
                "source_root": source,
                "snapshot_root": frozen,
                "spec_snapshot": spec_snapshot,
                "driver_snapshot": driver_snapshot,
                "expected_source_manifest": before_manifest,
                "final_source_manifest": final_manifest,
            }
            validate_final_proof_boundary(**boundary_arguments)

            for role, retained_path, expected_payload in (
                (
                    "srpm",
                    srpm_dir / source_filename,
                    payloads[0],
                ),
                (
                    "binary-rpm",
                    rpm_dir / binary_filenames[1],
                    payloads[2],
                ),
            ):
                with self.subTest(stable_pre_entry_mismatch=role):
                    retained_path.write_bytes(
                        f"stable mismatched {role}".encode("ascii")
                    )
                    try:
                        with self.assertRaisesRegex(
                            ValueError,
                            "retained RPM hash differs from inspected manifest",
                        ):
                            validate_final_proof_boundary(**boundary_arguments)
                    finally:
                        retained_path.write_bytes(expected_payload)

            original_hash = rpm_artifacts._hash_bound_file
            mutated = False

            def mutate_live_source(record: dict[str, object]) -> str:
                nonlocal mutated
                digest = original_hash(record)
                if record.get("kind") == "rpm" and not mutated:
                    live_spec.write_bytes(b"X" * len(live_spec_bytes))
                    mutated = True
                return digest

            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=mutate_live_source,
            ):
                with self.assertRaisesRegex(ValueError, "bound proof file bytes changed"):
                    validate_final_proof_boundary(**boundary_arguments)

            live_spec.write_bytes(live_spec_bytes)
            mutated = False

            def mutate_rpm_during_source_hash(record: dict[str, object]) -> str:
                nonlocal mutated
                digest = original_hash(record)
                if record.get("kind") == "proof-source" and not mutated:
                    (srpm_dir / source_filename).write_bytes(
                        b"RPM changed during source hashing"
                    )
                    mutated = True
                return digest

            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=mutate_rpm_during_source_hash,
            ):
                with self.assertRaisesRegex(
                    ValueError, "retained RPM (?:changed|hash)"
                ):
                    validate_final_proof_boundary(**boundary_arguments)

            (srpm_dir / source_filename).write_bytes(payloads[0])
            rpm_manifest_bytes = rpm_manifest.read_bytes()
            mutated = False

            def mutate_manifest_during_source_hash(
                record: dict[str, object],
            ) -> str:
                nonlocal mutated
                digest = original_hash(record)
                if record.get("kind") == "proof-source" and not mutated:
                    rpm_manifest.write_bytes(b"{}\n")
                    mutated = True
                return digest

            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=mutate_manifest_during_source_hash,
            ):
                with self.assertRaisesRegex(ValueError, "bound proof file bytes changed"):
                    validate_final_proof_boundary(**boundary_arguments)

            rpm_manifest.write_bytes(rpm_manifest_bytes)
            live_helper = source / "tools/gate01/inputs.py"
            live_helper_bytes = live_helper.read_bytes()
            mutated = False

            def replace_helper_during_rpm_hash(record: dict[str, object]) -> str:
                nonlocal mutated
                digest = original_hash(record)
                if record.get("kind") == "rpm" and not mutated:
                    replacement = live_helper.with_name("inputs.py.replacement")
                    replacement.write_bytes(live_helper_bytes)
                    os.replace(replacement, live_helper)
                    mutated = True
                return digest

            descriptors_before = set(os.listdir("/proc/self/fd"))
            with mock.patch.object(
                rpm_artifacts,
                "_hash_bound_file",
                side_effect=replace_helper_during_rpm_hash,
            ):
                with self.assertRaisesRegex(ValueError, "live proof source.*changed"):
                    validate_final_proof_boundary(**boundary_arguments)
            self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors_before)

            replacement_srpm = b"coordinated replacement SRPM"
            (srpm_dir / source_filename).write_bytes(replacement_srpm)
            coordinated_manifest = copy.deepcopy(manifest)
            coordinated_manifest["source_rpms"][0]["sha256"] = hashlib.sha256(
                replacement_srpm
            ).hexdigest()
            rpm_manifest.write_text(
                json.dumps(coordinated_manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "inspected identity"):
                validate_final_proof_boundary(**boundary_arguments)

    def test_inspector_emits_process_local_canonical_manifest_anchor(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        arguments = mock.Mock(
            rpm_dir=Path("/rpm-root/x86_64"),
            srpm_dir=Path("/srpms"),
            output=Path("/inspect/rpm-artifacts.json"),
            extract_root=Path("/inspect/extracted"),
            public_certificate=Path("/public/module-signing.pem"),
            print_manifest_sha256=True,
        )
        expected = hashlib.sha256(
            rpm_artifacts._canonical_json_bytes(manifest)
        ).hexdigest()
        with mock.patch.object(
            rpm_artifacts, "inspect_rpm_set", return_value=manifest
        ), mock.patch("builtins.print") as emitted:
            self.assertEqual(rpm_artifacts._inspect_command(arguments), 0)
        emitted.assert_called_once_with(expected)

    def test_isolation_audit_binds_actual_volume_arguments(self) -> None:
        root = "/repo/build/gate01/builder-a"
        plan = {
            "repository_root": "/repo",
            "output": f"{root}/kernel",
            "build_store": f"{root}/kernel-podman-build",
            "inspection_store": f"{root}/kernel-podman-inspect",
            "private_key_source": "/repo/build/gate01/secrets/module-signing.key",
            "public_certificate_source": (
                f"{root}/kernel-runtime/source-snapshot/module-signing.pem"
            ),
            "signing_environment": {
                "probe": False,
                "build": True,
                "inspection": False,
            },
            "probe_mounts": [],
            "build_mounts": [
                {
                    "source": f"{root}/kernel",
                    "target": "/work",
                    "read_only": False,
                },
                {
                    "source": "/repo/build/gate01/secrets/module-signing.key",
                    "target": "/run/secrets/module-signing.key",
                    "read_only": True,
                },
            ],
            "inspection_mounts": [
                {
                    "source": f"{root}/kernel-runtime/frozen-python",
                    "target": "/verifier",
                    "read_only": True,
                },
                {
                    "source": (
                        f"{root}/kernel-runtime/source-snapshot/module-signing.pem"
                    ),
                    "target": "/public/module-signing.pem",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel/rpmbuild/RPMS",
                    "target": "/rpm-root",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel/rpmbuild/SRPMS",
                    "target": "/srpms",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel-inspection",
                    "target": "/inspect",
                    "read_only": False,
                },
            ],
        }
        build_volumes = [
            f"{root}/kernel:/work:rw",
            "/repo/build/gate01/secrets/module-signing.key:"
            "/run/secrets/module-signing.key:ro",
        ]
        inspection_volumes = [
            f"{root}/kernel-runtime/frozen-python:/verifier:ro",
            f"{root}/kernel-runtime/source-snapshot/module-signing.pem:"
            "/public/module-signing.pem:ro",
            f"{root}/kernel/rpmbuild/RPMS:/rpm-root:ro",
            f"{root}/kernel/rpmbuild/SRPMS:/srpms:ro",
            f"{root}/kernel-inspection:/inspect:rw",
        ]
        with tempfile.TemporaryDirectory() as directory_name:
            plan_path = Path(directory_name) / "isolation.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            arguments = ["audit-isolation", "--plan", str(plan_path)]
            for volume in build_volumes:
                arguments.extend(("--build-volume", volume))
            for volume in inspection_volumes:
                arguments.extend(("--inspection-volume", volume))
            self.assertEqual(rpm_artifacts.main(arguments), 0)

            plan["build_mounts"][0]["source"] = "/safe/replacement-output"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(rpm_artifacts.main(arguments), 1)
            self.assertEqual(output.getvalue(), "RPM artifact validation failed\n")

            plan_path.write_text("{not-json", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(rpm_artifacts.main(arguments), 1)
            self.assertEqual(output.getvalue(), "RPM artifact validation failed\n")

    def test_builder_isolation_plan_rejects_store_or_secret_exposure(self) -> None:
        root = "/repo/build/gate01/builder-a"
        valid = {
            "repository_root": "/repo",
            "output": f"{root}/kernel",
            "build_store": f"{root}/kernel-podman-build",
            "inspection_store": f"{root}/kernel-podman-inspect",
            "private_key_source": "/repo/build/gate01/secrets/module-signing.key",
            "public_certificate_source": (
                f"{root}/kernel-runtime/source-snapshot/module-signing.pem"
            ),
            "signing_environment": {
                "probe": False,
                "build": True,
                "inspection": False,
            },
            "probe_mounts": [],
            "build_mounts": [
                {
                    "source": f"{root}/kernel",
                    "target": "/work",
                    "read_only": False,
                },
                {
                    "source": "/repo/build/gate01/secrets/module-signing.key",
                    "target": "/run/secrets/module-signing.key",
                    "read_only": True,
                },
            ],
            "inspection_mounts": [
                {
                    "source": f"{root}/kernel-runtime/verifier",
                    "target": "/verifier",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel-runtime/source-snapshot/module-signing.pem",
                    "target": "/public/module-signing.pem",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel/rpmbuild/RPMS",
                    "target": "/rpm-root",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel/rpmbuild/SRPMS",
                    "target": "/srpms",
                    "read_only": True,
                },
                {
                    "source": f"{root}/kernel-inspection",
                    "target": "/inspect",
                    "read_only": False,
                },
            ],
        }
        validate_builder_isolation_plan(valid)

        cases = (
            ("build_store", f"{root}/kernel/podman", "store"),
            ("inspection_store", f"{root}/kernel-podman-build", "overlap"),
            (
                "probe_mounts",
                [
                    {
                        "source": "/repo/build/gate01/secrets/module-signing.key",
                        "target": "/run/secrets/module-signing.key",
                        "read_only": True,
                    }
                ],
                "probe",
            ),
            (
                "inspection_mounts",
                [
                    {
                        "source": "/repo",
                        "target": "/repo",
                        "read_only": True,
                    }
                ],
                "repository",
            ),
            (
                "inspection_mounts",
                [
                    *valid["inspection_mounts"],
                    {
                        "source": "/repo/build/gate01/secrets/module-signing.key",
                        "target": "/run/secrets/module-signing.key",
                        "read_only": True,
                    },
                ],
                "inspection must not receive",
            ),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                plan = copy.deepcopy(valid)
                plan[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    validate_builder_isolation_plan(plan)

        overlap_cases = (
            ("build_store", root),
            ("inspection_store", f"{root}/kernel-podman-build/root"),
        )
        for field, value in overlap_cases:
            with self.subTest(overlap=field):
                plan = copy.deepcopy(valid)
                plan[field] = value
                with self.assertRaisesRegex(ValueError, "overlap"):
                    validate_builder_isolation_plan(plan)

        descendant_mount = copy.deepcopy(valid)
        descendant_mount["inspection_mounts"].append(
            {
                "source": f"{root}/kernel-podman-build/root",
                "target": "/leaked-store-root",
                "read_only": True,
            }
        )
        with self.assertRaisesRegex(ValueError, "store"):
            validate_builder_isolation_plan(descendant_mount)

        wrong_key = copy.deepcopy(valid)
        wrong_key["build_mounts"][1]["source"] = "/repo/other/signing.key"
        with self.assertRaisesRegex(ValueError, "exact private key"):
            validate_builder_isolation_plan(wrong_key)

        wrong_certificate = copy.deepcopy(valid)
        wrong_certificate["inspection_mounts"][1]["source"] = "/repo/other.pem"
        with self.assertRaisesRegex(ValueError, "exact public certificate"):
            validate_builder_isolation_plan(wrong_certificate)

        excess_secret = copy.deepcopy(valid)
        excess_secret["build_mounts"].append(
            {
                "source": "/repo/other/second.key",
                "target": "/run/secrets/second.key",
                "read_only": True,
            }
        )
        with self.assertRaisesRegex(ValueError, "secret-like"):
            validate_builder_isolation_plan(excess_secret)

    def test_launcher_rejects_symlink_and_unknown_builder(self) -> None:
        driver = REPO / "scripts/gate01/build-kernel.sh"
        clean_environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
        unknown = subprocess.run(
            ["/bin/bash", "-p", str(driver), "unknown"],
            cwd=REPO,
            env=clean_environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(unknown.returncode, 2)
        self.assertIn(b"builder-a|builder-b|canonical", unknown.stderr)

        with tempfile.TemporaryDirectory() as directory_name:
            link = Path(directory_name) / "build-kernel.sh"
            link.symlink_to(driver)
            rejected = subprocess.run(
                ["/bin/bash", "-p", str(link), "builder-a"],
                cwd=REPO,
                env=clean_environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"symlink", rejected.stderr)

        with tempfile.TemporaryDirectory() as directory_name:
            alias = Path(directory_name) / "repository-alias"
            alias.symlink_to(REPO, target_is_directory=True)
            rejected = subprocess.run(
                [alias / "scripts/gate01/build-kernel.sh", "builder-a"],
                cwd=REPO,
                env=clean_environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"symlink", rejected.stderr)

    def test_frozen_helper_tree_detects_live_change_and_incomplete_closure(self) -> None:
        helper_paths = (
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
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            source = root / "source"
            snapshot = root / "snapshot"
            for index, relative in enumerate(helper_paths):
                source_file = source / relative
                snapshot_file = snapshot / relative
                source_file.parent.mkdir(parents=True, exist_ok=True)
                snapshot_file.parent.mkdir(parents=True, exist_ok=True)
                content = f"helper-{index}\n".encode()
                source_file.write_bytes(content)
                snapshot_file.write_bytes(content)
                snapshot_file.chmod(0o444)
            for directory in sorted(
                (path for path in snapshot.rglob("*") if path.is_dir()),
                reverse=True,
            ):
                directory.chmod(0o555)
            snapshot.chmod(0o555)

            validate_frozen_helper_tree(source, snapshot)

            (source / "tools/gate01/module_key.py").write_bytes(b"changed\n")
            with self.assertRaisesRegex(ValueError, "frozen helper"):
                validate_frozen_helper_tree(source, snapshot)

            module_index = helper_paths.index("tools/gate01/module_key.py")
            (source / "tools/gate01/module_key.py").write_bytes(
                f"helper-{module_index}\n".encode()
            )
            missing = snapshot / "tools/gate01/toolchain.py"
            missing.parent.chmod(0o755)
            missing.unlink()
            with self.assertRaisesRegex(ValueError, "frozen helper"):
                validate_frozen_helper_tree(source, snapshot)

    def test_podman_bare_config_id_is_bound_to_locked_manifest(self) -> None:
        config_digest = "sha256:" + "a" * 64
        manifest_digest = "sha256:" + "b" * 64
        validate_imported_image_identity(
            "a" * 64,
            manifest_digest,
            config_digest,
            manifest_digest,
        )
        for observed_config, observed_manifest in (
            ("c" * 64, manifest_digest),
            ("a" * 64, "sha256:" + "d" * 64),
        ):
            with self.subTest(observed_config=observed_config):
                with self.assertRaisesRegex(ValueError, "image identity"):
                    validate_imported_image_identity(
                        observed_config,
                        observed_manifest,
                        config_digest,
                        manifest_digest,
                    )

    def test_cpio_stream_rejects_symlink_pivot_before_extraction(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        pivot = f"{release}/pivot"
        escaped = f"{pivot}/escaped.ko"
        headers = [
            {
                "path": pivot,
                "raw_mode": stat.S_IFLNK | 0o777,
                "size": len("kernel"),
                "user": "root",
                "group": "root",
                "link_target": "kernel",
            },
            {
                "path": escaped,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            },
        ]
        archive = _newc_archive(
            [
                _newc_entry(
                    "." + pivot,
                    mode=stat.S_IFLNK | 0o777,
                    data=b"kernel",
                    inode=1,
                ),
                _newc_entry(
                    "." + escaped,
                    mode=stat.S_IFREG | 0o644,
                    data=b"x",
                    inode=2,
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "payload.cpio"
            spool.write_bytes(archive)
            with self.assertRaisesRegex(ValueError, "below CPIO symlink"):
                _validate_cpio_archive(spool, headers)

    def test_cpio_stream_rejects_regular_hardlink(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        path = f"{release}/linked"
        headers = [
            {
                "path": path,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        archive = _newc_archive(
            [
                _newc_entry(
                    "." + path,
                    mode=stat.S_IFREG | 0o644,
                    data=b"x",
                    links=2,
                )
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "payload.cpio"
            spool.write_bytes(archive)
            with self.assertRaisesRegex(ValueError, "hardlink"):
                _validate_cpio_archive(spool, headers)

    def test_header_directory_must_be_root_owned_and_safe_mode(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        for field, value, message in (
            ("user", "daemon", "root:root"),
            ("raw_mode", stat.S_IFDIR | 0o777, "directory mode"),
        ):
            with self.subTest(field=field):
                header = {
                    "path": release,
                    "raw_mode": stat.S_IFDIR | 0o755,
                    "size": 0,
                    "user": "root",
                    "group": "root",
                    "link_target": "",
                }
                header[field] = value
                with mock.patch(
                    "tools.gate01.rpm_artifacts._run_text", return_value=release + "\n"
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        _validate_pre_extraction_paths(Path("payload.rpm"), [header], listing_override=[header["path"]])

    def test_explicit_directory_topology_must_exactly_match_module_ancestors(self) -> None:
        release = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64"
        kernel = f"{release}/kernel"
        drivers = f"{kernel}/drivers"
        module = f"{drivers}/virtio.ko"

        def header(path: str, mode: int) -> dict[str, object]:
            return {
                "path": path,
                "raw_mode": mode,
                "size": 0 if stat.S_ISDIR(mode) else 1,
                "user": "root",
                "group": "root",
                "link_target": "",
            }

        valid_headers = [
            header(kernel, stat.S_IFDIR | 0o755),
            header(drivers, stat.S_IFDIR | 0o755),
            header(module, stat.S_IFREG | 0o644),
        ]
        cases = (
            [
                header(release, stat.S_IFDIR | 0o755),
                *valid_headers,
            ],
            [valid_headers[0], valid_headers[2]],
        )
        for headers in cases:
            with self.subTest(paths=[item["path"] for item in headers]):
                listing = "\n".join(str(item["path"]) for item in headers) + "\n"
                with mock.patch(
                    "tools.gate01.rpm_artifacts._run_text", return_value=listing
                ):
                    with self.assertRaisesRegex(ValueError, "directory topology"):
                        _validate_pre_extraction_paths(Path("payload.rpm"), headers, listing_override=[header["path"] for header in headers])

    def test_binary_rpm_hash_differences_are_advisory(self) -> None:
        other = copy.deepcopy(self.manifest)
        other["binary_rpms"][2]["sha256"] = "f" * 64

        comparison = compare_rpm_manifests(self.manifest, other)

        self.assertEqual(comparison["verdict"], "pass")
        self.assertEqual(comparison["source_rpm"], "pass")
        self.assertEqual(comparison["package_nevras"], "pass")
        self.assertEqual(comparison["installed_files"], "pass")
        self.assertEqual(
            comparison["advisory_binary_rpm_hash_differences"],
            [
                {
                    "left_sha256": "3" * 64,
                    "nevra": (
                        "kernel-openmythos-modules-6.18.48-"
                        "1.openmythos.fc44.x86_64"
                    ),
                    "right_sha256": "f" * 64,
                }
            ],
        )

    def test_source_rpm_or_installed_content_difference_fails(self) -> None:
        source_changed = copy.deepcopy(self.manifest)
        source_changed["source_rpms"][0]["sha256"] = "f" * 64
        self.assertEqual(
            compare_rpm_manifests(self.manifest, source_changed)["verdict"],
            "fail",
        )

        file_changed = copy.deepcopy(self.manifest)
        file_changed["binary_rpms"][1]["files"][0]["sha256"] = "f" * 64
        file_changed["binary_rpms"][1]["security_metadata"]["files"][0]["digest"] = "f" * 64
        self.assertEqual(
            compare_rpm_manifests(self.manifest, file_changed)["verdict"],
            "fail",
        )

    def test_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_rpm_manifest(path)

    def test_loader_requires_complete_security_metadata_before_returning_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "manifest.json"
            value = copy.deepcopy(self.manifest)
            del value["source_rpms"][0]["security_metadata"]
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rpm_manifest(path)


class DescriptorBoundInspectionTests(unittest.TestCase):
    def test_extractor_spawn_failure_releases_original_held_extraction_tree(self) -> None:
        import errno
        descriptor = os.memfd_create("public-cpio-spool", os.MFD_CLOEXEC)
        try:
            with tempfile.TemporaryDirectory() as name:
                initial = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(rpm_artifacts.subprocess, "run", side_effect=OSError(errno.EIO, "injected spawn failure")), self.assertRaises(OSError):
                    rpm_artifacts._extract_validated_cpio_descriptor(descriptor, Path(name) / "extracted", {})
                self.assertEqual(len(os.listdir("/proc/self/fd")), initial)
        finally:
            os.close(descriptor)

    def test_legacy_path_inspection_refuses_before_any_path_or_tool_access(self) -> None:
        with mock.patch.object(Path, "glob", side_effect=AssertionError("legacy path traversal reached")):
            with self.assertRaisesRegex(ValueError, "descriptor"):
                rpm_artifacts.inspect_rpm_set(*(Path("/untrusted") for _ in range(5)))

    def test_evidence_descriptor_zero_write_fails_without_retry_spin(self) -> None:
        descriptor = os.memfd_create("public-json-output", os.MFD_CLOEXEC)
        try:
            with mock.patch.object(rpm_artifacts.os, "write", side_effect=[0, RuntimeError("would spin")]), self.assertRaisesRegex(RuntimeError, "short write"):
                rpm_artifacts._write_json_descriptor(descriptor, {"verdict": "pass"})
        finally:
            os.close(descriptor)

    def test_meta_consumer_requeries_full_security_metadata(self) -> None:
        package = copy.deepcopy(load_rpm_manifest(VALID)["binary_rpms"][0])
        package.update(source_package="0", source_rpm=rpm_artifacts.EXPECTED_SOURCE_FILENAME)
        metadata = package.pop("security_metadata")
        package.pop("files")
        spool = os.memfd_create("meta-cpio", os.MFD_CLOEXEC)
        try:
            for corrupt in (False, True):
                changed = copy.deepcopy(metadata)
                if corrupt:
                    changed["dependencies"]["conflicts"].append({"name": "forbidden", "flags": 0, "version": ""})
                with self.subTest(corrupt=corrupt), mock.patch.object(rpm_artifacts, "_query_package_descriptor", return_value=package), mock.patch.object(rpm_artifacts, "_query_file_headers_descriptor", return_value=[]), mock.patch.object(rpm_artifacts, "_validate_pre_extraction_descriptor"), mock.patch.object(rpm_artifacts, "_spool_rpm_cpio_descriptor", side_effect=lambda *_args: os.dup(spool)), mock.patch.object(rpm_artifacts, "_validate_cpio_archive_descriptor", return_value={}), mock.patch.object(rpm_artifacts, "_query_security_metadata", return_value=changed) as query, mock.patch.object(rpm_artifacts, "_validate_meta_requirements_descriptor", return_value=["requirements"]) as requires:
                    if corrupt:
                        with self.assertRaises(ValueError):
                            rpm_artifacts._validate_meta_rpm_descriptor(33)
                        requires.assert_not_called()
                    else:
                        self.assertEqual(rpm_artifacts._validate_meta_rpm_descriptor(33), ["requirements"])
                    self.assertEqual(query.call_args.args[:4], (33, "meta", [], {}))
        finally:
            os.close(spool)

    def test_meta_fixed_worker_accepts_only_sealed_code_and_read_only_meta(self) -> None:
        from tools.gate01.proof_io import FixedDescriptors, seal_public_bytes, _canonical_json
        expected = [f"kernel-openmythos-{role}-uname-r = {rpm_artifacts.KERNEL_RELEASE}" for role in ("core", "modules")]
        capsule = seal_public_bytes(b"sealed code", "meta-worker-code")
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "meta.rpm"
            path.write_bytes(b"rpm fixture")
            readonly = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            writable = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            try:
                for extra in (None, 21, 22, 23, 24, 25, 26, 30, 31, 32, 40, 41, 42, 50):
                    mapping = {20: capsule.fd, 33: readonly}
                    if extra is not None:
                        mapping[extra] = readonly
                    with self.subTest(extra=extra), FixedDescriptors(mapping), mock.patch.object(rpm_artifacts, "_validate_meta_rpm_descriptor", return_value=expected) as query:
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            if extra is None:
                                self.assertEqual(rpm_artifacts._meta_fixed_descriptor_command(None), 0)
                                self.assertEqual(output.getvalue().encode(), _canonical_json({"requirements": expected}))
                                query.assert_called_once_with(33)
                            else:
                                with self.assertRaisesRegex(ValueError, "unexpected inherited descriptor"):
                                    rpm_artifacts._meta_fixed_descriptor_command(None)
                                query.assert_not_called()
                with FixedDescriptors({20: capsule.fd, 33: writable}), self.assertRaisesRegex(ValueError, "read-only"):
                    rpm_artifacts._meta_fixed_descriptor_command(None)
            finally:
                os.close(readonly)
                os.close(writable)
                capsule.close()

    def test_inspector_failures_redact_candidate_paths_links_and_tool_stderr(self) -> None:
        secret = "candidate-private-secret"
        operations = (
            lambda: rpm_artifacts._cpio_payload_path("../" + secret),
            lambda: rpm_artifacts._validate_absolute_payload_path("/../" + secret),
            lambda: rpm_artifacts._validate_symlink_target(PurePosixPath("/" + secret), "/escape/" + secret),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(ValueError) as raised:
                    operation()
                self.assertNotIn(secret, str(raised.exception))
        descriptor = os.memfd_create("spool-error-rpm", os.MFD_CLOEXEC)
        try:
            with tempfile.TemporaryDirectory() as name, mock.patch.object(rpm_artifacts.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout=b"", stderr=secret.encode())):
                with self.assertRaises(RuntimeError) as raised:
                    rpm_artifacts._spool_rpm_cpio_descriptor(descriptor, Path(name))
            self.assertEqual(str(raised.exception), "rpm2cpio failed for held RPM descriptor")
        finally:
            os.close(descriptor)

    def test_inspector_cli_failure_has_fixed_diagnostic_without_traceback(self) -> None:
        for failure in (ValueError("candidate-private-secret"), OSError("candidate-private-secret"), subprocess.CalledProcessError(1, ["tool", "candidate-private-secret"], stderr=b"candidate-private-secret")):
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(kind=type(failure).__name__):
                with mock.patch.object(rpm_artifacts, "_inspect_fixed_descriptors_command", side_effect=failure), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = rpm_artifacts.main(["inspect-fixed-fds", "--extract-root", "/tmp/work/extracted", "--spec-sha256", "a" * 64, "--source-sha256", "b" * 64, "--config-sha256", "c" * 64, "--certificate-sha256", "d" * 64])
                self.assertEqual(status, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(errors.getvalue(), "RPM artifact validation failed\n")

    def test_meta_security_query_binds_payload_bytes_and_rejects_every_forbidden_tag(self) -> None:
        package = load_rpm_manifest(VALID)["binary_rpms"][0]
        baseline = package["security_metadata"]
        values = {tag: [] for tag in rpm_artifacts.SECURITY_QUERY_TAGS}
        for family, prefix in rpm_artifacts.SECURITY_DEPENDENCY_PREFIXES.items():
            for key, suffix in (("name", "NAME"), ("flags", "FLAGS"), ("version", "VERSION")):
                values[prefix + suffix] = [record[key] for record in baseline["dependencies"][family]]
        for key, tag in rpm_artifacts.SECURITY_PAYLOAD_TAGS.items():
            values[tag] = [baseline["payload"][key]]
        header = b"\x8e\xad\xe8\x01\0\0\0\0" + b"\0" * 8
        compressed, cpio = b"compressed payload bytes", _newc_archive([])
        rpm_bytes = b"\xed\xab\xee\xdb\x03\x00" + b"\0" * 90 + header + header + compressed
        values["PAYLOADSHA256"] = [hashlib.sha256(compressed).hexdigest()]
        values["PAYLOADSHA256ALT"] = [hashlib.sha256(cpio).hexdigest()]
        rpm_fd, spool_fd = os.memfd_create("security-rpm", os.MFD_CLOEXEC), os.memfd_create("security-cpio", os.MFD_CLOEXEC)
        try:
            os.write(rpm_fd, rpm_bytes)
            os.write(spool_fd, cpio)
            with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values):
                result = rpm_artifacts._query_security_metadata(rpm_fd, "meta", [], {}, spool_fd)
            self.assertEqual(result["payload"]["compressed_sha256"], hashlib.sha256(compressed).hexdigest())
            for tag in (*rpm_artifacts.SECURITY_FORBIDDEN_TAGS, "PAYLOADSIZE", "PAYLOADSIZEALT"):
                with self.subTest(tag=tag):
                    changed = copy.deepcopy(values)
                    changed[tag] = [1]
                    with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=changed):
                        with self.assertRaisesRegex(ValueError, "security_metadata"):
                            rpm_artifacts._query_security_metadata(rpm_fd, "meta", [], {}, spool_fd)
            os.pwrite(rpm_fd, b"X", len(rpm_bytes) - 1)
            with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values):
                with self.assertRaisesRegex(ValueError, "payload digest"):
                    rpm_artifacts._query_security_metadata(rpm_fd, "meta", [], {}, spool_fd)
        finally:
            os.close(spool_fd)
            os.close(rpm_fd)

    def test_cpio_security_numeric_fields_and_inode_aliases_are_rejected(self) -> None:
        first = _newc_entry("./safe", mode=stat.S_IFREG | 0o644, data=b"good", inode=1)
        header = {"path": "/safe", "raw_mode": stat.S_IFREG | 0o644, "size": 4, "user": "root", "group": "root", "link_target": ""}
        for index, value in ((0, 0), (5, 0), (7, 1), (8, 1), (9, 1), (10, 1), (12, 1)):
            with self.subTest(field=index):
                mutated = first[:6 + index * 8] + f"{value:08x}".encode() + first[14 + index * 8:]
                descriptor = os.memfd_create("cpio-policy-test", os.MFD_CLOEXEC)
                try:
                    os.write(descriptor, _newc_archive([mutated]))
                    with self.assertRaisesRegex(ValueError, "CPIO"):
                        _validate_cpio_archive_descriptor(descriptor, [header])
                finally:
                    os.close(descriptor)
        descriptor = os.memfd_create("cpio-inode-test", os.MFD_CLOEXEC)
        try:
            os.write(descriptor, _newc_archive([first, _newc_entry("./second", mode=stat.S_IFREG | 0o644, data=b"good", inode=1)]))
            with self.assertRaisesRegex(ValueError, "CPIO"):
                _validate_cpio_archive_descriptor(descriptor, [header, {**header, "path": "/second"}])
        finally:
            os.close(descriptor)

    def test_rpm_tag_parser_rejects_ambiguous_counts_types_and_trailing_output(self) -> None:
        tags = ("REQUIRENAME", "REQUIREFLAGS", "REQUIREVERSION")
        values = {"REQUIRENAME": ["line\nwith\rcontrols\x1e\x1f"], "REQUIREFLAGS": [8], "REQUIREVERSION": ["version"]}
        valid = _test_rpm_tag_output(tags, values).encode()
        self.assertEqual(rpm_artifacts._parse_rpm_tag_values(valid, tags), values)
        for malformed in (
            valid + b"ignored\n", valid[:-1], valid.replace(b"REQUIRENAME", b"UNKNOWN", 1),
            valid.replace(b"\n1\n1\n", b"\n0\n1\n", 1), valid.replace(b"\n1\n1\n", b"\n1\n0\n", 1),
            valid.replace(b"\n1\n1\n", b"\n1\n01\n", 1), valid.replace(b"\n8\n", b"\ntrue\n"),
            valid.replace(b"\n8\n", b"\nNaN\n"), valid.replace(b"\n8\n", b'\n{"secret":1,"secret":2}\n'),
            valid.replace(b"\n8\n", b"\n[]\n"), valid.replace(b"\n8\n", b"\nnull\n"),
        ):
            with self.subTest(case=hashlib.sha256(malformed).hexdigest()[:8]):
                with self.assertRaisesRegex(ValueError, "framing"):
                    rpm_artifacts._parse_rpm_tag_values(malformed, tags)
        with self.assertRaisesRegex(ValueError, "parallel"):
            rpm_artifacts._parallel_rpm_records({"REQUIRENAME": [], "REQUIREFLAGS": [0], "REQUIREVERSION": []}, {"name": "REQUIRENAME", "flags": "REQUIREFLAGS", "version": "REQUIREVERSION"})

    def test_rpm_unsupported_tag_and_tool_error_are_not_absence_or_echoed(self) -> None:
        for support, stderr, status in ((b"NAME\n", b"", 0), (b"FILECAPS\n", b"attacker-controlled-secret", 1)):
            with self.subTest(status=status):
                result = subprocess.CompletedProcess([], status, stdout=support, stderr=stderr)
                with mock.patch.object(rpm_artifacts.subprocess, "run", return_value=result):
                    with self.assertRaises(ValueError) as raised:
                        rpm_artifacts._query_rpm_tag_values(37, ("FILECAPS",))
                self.assertNotIn("attacker-controlled", str(raised.exception))

    def test_rpm_raw_header_rejects_unqueryable_security_ids_in_either_header(self) -> None:
        def header(tags: tuple[int, ...]) -> bytes:
            indexes = b"".join(tag.to_bytes(4, "big") + (7).to_bytes(4, "big") + index.to_bytes(4, "big") + (1).to_bytes(4, "big") for index, tag in enumerate(tags))
            return b"\x8e\xad\xe8\x01\0\0\0\0" + len(tags).to_bytes(4, "big") + len(tags).to_bytes(4, "big") + indexes + b"x" * len(tags)
        for tag in (None, 1177, 1186, 1187):
            for role in ("signature", "main"):
                with self.subTest(tag=tag, role=role):
                    signature = header((1000,) if tag is None or role == "main" else (tag,))
                    signature += b"\0" * (-len(signature) % 8)
                    main = header((1001,) if tag is None or role == "signature" else (tag,))
                    compressed = b"compressed payload fixture"
                    value = b"\xed\xab\xee\xdb\x03\x00" + b"\0" * 90 + signature + main + compressed
                    descriptor = os.memfd_create("rpm-raw-header-test", os.MFD_CLOEXEC)
                    try:
                        os.write(descriptor, value)
                        if tag is None:
                            self.assertEqual(rpm_artifacts._compressed_payload_sha256(descriptor), hashlib.sha256(compressed).hexdigest())
                        else:
                            with self.assertRaisesRegex(ValueError, "forbidden raw"):
                                rpm_artifacts._compressed_payload_sha256(descriptor)
                    finally:
                        os.close(descriptor)

    def test_held_file_header_query_preserves_json_framing_and_forbids_rpm_manifests(self) -> None:
        tags = ("FILENAMES", "FILEMODES", "LONGFILESIZES", "FILEUSERNAME", "FILEGROUPNAME", "FILELINKTOS")
        values = {name: [value] for name, value in zip(tags, ("/safe\nnot-another-record", 33188, 4, "root", "root", ""), strict=True)}
        calls = []
        def run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append((arguments, kwargs))
            output = "\n".join(tags) + "\n" if "--querytags" in arguments else _test_rpm_tag_output(tags, values)
            return subprocess.CompletedProcess(arguments, 0, stdout=output if kwargs.get("text") else output.encode(), stderr="" if kwargs.get("text") else b"")
        with mock.patch.object(rpm_artifacts.subprocess, "run", side_effect=run):
            observed = rpm_artifacts._query_file_headers_descriptor(37)
        self.assertEqual(observed, [{"path": "/safe\nnot-another-record", "raw_mode": 33188, "size": 4, "user": "root", "group": "root", "link_target": ""}])
        query_calls = [call for call in calls if "--querytags" not in call[0]]
        self.assertEqual(len(query_calls), 1)
        self.assertEqual(query_calls[0][0][:4], ["/usr/bin/rpm", "--nomanifest", "-qp", "--qf"])
        self.assertEqual(query_calls[0][0][-1], "/proc/self/fd/37")
        self.assertEqual(query_calls[0][1]["pass_fds"], (37,))

    def test_meta_rejects_extra_non_uname_requires(self) -> None:
        requires = copy.deepcopy(load_rpm_manifest(VALID)["binary_rpms"][0]["security_metadata"]["dependencies"]["requires"])
        requires.append({"name": "attacker-controlled-install-side-effect", "flags": 0, "version": ""})
        values = {"REQUIRENAME": [record["name"] for record in requires], "REQUIREFLAGS": [record["flags"] for record in requires], "REQUIREVERSION": [record["version"] for record in requires]}
        with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values):
            with self.assertRaises(ValueError):
                _validate_meta_requirements_descriptor(37)

    def test_package_identity_and_listing_use_framed_held_fd_queries(self) -> None:
        tags = ("NAME", "EPOCH", "VERSION", "RELEASE", "ARCH", "NEVRA", "SOURCEPACKAGE", "SOURCERPM")
        values = dict(zip(tags, (["name\x1f\nnot-a-field"], [], ["version"], ["release"], ["x86_64"], ["nevra"], [], ["source.src.rpm"]), strict=True))
        descriptor = os.memfd_create("rpm-query-protocol", os.MFD_CLOEXEC)
        try:
            with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values) as query, mock.patch.object(rpm_artifacts, "_run_text_for_descriptors", return_value="\x1f".join(("name", "0", "version", "release", "x86_64", "nevra", "0", "source.src.rpm"))):
                package = rpm_artifacts._query_package_descriptor(descriptor)
            self.assertEqual(package["name"], values["NAME"][0])
            self.assertEqual(package["epoch"], "0")
            self.assertEqual(package["source_package"], "0")
            query.assert_called_once_with(descriptor, tags)
            with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value={"FILENAMES": []}) as query:
                rpm_artifacts._validate_pre_extraction_descriptor(descriptor, [])
            query.assert_called_once_with(descriptor, ("FILENAMES",))
        finally:
            os.close(descriptor)

    def test_non_rpm_manifest_fallback_is_disabled_for_every_held_query(self) -> None:
        descriptor = os.memfd_create("not-an-rpm", os.MFD_CLOEXEC)
        os.write(descriptor, b"/candidate/secret.rpm\n")
        try:
            for operation in (rpm_artifacts._query_package_descriptor, rpm_artifacts._query_file_headers_descriptor, lambda fd: rpm_artifacts._validate_pre_extraction_descriptor(fd, [])):
                calls = []
                def run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                    calls.append(arguments)
                    if "--querytags" in arguments:
                        output = "\n".join(sorted(set(rpm_artifacts.SECURITY_QUERY_TAGS) | {"NAME", "EPOCH", "VERSION", "RELEASE", "ARCH", "NEVRA", "SOURCEPACKAGE", "SOURCERPM"})) + "\n"
                        return subprocess.CompletedProcess(arguments, 0, stdout=output.encode(), stderr=b"")
                    self.assertIn("--nomanifest", arguments)
                    return subprocess.CompletedProcess(arguments, 1, stdout=b"", stderr=b"candidate-secret")
                with self.subTest(operation=operation.__name__), mock.patch.object(rpm_artifacts.subprocess, "run", side_effect=run):
                    with self.assertRaisesRegex(ValueError, "held RPM metadata query failed"):
                        operation(descriptor)
                self.assertTrue(calls)
        finally:
            os.close(descriptor)

    def test_cms_profile_rejects_crypto_valid_extra_objects_signers_attributes_and_certs(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            key, certificate = _create_test_certificate(root, "cms")
            module = _create_test_signed_module(root, key, certificate)
            sha256 = (root / "module-signature.der").read_bytes()
            _create_test_signed_module(root, key, certificate, digest="sha1")
            sha1 = (root / "module-signature.der").read_bytes()
            outer = _test_der_parts(sha256)
            fields = _test_der_parts(_test_der_parts(outer[1])[0])
            sha1_fields = _test_der_parts(_test_der_parts(_test_der_parts(sha1)[1])[0])
            signer = _test_der_parts(fields[-1])[0]
            sha1_signer = _test_der_parts(sha1_fields[-1])[0]
            certificate_der = base64.b64decode(b"".join(certificate.read_bytes().splitlines()[1:-1]), validate=True)
            def cms(parts: list[bytes]) -> bytes:
                return _test_der(0x30, outer[0], _test_der(0xa0, _test_der(0x30, *parts)))
            sha_oid = bytes.fromhex("0609608648016503040201")
            misleading_attrs = _test_der(0xa1, _test_der(0x30, bytes.fromhex("06032a0304"), _test_der(0x31, _test_der(0x04, sha_oid + sha_oid))))
            variants = {
                "trailing-null": sha256 + b"\x05\x00",
                "second-content-info": sha256 + sha256,
                "embedded-certificate": cms([*fields[:-1], _test_der(0xa0, certificate_der), fields[-1]]),
                "two-embedded-certificates": cms([*fields[:-1], _test_der(0xa0, certificate_der, certificate_der), fields[-1]]),
                "sha1-with-misleading-oids": cms([*sha1_fields[:-1], _test_der(0x31, _test_der(0x30, *_test_der_parts(sha1_signer), misleading_attrs))]),
                "mixed-signers": cms([fields[0], _test_der(0x31, *sorted([*_test_der_parts(fields[1]), *_test_der_parts(sha1_fields[1])])), fields[2], _test_der(0x31, *sorted([signer, sha1_signer]))]),
            }
            for label, signature in variants.items():
                with self.subTest(label=label):
                    (root / "adversarial.der").write_bytes(signature)
                    verified = subprocess.run(["/usr/bin/openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(root / "adversarial.der"), "-content", str(root / "unsigned-module"), "-nointern", "-certfile", str(certificate), "-noverify", "-out", os.devnull], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                    self.assertEqual(verified.returncode, 0, label)
                    _test_module_cms(module, signature)
                    with self.assertRaisesRegex(ValueError, "CMS"):
                        _verify_module_signature(module, certificate)
            _test_module_cms(module, sha256)
            _verify_module_signature(module, certificate)

    def test_public_certificate_authority_rejects_bundles_and_trailing_data(self) -> None:
        from tools.gate01.module_key import describe_descriptor
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            key, certificate = _create_test_certificate(root, "certificate")
            _, unrelated = _create_test_certificate(root, "unrelated")
            module = _create_test_signed_module(root, key, certificate)
            good = certificate.read_bytes()
            der = base64.b64decode(b"".join(good.splitlines()[1:-1]), validate=True)
            for label, value in {
                "duplicate": good + good,
                "wrong-first": unrelated.read_bytes() + good,
                "trailing-text": good + b"ignored trailing data",
                "trailing-der": b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der + b"\x05\x00") + b"\n-----END CERTIFICATE-----\n",
                "invalid-base64": good.replace(b"\n", b"!\n", 1),
            }.items():
                with self.subTest(label=label):
                    certificate.write_bytes(value)
                    with self.assertRaisesRegex(ValueError, "certificate"):
                        _verify_module_signature(module, certificate)
                    descriptor = os.open(certificate, os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        with self.assertRaisesRegex(ValueError, "certificate"):
                            describe_descriptor(descriptor)
                    finally:
                        os.close(descriptor)
            certificate.write_bytes(b" \t\r\n" + good + b" \t\r\n")
            _verify_module_signature(module, certificate)

    def test_extraction_authority_survives_until_all_payload_inspection_finishes(self) -> None:
        for attack in ("same-size", "root-replace", "mutate-restore"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                header = {"path": "/safe", "raw_mode": stat.S_IFREG | 0o644, "size": 4, "user": "root", "group": "root", "link_target": ""}
                spool = root / "payload.cpio"
                spool.write_bytes(_newc_archive([_newc_entry("./safe", mode=stat.S_IFREG | 0o644, data=b"good")]))
                descriptor = os.open(spool, os.O_RDONLY | os.O_CLOEXEC)
                bound = None
                try:
                    records = _validate_cpio_archive_descriptor(descriptor, [header])
                    destination = root / "extract"
                    bound = _extract_validated_cpio_descriptor(descriptor, destination, records)
                    if attack == "root-replace":
                        destination.rename(root / "displaced")
                        destination.mkdir()
                        (destination / "safe").write_bytes(b"good")
                        (destination / "safe").chmod(0o644)
                    else:
                        (destination / "safe").write_bytes(b"evil")
                        if attack == "mutate-restore":
                            (destination / "safe").write_bytes(b"good")
                    with self.assertRaisesRegex(ValueError, "payload|extraction"):
                        _inspect_bound_payload_file(header, bound or destination, -1)
                finally:
                    if bound is not None:
                        bound.close()
                    os.close(descriptor)

    def test_sha1_module_signature_is_rejected_even_when_cryptographically_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key, certificate = _create_test_certificate(directory, "sha1")
            module = _create_test_signed_module(
                directory, key, certificate, digest="sha1"
            )
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                _verify_module_signature(module, certificate)

    def test_validated_cpio_descriptor_is_the_descriptor_extracted(self) -> None:
        path = "/usr/lib/modules/6.18.48-1.openmythos.fc44.x86_64/safe"
        headers = [
            {
                "path": path,
                "raw_mode": stat.S_IFREG | 0o644,
                "size": 4,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
        ]
        good = _newc_archive(
            [_newc_entry("." + path, mode=stat.S_IFREG | 0o644, data=b"good")]
        )
        evil = _newc_archive(
            [_newc_entry("../escape", mode=stat.S_IFREG | 0o644, data=b"evil")]
        )
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            spool = root / "payload.cpio"
            spool.write_bytes(good)
            descriptor = os.open(spool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                payload_records = _validate_cpio_archive_descriptor(
                    descriptor, headers
                )
                replacement = root / "replacement.cpio"
                replacement.write_bytes(evil)
                replacement.replace(spool)
                destination = root / "extract"
                extracted_tree = _extract_validated_cpio_descriptor(
                    descriptor, destination, payload_records
                )
                extracted_tree.close()
                self.assertEqual(
                    (destination / path.removeprefix("/")).read_bytes(), b"good"
                )
                self.assertFalse((root / "escape").exists())
            finally:
                os.close(descriptor)

    def test_payload_and_certificate_are_held_across_hash_cms_and_modinfo(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            key, certificate = _create_test_certificate(root, "held")
            module = _create_test_signed_module(root, key, certificate)
            release = "6.18.48-1.openmythos.fc44.x86_64"
            payload_root = root / "payload"
            payload = payload_root / f"usr/lib/modules/{release}/kernel/test.ko"
            payload.parent.mkdir(parents=True)
            shutil.copy2(module, payload)
            payload.chmod(0o644)
            header = {
                "path": f"/usr/lib/modules/{release}/kernel/test.ko",
                "raw_mode": stat.S_IFREG | 0o644,
                "size": payload.stat().st_size,
                "user": "root",
                "group": "root",
                "link_target": "",
            }
            certificate_fd = os.open(
                certificate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            original_run = rpm_artifacts._run_text_for_descriptors
            replaced = False

            def replace_after_first_tool(
                arguments: tuple[str, ...], descriptors: tuple[int, ...]
            ) -> str:
                nonlocal replaced
                if not replaced:
                    replacement = payload.with_name("evil.ko")
                    replacement.write_bytes(b"not the signed module")
                    replacement.chmod(0o644)
                    replacement.replace(payload)
                    replaced = True
                if "signer" in arguments:
                    return "OpenMythos Gate 01 Development Module Key\n"
                if "sig_id" in arguments:
                    return "PKCS#7\n"
                if "vermagic" in arguments:
                    return release + " SMP\n"
                return original_run(arguments, descriptors)

            try:
                with mock.patch.object(
                    rpm_artifacts,
                    "_run_text_for_descriptors",
                    side_effect=replace_after_first_tool,
                ):
                    with self.assertRaisesRegex(ValueError, "payload path identity"):
                        _inspect_bound_payload_file(
                            header, payload_root, certificate_fd
                        )
            finally:
                os.close(certificate_fd)

    def test_source_rpm_payload_is_exact_and_bound_to_input_hashes(self) -> None:
        expected = {
            "kernel-openmythos.spec": hashlib.sha256(b"spec").hexdigest(),
            "linux-6.18.48.tar.xz": hashlib.sha256(b"source").hexdigest(),
            "6.18.48-x86_64.config": hashlib.sha256(b"config").hexdigest(),
            "module-signing.pem": hashlib.sha256(b"cert").hexdigest(),
        }
        valid = {
            name: {
                "path": "/" + name,
                "type": "file",
                "mode": "0644",
                "user": "root",
                "group": "root",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in (
                ("kernel-openmythos.spec", b"spec"),
                ("linux-6.18.48.tar.xz", b"source"),
                ("6.18.48-x86_64.config", b"config"),
                ("module-signing.pem", b"cert"),
            )
        }
        _validate_source_rpm_payload(valid, expected)

        for mutation in ("missing", "extra", "wrong-hash", "symlink"):
            records = copy.deepcopy(valid)
            if mutation == "missing":
                records.pop("module-signing.pem")
            elif mutation == "extra":
                records["private.key"] = copy.deepcopy(
                    records["kernel-openmythos.spec"]
                )
                records["private.key"]["path"] = "/private.key"
            elif mutation == "wrong-hash":
                records["kernel-openmythos.spec"]["sha256"] = "f" * 64
            else:
                records["module-signing.pem"].update(
                    {"type": "symlink", "mode": "0777", "link_target": "elsewhere"}
                )
                records["module-signing.pem"].pop("sha256")
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "source RPM payload"):
                    _validate_source_rpm_payload(records, expected)

    def test_meta_uname_requirements_are_queried_from_the_held_rpm(self) -> None:
        expected = {
            "kernel-openmythos-core-uname-r = 6.18.48-1.openmythos.fc44.x86_64",
            "kernel-openmythos-modules-uname-r = 6.18.48-1.openmythos.fc44.x86_64",
        }
        requires = load_rpm_manifest(VALID)["binary_rpms"][0]["security_metadata"]["dependencies"]["requires"]
        values = {"REQUIRENAME": [record["name"] for record in requires], "REQUIREFLAGS": [record["flags"] for record in requires], "REQUIREVERSION": [record["version"] for record in requires]}
        with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values):
            self.assertEqual(_validate_meta_requirements_descriptor(37), sorted(expected))
        values = {key: value[:1] for key, value in values.items()}
        with mock.patch.object(rpm_artifacts, "_query_rpm_tag_values", return_value=values):
            with self.assertRaisesRegex(ValueError, "uname requirements"):
                _validate_meta_requirements_descriptor(37)


if __name__ == "__main__":
    unittest.main()
