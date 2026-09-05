from __future__ import annotations

import copy
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.gate01.rpm_artifacts import (
    compare_rpm_manifests,
    load_rpm_manifest,
    normalize_source_package_identity,
    _extract_validated_cpio,
    _snapshot_rpm,
    _validate_cpio_archive,
    _validate_modules_order,
    _validate_pre_extraction_paths,
    _verify_module_signature,
    validate_builder_isolation_plan,
    validate_imported_image_identity,
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
) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    fields = (
        inode,
        mode,
        uid,
        gid,
        links,
        1787899659,
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
    trailer = _newc_entry("TRAILER!!!", mode=0, inode=0)
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
    directory: Path, key: Path, certificate: Path
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


class RpmManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_rpm_manifest(VALID)

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
                _validate_pre_extraction_paths(Path("payload.rpm"), headers)

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

    def test_builder_isolation_plan_rejects_store_or_secret_exposure(self) -> None:
        root = "/repo/build/gate01/builder-a"
        valid = {
            "repository_root": "/repo",
            "output": f"{root}/kernel",
            "build_store": f"{root}/kernel-podman-build",
            "inspection_store": f"{root}/kernel-podman-inspect",
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
                    "source": f"{root}/kernel/rpmbuild/RPMS/x86_64",
                    "target": "/rpms",
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
            ("inspection_store", f"{root}/kernel-podman-build", "distinct"),
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
                        _validate_pre_extraction_paths(Path("payload.rpm"), [header])

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


if __name__ == "__main__":
    unittest.main()
