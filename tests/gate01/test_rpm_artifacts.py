from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.gate01.rpm_artifacts import (
    compare_rpm_manifests,
    load_rpm_manifest,
    normalize_source_package_identity,
    _validate_pre_extraction_paths,
    validate_rpm_manifest,
)


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests/gate01/fixtures"
VALID = FIXTURES / "rpm-manifest-valid.json"
DUPLICATE = FIXTURES / "rpm-manifest-duplicate-nevra.json"


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
        }

        normalized = normalize_source_package_identity(header)

        self.assertEqual(normalized["architecture"], "src")
        self.assertEqual(
            normalized["nevra"],
            "kernel-openmythos-6.18.48-1.openmythos.fc44.src",
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
