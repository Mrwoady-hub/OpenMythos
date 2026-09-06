from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
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
                "tools/gate01/inputs.py",
                "tools/gate01/kernel_config.py",
                "tools/gate01/module_key.py",
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
            self.assertIn(b"allowlisted -m", rejected.stderr)

    def test_build_driver_uses_one_isolated_bootstrap_and_never_reloads_plan(
        self,
    ) -> None:
        driver = (REPO / "scripts/gate01/build-kernel.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("PYTHONPATH=", driver)
        self.assertIn("python3 -I -S -B", driver)
        self.assertIn("-I -S -B /verifier/tools/gate01/rpm_artifacts.py", driver)
        self.assertIn('bootstrap --root "$frozen_python_root"', driver)
        self.assertIn("bootstrap --root /verifier", driver)
        self.assertIn("--print-manifest-sha256", driver)
        self.assertNotIn("bound-sha256", driver)
        self.assertLess(driver.index("build_mount_args=("), driver.index("isolation_plan="))
        self.assertNotIn("mount_args_from_isolation_plan", driver)

    def test_cleanup_failures_override_nominal_success_and_attempt_every_step(
        self,
    ) -> None:
        driver = (REPO / "scripts/gate01/build-kernel.sh").read_text(
            encoding="utf-8"
        )
        cleanup_start = driver.index("\ncleanup() {") + 1
        cleanup_end = driver.index("\n}\ntrap cleanup EXIT", cleanup_start) + 2
        cleanup_function = driver[cleanup_start:cleanup_end]
        bootstrap_start = driver.index("  bootstrap_cleanup() {")
        bootstrap_end = driver.index(
            "\n  }\n  trap bootstrap_cleanup EXIT", bootstrap_start
        ) + len("\n  }")
        bootstrap_function = textwrap.dedent(
            driver[bootstrap_start:bootstrap_end]
        )

        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            calls = root / "calls"
            harness = f"""
                set -u
                build_podman_root=build-store
                inspect_podman_root=inspect-store
                inspection_work=inspection-work
                runtime_root=runtime-root
                output={root / 'output'}
                output_scan_complete=1
                frozen_helpers_ready=1
                source_freeze_verified=1
                retained_rpm_binding_verified=1
                remove_builder_tree() {{
                  printf '%s\\n' "$1" >> {calls}
                  [[ $1 != build-store ]]
                }}
                remove_stable_driver_copy() {{
                  printf '%s\\n' stable-driver >> {calls}
                  return 1
                }}
                {cleanup_function}
                trap cleanup EXIT
                exit 0
            """
            result = subprocess.run(
                ["bash", "-c", textwrap.dedent(harness)], check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "build-store",
                    "inspect-store",
                    "inspection-work",
                    "runtime-root",
                    "stable-driver",
                ],
            )
            calls.unlink()
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    textwrap.dedent(harness).replace("exit 0", "exit 37"),
                ],
                check=False,
            )
            self.assertEqual(result.returncode, 37)
            self.assertEqual(len(calls.read_text(encoding="utf-8").splitlines()), 5)

            bootstrap_builder = root / "builder"
            stable_root = bootstrap_builder / ".kernel-driver.ABC12345"
            stable_root.mkdir(parents=True)
            stable_driver = stable_root / "build-kernel.sh"
            stable_driver.write_text("driver\n", encoding="utf-8")
            (stable_root / "cleanup-blocker").write_text("block\n", encoding="utf-8")
            bootstrap_harness = f"""
                set -u
                bootstrap_builder={bootstrap_builder}
                stable_driver_root={stable_root}
                stable_driver={stable_driver}
                {bootstrap_function}
                true
                bootstrap_cleanup
            """
            result = subprocess.run(
                ["bash", "-c", textwrap.dedent(bootstrap_harness)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(result.returncode, 0)

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

    def test_final_boundary_detects_source_mutation_during_rpm_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            source = root / "source"
            frozen = root / "frozen"
            snapshots = root / "snapshots"
            helper_paths = (
                "tools/__init__.py",
                "tools/gate01/__init__.py",
                "tools/gate01/inputs.py",
                "tools/gate01/kernel_config.py",
                "tools/gate01/module_key.py",
                "tools/gate01/rpm_artifacts.py",
                "tools/gate01/toolchain.py",
            )
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
            with self.assertRaisesRegex(ValueError, "actual volume arguments"):
                rpm_artifacts.main(arguments)

            plan_path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                rpm_artifacts.main(arguments)

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

    def test_stable_driver_snapshot_is_removed_on_early_inner_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            repository = Path(directory_name)
            original = repository / "scripts/gate01/build-kernel.sh"
            stable_root = (
                repository
                / "build/gate01/builder-a/.kernel-driver.ABC123xy"
            )
            stable = stable_root / "build-kernel.sh"
            original.parent.mkdir(parents=True)
            stable_root.mkdir(parents=True)
            shutil.copy2(REPO / "scripts/gate01/build-kernel.sh", original)
            shutil.copy2(original, stable)
            stable.chmod(0o555)
            stable_root.chmod(0o500)
            environment = os.environ.copy()
            environment.update(
                {
                    "OPENMYTHOS_STABLE_KERNEL_DRIVER": "1",
                    "OPENMYTHOS_ORIGINAL_REPO": str(repository),
                    "OPENMYTHOS_ORIGINAL_KERNEL_DRIVER": str(original),
                    "OPENMYTHOS_STABLE_KERNEL_DRIVER_ROOT": str(stable_root),
                    "OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256": hashlib.sha256(
                        stable.read_bytes()
                    ).hexdigest(),
                }
            )

            result = subprocess.run(
                ["bash", str(stable), "builder-a"],
                check=False,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(stable_root.exists())

    def test_frozen_helper_tree_detects_live_change_and_incomplete_closure(self) -> None:
        helper_paths = (
            "tools/__init__.py",
            "tools/gate01/__init__.py",
            "tools/gate01/inputs.py",
            "tools/gate01/kernel_config.py",
            "tools/gate01/module_key.py",
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

            (source / "tools/gate01/module_key.py").write_bytes(b"helper-4\n")
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
                        _validate_pre_extraction_paths(Path("payload.rpm"), [header])

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
