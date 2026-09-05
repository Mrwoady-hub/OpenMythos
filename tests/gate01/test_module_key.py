import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class ModuleKeyDescribeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.private_key = self.root / "test.key"
        self.certificate = self.root / "test.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Gate 01 Test/O=OpenMythos Tests/",
                "-keyout",
                os.fspath(self.private_key),
                "-out",
                os.fspath(self.certificate),
            ],
            check=True,
            capture_output=True,
        )

    def describe(
        self, certificate: Path, output: Path
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "python3",
                "-m",
                "tools.gate01.module_key",
                "describe",
                "--certificate",
                os.fspath(certificate),
                "--output",
                os.fspath(output),
            ],
            capture_output=True,
        )

    def test_describe_emits_exact_public_certificate_manifest(self) -> None:
        output = self.root / "nested" / "module-key.json"

        result = self.describe(self.certificate, output)

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "certificate_sha256",
                "spki_sha256",
                "serial",
                "subject",
                "not_before",
                "not_after",
            },
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertRegex(manifest["certificate_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(manifest["spki_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertTrue(output.read_bytes().endswith(b"\n"))

    def test_describe_is_byte_deterministic(self) -> None:
        first = self.root / "first.json"
        second = self.root / "second.json"

        first_result = self.describe(self.certificate, first)
        second_result = self.describe(self.certificate, second)

        self.assertEqual(first_result.returncode, 0, first_result.stderr.decode())
        self.assertEqual(second_result.returncode, 0, second_result.stderr.decode())
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_describe_rejects_missing_certificate(self) -> None:
        result = self.describe(self.root / "missing.pem", self.root / "module-key.json")

        self.assertNotEqual(result.returncode, 0)

    def test_describe_never_writes_private_key_material(self) -> None:
        output = self.root / "module-key.json"

        result = self.describe(self.certificate, output)

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(
            any("PRIVATE KEY" in str(value) for value in manifest.values())
        )


class ModuleKeyScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.private_key = self.root / "outside.key"
        self.certificate = self.root / "outside.pem"
        self.scan_root = self.root / "scan-root"
        self.scan_root.mkdir()
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Gate 01 Scan Test/",
                "-keyout",
                os.fspath(self.private_key),
                "-out",
                os.fspath(self.certificate),
            ],
            check=True,
            capture_output=True,
        )

    def scan(self) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "python3",
                "-m",
                "tools.gate01.module_key",
                "scan",
                "--private-key",
                os.fspath(self.private_key),
                "--root",
                os.fspath(self.scan_root),
            ],
            capture_output=True,
        )

    def test_scan_accepts_tree_without_private_key_material(self) -> None:
        (self.scan_root / "public.txt").write_text("public data\n", encoding="ascii")

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_scan_reports_paths_containing_complete_pem_or_der_secret(self) -> None:
        (self.scan_root / "pem-copy.bin").write_bytes(
            b"prefix\n" + self.private_key.read_bytes() + b"suffix\n"
        )
        private_der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                os.fspath(self.private_key),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        nested = self.scan_root / "nested"
        nested.mkdir()
        (nested / "der-copy.bin").write_bytes(private_der)

        result = self.scan()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout.decode().splitlines(),
            ["nested/der-copy.bin", "pem-copy.bin"],
        )
        self.assertNotIn(self.private_key.read_bytes(), result.stdout)

    def test_scan_rejects_private_key_marker_without_complete_secret(self) -> None:
        marker = b"".join(
            [b"-----BEGIN ", b"ENCRYPTED PRIVATE KEY", b"-----\nredacted\n"]
        )
        (self.scan_root / "marker.txt").write_bytes(marker)

        result = self.scan()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"marker.txt\n")

    def test_scan_does_not_follow_file_or_directory_symlinks(self) -> None:
        outside_directory = self.root / "outside-directory"
        outside_directory.mkdir()
        (outside_directory / "secret.key").write_bytes(self.private_key.read_bytes())
        (self.scan_root / "key-link").symlink_to(self.private_key)
        (self.scan_root / "directory-link").symlink_to(
            outside_directory, target_is_directory=True
        )

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")


class DevelopmentKeyScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.process_tmp = self.root / "process-tmp"
        self.process_tmp.mkdir()
        self.output = self.process_tmp / "identity"
        self.environment = dict(os.environ)
        self.environment["TMPDIR"] = os.fspath(self.process_tmp)

    def create(self, output: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        command = [os.fspath(REPO / "scripts/gate01/create-development-key.sh")]
        if output is not None:
            command.extend(["--output-dir", os.fspath(output)])
        return subprocess.run(
            command,
            cwd=REPO,
            env=self.environment,
            capture_output=True,
        )

    def test_create_produces_complete_set_with_strict_modes_and_is_idempotent(self) -> None:
        first = self.create(self.output)

        self.assertEqual(first.returncode, 0, first.stderr.decode())
        names = [
            "module-signing.key",
            "module-signing.pem",
            "module-signing.x509",
            "module-key.json",
        ]
        public_names = names[1:]
        first_public_bytes = {
            name: (self.output / name).read_bytes() for name in public_names
        }
        private_stat = (self.output / "module-signing.key").stat()
        private_identity = (
            private_stat.st_dev,
            private_stat.st_ino,
            private_stat.st_size,
            private_stat.st_mtime_ns,
            private_stat.st_ctime_ns,
        )
        self.assertEqual(
            (self.output / "module-signing.key").stat().st_mode & 0o777, 0o600
        )
        self.assertEqual(
            (self.output / "module-signing.pem").stat().st_mode & 0o777, 0o644
        )
        self.assertEqual(
            (self.output / "module-signing.x509").stat().st_mode & 0o777, 0o644
        )
        self.assertEqual(
            (self.output / "module-key.json").stat().st_mode & 0o777, 0o600
        )
        self.assertIn(
            b"development key only; Gate 02 replaces this identity", first.stdout
        )

        second = self.create(self.output)

        self.assertEqual(second.returncode, 0, second.stderr.decode())
        self.assertEqual(
            first_public_bytes,
            {name: (self.output / name).read_bytes() for name in public_names},
        )
        second_private_stat = (self.output / "module-signing.key").stat()
        self.assertEqual(
            private_identity,
            (
                second_private_stat.st_dev,
                second_private_stat.st_ino,
                second_private_stat.st_size,
                second_private_stat.st_mtime_ns,
                second_private_stat.st_ctime_ns,
            ),
        )

    def test_create_rejects_partial_existing_set(self) -> None:
        self.output.mkdir()
        partial = self.output / "module-signing.pem"
        partial.write_text("incomplete\n", encoding="ascii")

        result = self.create(self.output)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(partial.read_text(encoding="ascii"), "incomplete\n")
        self.assertFalse((self.output / "module-signing.key").exists())

    def test_create_rejects_explicit_output_outside_process_tmp_and_build(self) -> None:
        outside = self.root / "outside"

        result = self.create(outside)

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
