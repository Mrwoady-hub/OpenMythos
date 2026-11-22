import io
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tools.gate01 import module_key


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

    def test_describe_descriptor_survives_certificate_path_replacement(self) -> None:
        descriptor = os.open(
            self.certificate, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            expected = module_key.describe_descriptor(descriptor)
            replacement = self.root / "replacement.pem"
            replacement.write_text("not a certificate\n", encoding="ascii")
            replacement.replace(self.certificate)
            self.assertEqual(module_key.describe_descriptor(descriptor), expected)
            certificate = os.pread(descriptor, os.fstat(descriptor).st_size, 0)
            self.assertEqual(
                expected["certificate_sha256"], hashlib.sha256(certificate).hexdigest()
            )
        finally:
            os.close(descriptor)


class ModuleKeyScanTests(unittest.TestCase):
    def test_scanner_checks_decoded_rpm_metadata_not_only_json_encoded_bytes(self) -> None:
        marker = "-----BEGIN PRIVATE KEY-----"
        escaped = "".join("\\u%04x" % ord(character) for character in marker)
        (self.scan_root / "rpm-artifacts.json").write_text('{"binary_rpms":[{"security_metadata":{"candidate":"' + escaped + '"}}]}\n', encoding="ascii")
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"private-key leakage detected\n")
        self.assertEqual(result.stderr, b"")

    def test_scanner_checks_names_symlink_targets_and_xattrs_without_echoing_them(self) -> None:
        marker = b"-----BEGIN PRIVATE KEY-----"
        for role in ("name", "symlink", "file-xattr", "directory-xattr"):
            with self.subTest(role=role), tempfile.TemporaryDirectory(dir=self.root) as name:
                target = Path(name)
                if role == "name":
                    (target / marker.decode()).write_bytes(b"public")
                elif role == "symlink":
                    (target / "link").symlink_to(marker.decode())
                elif role == "file-xattr":
                    payload = target / "public"
                    payload.write_bytes(b"public")
                    os.setxattr(payload, "user.secret", marker)
                else:
                    os.setxattr(target, "user.secret", marker)
                key_fd = os.open(self.private_key, os.O_RDONLY | os.O_CLOEXEC)
                root_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                output = io.StringIO()
                try:
                    with redirect_stdout(output):
                        result = module_key.scan_descriptors(key_fd, root_fd)
                    self.assertEqual(result, 1)
                    self.assertEqual(output.getvalue(), "private-key leakage detected\n")
                finally:
                    os.close(root_fd)
                    os.close(key_fd)

    def test_scanner_rejects_special_nodes_without_blocking(self) -> None:
        for role in ("fifo", "socket"):
            with self.subTest(role=role), tempfile.TemporaryDirectory(dir=self.root) as name:
                root = Path(name)
                if role == "fifo":
                    os.mkfifo(root / "special")
                else:
                    os.mknod(root / "special", stat.S_IFSOCK | 0o600)
                with self.assertRaisesRegex(RuntimeError, "unsupported node"):
                    module_key.scan(self.private_key, root)

    def test_scanner_terminal_sweep_rejects_prior_child_mutation_in_each_pass(self) -> None:
        first = self.scan_root / "a"
        second = self.scan_root / "b"
        for mutate_at in (2, 4):
            with self.subTest(mutate_at=mutate_at):
                first.write_bytes(b"public")
                second.write_bytes(b"public")
                original = module_key._descriptor_contains_secret
                calls = 0
                def scan_then_mutate(descriptor: int, patterns: tuple[bytes, bytes]) -> bool:
                    nonlocal calls
                    result = original(descriptor, patterns)
                    calls += 1
                    if calls == mutate_at:
                        first.write_bytes(b"secret")
                        first.write_bytes(b"public")
                    return result
                with mock.patch.object(module_key, "_descriptor_contains_secret", side_effect=scan_then_mutate):
                    with self.assertRaisesRegex(RuntimeError, "changed during traversal"):
                        module_key.scan(self.private_key, self.scan_root)

    def test_scanner_content_leakage_uses_only_a_fixed_public_diagnostic(self) -> None:
        malicious_name = "attacker-controlled-secret-fragment"
        (self.scan_root / malicious_name).write_bytes(b"-----BEGIN PRIVATE KEY-----")
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"private-key leakage detected\n")
        self.assertEqual(result.stderr, b"")

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
        self.private_der = subprocess.run(
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

    def test_scan_reports_redacted_failure_for_complete_pem_or_der_secret(self) -> None:
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
            ["private-key leakage detected"],
        )
        self.assertNotIn(self.private_key.read_bytes(), result.stdout)

    def test_scan_rejects_private_key_marker_without_complete_secret(self) -> None:
        marker = b"".join(
            [b"-----BEGIN ", b"ENCRYPTED PRIVATE KEY", b"-----\nredacted\n"]
        )
        (self.scan_root / "marker.txt").write_bytes(marker)

        result = self.scan()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"private-key leakage detected\n")

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

    def test_scan_fails_closed_when_opened_directory_is_replaced(self) -> None:
        ancestor = self.scan_root / "ancestor"
        ancestor.mkdir()
        (ancestor / "payload.bin").write_bytes(self.private_key.read_bytes())
        clean = self.root / "clean"
        clean.mkdir()
        (clean / "payload.bin").write_bytes(b"public data\n")
        displaced = self.root / "displaced"
        real_open = os.open
        attacked = False

        def replace_ancestor_before_file_open(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal attacked
            if not attacked and Path(os.fspath(path)).name == "payload.bin":
                ancestor.rename(displaced)
                ancestor.symlink_to(clean, target_is_directory=True)
                attacked = True
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(module_key, "_openssl", return_value=self.private_der):
            with mock.patch.object(
                module_key.os, "open", side_effect=replace_ancestor_before_file_open
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "directory identity changed"
                ):
                    module_key.scan(self.private_key, self.scan_root)
        self.assertTrue(attacked)

    def test_scan_detects_secrets_and_markers_across_chunk_boundaries(self) -> None:
        chunk_size = 64
        padding = b"x" * (chunk_size - 3)
        marker = b"".join(
            [b"-----BEGIN ", b"ENCRYPTED PRIVATE KEY", b"-----"]
        )
        (self.scan_root / "der.bin").write_bytes(padding + self.private_der)
        (self.scan_root / "marker.bin").write_bytes(padding + marker)
        (self.scan_root / "pem.bin").write_bytes(
            padding + self.private_key.read_bytes()
        )
        real_read = os.read
        read_sizes: list[int] = []

        def record_bounded_read(descriptor: int, size: int) -> bytes:
            read_sizes.append(size)
            return real_read(descriptor, size)

        scan_output = io.StringIO()
        with mock.patch.object(module_key, "SCAN_CHUNK_SIZE", chunk_size, create=True):
            with mock.patch.object(
                module_key, "_openssl", return_value=self.private_der
            ):
                with mock.patch.object(
                    module_key.os, "read", side_effect=record_bounded_read
                ):
                    with redirect_stdout(scan_output):
                        result = module_key.scan(self.private_key, self.scan_root)

        self.assertEqual(result, 1)
        self.assertEqual(
            scan_output.getvalue().splitlines(),
            ["private-key leakage detected"],
        )
        self.assertTrue(read_sizes, "scanner bypassed bounded os.read calls")
        self.assertLessEqual(max(read_sizes), chunk_size)

    def test_scan_reads_large_sparse_file_in_bounded_chunks(self) -> None:
        chunk_size = 64 * 1024
        sparse = self.scan_root / "large-sparse.bin"
        with sparse.open("wb") as stream:
            stream.seek(chunk_size * 16)
            stream.write(b"public data\n")
        real_read = os.read
        read_sizes: list[int] = []

        def record_bounded_read(descriptor: int, size: int) -> bytes:
            read_sizes.append(size)
            return real_read(descriptor, size)

        with mock.patch.object(module_key, "SCAN_CHUNK_SIZE", chunk_size, create=True):
            with mock.patch.object(
                module_key, "_openssl", return_value=self.private_der
            ):
                with mock.patch.object(
                    module_key.os, "read", side_effect=record_bounded_read
                ):
                    result = module_key.scan(self.private_key, self.scan_root)

        self.assertEqual(result, 0)
        self.assertGreater(len(read_sizes), 16)
        self.assertLessEqual(max(read_sizes), chunk_size)

    def test_descriptor_scan_uses_exact_held_key_and_root_inodes(self) -> None:
        (self.scan_root / "public.txt").write_bytes(b"public\n")
        key_fd = os.open(
            self.private_key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        root_fd = os.open(
            self.scan_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        try:
            original_key = self.private_key.read_bytes()
            replacement = self.root / "replacement.key"
            replacement.write_bytes(b"not the signing key")
            replacement.replace(self.private_key)
            (self.scan_root / "leak.bin").write_bytes(original_key)
            output = io.StringIO()
            with redirect_stdout(output):
                result = module_key.scan_descriptors(key_fd, root_fd)
            self.assertEqual(result, 1)
            self.assertEqual(output.getvalue(), "private-key leakage detected\n")
        finally:
            os.close(root_fd)
            os.close(key_fd)

    def test_descriptor_scan_rejects_tree_change_after_secret_scan(self) -> None:
        payload = self.scan_root / "payload"
        payload.write_bytes(b"public\n")
        key_fd = os.open(
            self.private_key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        root_fd = os.open(
            self.scan_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        original = module_key._descriptor_contains_secret
        attacked = False

        def inject_after_scan(
            descriptor: int, exact_patterns: tuple[bytes, bytes]
        ) -> bool:
            nonlocal attacked
            value = original(descriptor, exact_patterns)
            if not attacked:
                payload.write_bytes(self.private_key.read_bytes())
                attacked = True
            return value

        try:
            with mock.patch.object(
                module_key,
                "_descriptor_contains_secret",
                side_effect=inject_after_scan,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during traversal"):
                    module_key.scan_descriptors(key_fd, root_fd)
        finally:
            os.close(root_fd)
            os.close(key_fd)

    def test_held_artifact_descriptors_are_scanned_without_path_reopen(self) -> None:
        clean = os.memfd_create("clean", os.MFD_CLOEXEC)
        leaked = os.memfd_create("leaked", os.MFD_CLOEXEC)
        os.write(clean, b"ordinary RPM bytes")
        os.write(leaked, b"prefix" + self.private_key.read_bytes() + b"suffix")
        key_descriptor = os.open(
            self.private_key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            self.assertEqual(
                module_key.scan_file_descriptors(
                    key_descriptor, {"clean": clean, "leaked": leaked}
                ),
                ["leaked"],
            )
        finally:
            os.close(key_descriptor)
            os.close(clean)
            os.close(leaked)

    def test_held_scan_terminal_sweep_rejects_prior_file_mutation_on_second_pass(self) -> None:
        descriptors = {label: os.memfd_create(label, os.MFD_CLOEXEC) for label in ("a", "b")}
        key = os.open(self.private_key, os.O_RDONLY | os.O_CLOEXEC)
        for descriptor in descriptors.values():
            os.write(descriptor, b"public")
        original = module_key._descriptor_contains_secret
        calls = 0
        def scan_then_mutate(descriptor: int, patterns: tuple[bytes, bytes]) -> bool:
            nonlocal calls
            result = original(descriptor, patterns)
            calls += 1
            if calls == 4:
                os.pwrite(descriptors["a"], b"secret", 0)
                os.pwrite(descriptors["a"], b"public", 0)
            return result
        try:
            with mock.patch.object(module_key, "_descriptor_contains_secret", side_effect=scan_then_mutate):
                with self.assertRaisesRegex(RuntimeError, "changed"):
                    module_key.scan_file_descriptors(key, descriptors)
        finally:
            os.close(key)
            for descriptor in descriptors.values():
                os.close(descriptor)


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
