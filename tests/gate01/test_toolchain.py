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
            "installed_rpms": ["gcc-15-1.fc44.x86_64"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolchain.lock.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            lock = load_toolchain_lock(path)
            with self.assertRaisesRegex(ValueError, "floating image reference"):
                validate_toolchain_lock(lock)


if __name__ == "__main__":
    unittest.main()
