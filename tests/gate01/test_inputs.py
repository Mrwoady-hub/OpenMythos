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
        self.assertEqual(raw["fedora_bootc"]["version"], "44.20260905.0")
        self.assertEqual(
            raw["fedora_bootc"]["index_digest"],
            "sha256:778cafb9040cd2fb91d3ae7bf68bff6e775714cdd6ee47cbd9970646c40fd2cf",
        )
        self.assertEqual(
            raw["fedora_bootc"]["manifest_digest"],
            "sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756",
        )

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
