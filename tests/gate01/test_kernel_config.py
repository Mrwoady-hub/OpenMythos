import json
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_lowercase_character_in_kernel_symbol_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lowercase.config"
            path.write_text("CONFIG_SCSI_DC395x=m\n", encoding="ascii")
            self.assertEqual(parse_config(path), {"CONFIG_SCSI_DC395x": "m"})

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

    def test_duplicate_config_symbol_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.config"
            path.write_text("CONFIG_DUPLICATE=y\n# CONFIG_DUPLICATE is not set\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "duplicate config symbol: CONFIG_DUPLICATE"):
                parse_config(path)

    def test_malformed_config_assignment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.config"
            path.write_text("CONFIG_LOWER-case=y\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "malformed config line 1"):
                parse_config(path)

    def test_audit_errors_are_sorted_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kernel_version": "6.18.48",
                        "kernel_release": "6.18.48-1.openmythos.fc44.x86_64",
                        "required": {
                            "CONFIG_ALPHA": "y",
                            "CONFIG_BETA": "m",
                        },
                    }
                ),
                encoding="utf-8",
            )
            requirements = load_requirements(path)
            self.assertEqual(
                audit_config({"CONFIG_ALPHA": "m"}, requirements),
                [
                    "CONFIG_ALPHA: expected y, got m",
                    "CONFIG_BETA: missing, expected m",
                ],
            )

    def test_requirements_reject_unknown_top_level_field(self) -> None:
        payload = self._minimal_requirements()
        payload["unexpected"] = True
        self._assert_requirements_error(payload, "unknown fields")

    def test_requirements_reject_non_string_value(self) -> None:
        payload = self._minimal_requirements()
        payload["required"] = {"CONFIG_ALPHA": True}
        self._assert_requirements_error(payload, "must be strings")

    def test_requirements_reject_symbol_without_config_prefix(self) -> None:
        payload = self._minimal_requirements()
        payload["required"] = {"ALPHA": "y"}
        self._assert_requirements_error(payload, "must start with CONFIG_")

    def test_requirements_reject_unsorted_symbols(self) -> None:
        payload = self._minimal_requirements()
        payload["required"] = {"CONFIG_BETA": "m", "CONFIG_ALPHA": "y"}
        self._assert_requirements_error(payload, "must be sorted")

    def test_requirements_reject_duplicate_symbols(self) -> None:
        raw = (
            '{"schema_version":1,"kernel_version":"6.18.48",'
            '"kernel_release":"6.18.48-1.openmythos.fc44.x86_64",'
            '"required":{"CONFIG_ALPHA":"y","CONFIG_ALPHA":"m"}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.json"
            path.write_text(raw, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key: CONFIG_ALPHA"):
                load_requirements(path)

    def test_checksum_cli_writes_exact_atomic_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sample.config"
            output = Path(directory) / "sample.config.sha256"
            config.write_bytes(b"CONFIG_ALPHA=y\n")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.gate01.kernel_config",
                    "checksum",
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ],
                cwd=REPO,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_text(encoding="ascii"),
                "3b92cd4fae933696dbec362bc1348c6e28c42d9a1a593add03bb69ce02f97f1c  sample.config\n",
            )
            self.assertFalse(output.with_name(output.name + ".tmp").exists())

    @staticmethod
    def _minimal_requirements() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kernel_version": "6.18.48",
            "kernel_release": "6.18.48-1.openmythos.fc44.x86_64",
            "required": {"CONFIG_ALPHA": "y"},
        }

    def _assert_requirements_error(
        self, payload: dict[str, object], message: str
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, message):
                load_requirements(path)


if __name__ == "__main__":
    unittest.main()
