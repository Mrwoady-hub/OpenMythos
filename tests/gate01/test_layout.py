from pathlib import Path
import unittest

from tools.gate01.layout import (
    GATE01_BUILD_ROOT,
    REPO_ROOT,
    relative_to_repo,
    require_gate01_output,
)


class LayoutTests(unittest.TestCase):
    def test_build_root_is_scoped_to_repository(self) -> None:
        self.assertEqual(GATE01_BUILD_ROOT, REPO_ROOT / "build" / "gate01")

    def test_relative_to_repo_rejects_escape(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside repository"):
            relative_to_repo(REPO_ROOT.parent / "other")

    def test_gate01_output_rejects_broad_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside Gate 01 build root"):
            require_gate01_output(REPO_ROOT)

    def test_gate01_output_accepts_descendant(self) -> None:
        candidate = GATE01_BUILD_ROOT / "builder-a" / "rpms"
        self.assertEqual(require_gate01_output(candidate), candidate.resolve())


if __name__ == "__main__":
    unittest.main()
