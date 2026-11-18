"""Tests that the application entry point exposes feature extraction only."""

import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.main import run_interactive_menu

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_SCRIPT = PROJECT_ROOT / "src" / "main.py"


class TestMainCli(unittest.TestCase):
    def test_help_lists_features_as_the_only_mode(self):
        result = subprocess.run(
            [sys.executable, str(MAIN_SCRIPT), "--help"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("-m {features}", result.stdout)
        self.assertNotIn("classify", result.stdout)

    def test_pairs_and_classify_modes_are_rejected(self):
        for mode in ("pairs", "classify"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, str(MAIN_SCRIPT), "--mode", mode],
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)

    def test_interactive_menu_only_shows_features(self):
        output = StringIO()
        with patch("builtins.input", return_value="0"), redirect_stdout(output):
            run_interactive_menu()

        self.assertIn("Ekstraksi features", output.getvalue())
        self.assertNotIn("Ekstraksi pairs", output.getvalue())
        self.assertNotIn("Klasifikasi", output.getvalue())


if __name__ == "__main__":
    unittest.main()
