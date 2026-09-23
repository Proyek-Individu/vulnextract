"""
Configuration and Path Management for CVE Method Pair Processing.
"""

from pathlib import Path

# Resolve base directories dynamically so code can run from any working directory
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent

DEFAULT_INPUT_FILE = PROJECT_ROOT / "data" / "input" / "cve_fix_pairs.csv"
DEFAULT_OUTPUT_FILE = PROJECT_ROOT / "data" / "output" / "output_csv_fix_pairs.csv"
