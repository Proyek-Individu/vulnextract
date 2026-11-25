"""
CLI entry point for statement-level feature extraction.

Run without arguments for the interactive menu, or pass CLI arguments for
scripted runs.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from src.config import (
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_ALLOW_SYNTHETIC_FALLBACK,
        DEFAULT_INPUT_FILE,
        DEFAULT_MAX_ROWS,
        DEFAULT_VERBOSE,
    )
    from src.feature_pipeline import FeatureExtractionPipeline
except ImportError:
    from config import (
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_ALLOW_SYNTHETIC_FALLBACK,
        DEFAULT_INPUT_FILE,
        DEFAULT_MAX_ROWS,
        DEFAULT_VERBOSE,
    )
    from feature_pipeline import FeatureExtractionPipeline


def setup_logging(verbose: bool = False) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def run_features(
    input_path,
    verbose: bool = False,
    max_rows: Optional[int] = DEFAULT_MAX_ROWS,
    allow_synthetic_fallback: bool = DEFAULT_ALLOW_SYNTHETIC_FALLBACK,
) -> None:
    setup_logging(verbose)
    pipeline = FeatureExtractionPipeline(
        max_rows=max_rows,
        allow_synthetic_fallback=allow_synthetic_fallback,
    )
    _, stats = pipeline.process_file(
        input_path=input_path,
        output_path=DEFAULT_FEATURES_OUTPUT_FILE,
        max_rows=max_rows,
    )

    print()
    print("Selesai!")
    print("Mode        : features")
    print(f"Input rows  : {stats.total_input_rows}")
    print(f"Output rows : {stats.total_output_rows}")
    print(f"  - dari vulnerable_code (diff)     : {stats.total_from_vulnerable_side}")
    print(f"  - dari fixed_code (safe class)     : {stats.total_from_fixed_side}")
    print(f"  - dari baris yang sejak awal sama  : {stats.total_from_unchanged_rows}")
    print(f"Label vulnerable (label=1) : {stats.total_positive_labels}")
    print(f"Skipped unsupported language : {stats.skipped_unsupported_language}")
    print(f"Skipped no-code               : {stats.skipped_no_code}")
    print(f"Skipped extraction failure    : {stats.skipped_extraction_failure}")
    print(f"Dilewati: input ganda: {stats.skipped_duplicate_input_rows}")
    print(f"Dilewati: statement sudah ada di arsip: {stats.skipped_duplicate_output_rows}")
    print(
        "Dilewati: diff commit tidak tersedia (fallback sintesis nonaktif): "
        f"{stats.skipped_advisory_no_commit_diff}"
    )
    for language, node_counts in sorted(stats.unknown_statement_nodes.items()):
        for node_type, count in sorted(node_counts.items()):
            print(f"Node tak dikenal dilewati: bahasa={language} {node_type}={count}")
    print(f"Output file : {DEFAULT_FEATURES_OUTPUT_FILE}")


def _ask(label: str, default: str) -> str:
    """Prompt for a value, using `default` when the response is empty."""
    answer = input(f"{label} [{default}]: ").strip()
    return answer if answer else default


def _ask_yes_no(label: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    answer = input(f"{label} [{hint}]: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes", "ya")


def _parse_max_rows_input(value: str) -> Optional[int]:
    value = str(value or "").strip()
    if not value or value == "0" or value.lower() in ("all", "none", "null"):
        return None
    rows = int(value)
    return rows if rows > 0 else None


def run_interactive_menu() -> None:
    """Run the feature-only interactive menu."""
    while True:
        print()
        print("=" * 48)
        print(" vulnextract - Statement Feature Extraction")
        print("=" * 48)
        print("  1. Ekstraksi features (statement-level)")
        print("  0. Keluar")
        choice = input("Pilih menu [1]: ").strip() or "1"

        if choice == "0":
            print("Sampai jumpa!")
            return
        if choice != "1":
            print("Pilihan tidak dikenali, coba lagi.")
            continue

        input_path = _ask("Input file", str(DEFAULT_INPUT_FILE))
        max_rows_text = _ask(
            "Batas baris maksimum (0 = semua)",
            str(DEFAULT_MAX_ROWS or 0),
        )
        verbose = _ask_yes_no("Aktifkan log debug?", default_yes=DEFAULT_VERBOSE)
        if not _ask_yes_no("Lanjutkan?", default_yes=True):
            print("Dibatalkan.")
            continue

        try:
            run_features(
                input_path,
                verbose,
                _parse_max_rows_input(max_rows_text),
            )
        except Exception as error:
            logging.error(f"Proses gagal: {error}")


def parse_args() -> argparse.Namespace:
    """Parse feature-extraction CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Extract labeled statement-level features from a vulnerability dataset."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=DEFAULT_INPUT_FILE,
        help=f"Path or URL to input dataset (default: {DEFAULT_INPUT_FILE})",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["features"],
        default="features",
        help="Statement-level feature extraction (the only supported mode).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help=f"Maximum input rows (0 = unlimited; default: {DEFAULT_MAX_ROWS})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=DEFAULT_VERBOSE,
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        default=DEFAULT_ALLOW_SYNTHETIC_FALLBACK,
        help="Allow local synthetic AST fallback for advisories without a commit diff.",
    )
    return parser.parse_args()


def main() -> None:
    if len(sys.argv) == 1:
        run_interactive_menu()
        return

    args = parse_args()
    max_rows = (
        DEFAULT_MAX_ROWS
        if args.max_rows is None
        else (args.max_rows if args.max_rows > 0 else None)
    )

    try:
        run_features(
            args.input,
            args.verbose,
            max_rows=max_rows,
            allow_synthetic_fallback=args.allow_synthetic,
        )
    except Exception as error:
        logging.error(f"Execution failed: {error}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
