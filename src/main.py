"""
CLI Entrypoint for Statement-Level and Method-Level CVE Pair Extraction.

Two ways to run:
- No arguments (`python src/main.py`): interactive menu — pick a mode,
  confirm/override the defaults loaded from global.yaml, done. This is the
  recommended way to run the tool day-to-day.
- With arguments (`python src/main.py -m features -i ... -o ...`): scriptable
  CLI flags, for automation (CI, batch runs, the other student's own scripts).
"""

import argparse
import logging
import sys
from pathlib import Path

# Ensure modules can be resolved regardless of execution context
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from src.config import (
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_GRANULARITY,
        DEFAULT_INPUT_FILE,
        DEFAULT_OUTPUT_FILE,
        DEFAULT_STRATEGY,
        DEFAULT_VERBOSE,
    )
    from src.feature_pipeline import FeatureExtractionPipeline
    from src.pipeline import CveMethodPipeline
    from src.strategies import AlignedPairingStrategy, StrictZipPairingStrategy
except ImportError:
    from config import (
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_GRANULARITY,
        DEFAULT_INPUT_FILE,
        DEFAULT_OUTPUT_FILE,
        DEFAULT_STRATEGY,
        DEFAULT_VERBOSE,
    )
    from feature_pipeline import FeatureExtractionPipeline
    from pipeline import CveMethodPipeline
    from strategies import AlignedPairingStrategy, StrictZipPairingStrategy


def setup_logging(verbose: bool = False) -> None:
    """Configures structured logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s"
    )


# ---------------------------------------------------------------------------
# Pipeline execution (shared by both the CLI-flag flow and the interactive menu)
# ---------------------------------------------------------------------------

def run_pairs(input_path, output_path, granularity: str, strategy: str, verbose: bool = False) -> None:
    setup_logging(verbose)
    strategy_obj = AlignedPairingStrategy() if strategy == "aligned" else StrictZipPairingStrategy()
    pipeline = CveMethodPipeline(pairing_strategy=strategy_obj, granularity=granularity)

    _, stats = pipeline.process_file(input_path=input_path, output_path=output_path)

    print()
    print("Selesai!")
    print(f"Mode        : pairs")
    print(f"Granularity : {granularity}")
    print(f"Strategy    : {strategy}")
    print(f"Input rows  : {stats.total_input_rows}")
    print(f"Output rows : {stats.total_output_rows}")
    print(f"Skipped no-code  : {stats.skipped_no_code}")
    print(f"Skipped mismatch : {stats.skipped_mismatch}")
    print(f"Output file : {output_path}")


def run_features(input_path, output_path, verbose: bool = False) -> None:
    setup_logging(verbose)
    pipeline = FeatureExtractionPipeline()

    _, stats = pipeline.process_file(input_path=input_path, output_path=output_path)

    print()
    print("Selesai!")
    print(f"Mode        : features")
    print(f"Input rows  : {stats.total_input_rows}")
    print(f"Output rows : {stats.total_output_rows}")
    print(f"  - dari vulnerable_code (diff)     : {stats.total_from_vulnerable_side}")
    print(f"  - dari fixed_code (safe class)     : {stats.total_from_fixed_side}")
    print(f"  - dari baris yang sejak awal sama  : {stats.total_from_unchanged_rows}")
    print(f"Label vulnerable (label=1) : {stats.total_positive_labels}")
    print(f"Skipped unsupported language : {stats.skipped_unsupported_language}")
    print(f"Skipped no-code               : {stats.skipped_no_code}")
    print(f"Skipped extraction failure    : {stats.skipped_extraction_failure}")
    print(f"Output file : {output_path}")


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def _ask(label: str, default: str) -> str:
    """Prompts for a value; pressing Enter keeps `default`."""
    answer = input(f"{label} [{default}]: ").strip()
    return answer if answer else default


def _ask_yes_no(label: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    answer = input(f"{label} [{hint}]: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes", "ya")


def _menu_run_pairs() -> None:
    print()
    print("--- Ekstraksi pairs (vulnerable/fixed text pairs) ---")
    input_path = _ask("Input file", str(DEFAULT_INPUT_FILE))
    output_path = _ask("Output file", str(DEFAULT_OUTPUT_FILE))
    granularity = _ask("Granularity (statement/method)", DEFAULT_GRANULARITY)
    strategy = _ask("Strategy (aligned/strict)", DEFAULT_STRATEGY)
    verbose = _ask_yes_no("Aktifkan log debug?", default_yes=DEFAULT_VERBOSE)

    if not _ask_yes_no("Lanjutkan?", default_yes=True):
        print("Dibatalkan.")
        return

    run_pairs(input_path, Path(output_path), granularity, strategy, verbose)


def _menu_run_features() -> None:
    print()
    print("--- Ekstraksi features (statement-level, berlabel, untuk ML) ---")
    input_path = _ask("Input file", str(DEFAULT_INPUT_FILE))
    output_path = _ask("Output file", str(DEFAULT_FEATURES_OUTPUT_FILE))
    verbose = _ask_yes_no("Aktifkan log debug?", default_yes=DEFAULT_VERBOSE)

    if not _ask_yes_no("Lanjutkan?", default_yes=True):
        print("Dibatalkan.")
        return

    run_features(input_path, Path(output_path), verbose)


def run_interactive_menu() -> None:
    """Shown when `python src/main.py` is run with no arguments at all."""
    while True:
        print()
        print("=" * 48)
        print(" vulnextract - CVE Extraction Pipeline")
        print("=" * 48)
        print("  1. Ekstraksi pairs (vulnerable/fixed text pairs)")
        print("  2. Ekstraksi features (statement-level, untuk ML)")
        print("  3. Deteksi vulnerability (belum tersedia)")
        print("  0. Keluar")
        choice = input("Pilih menu [1]: ").strip() or "1"

        try:
            if choice == "1":
                _menu_run_pairs()
            elif choice == "2":
                _menu_run_features()
            elif choice == "3":
                print()
                print("Fitur deteksi vulnerability belum tersedia - akan dibangun di atas")
                print("dataset hasil mode 'features' pada tahap pengembangan selanjutnya.")
            elif choice == "0":
                print("Sampai jumpa!")
                return
            else:
                print("Pilihan tidak dikenali, coba lagi.")
                continue
        except Exception as e:
            logging.error(f"Proses gagal: {e}")

        if not _ask_yes_no("\nKembali ke menu utama?", default_yes=True):
            print("Sampai jumpa!")
            return


# ---------------------------------------------------------------------------
# Scriptable CLI flags
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract statement-level or method-level vulnerable and fixed code pairs from CVE dataset."
    )
    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=DEFAULT_INPUT_FILE,
        help=f"Path to input CSV file (default dari global.yaml: {DEFAULT_INPUT_FILE})"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help=(
            "Path to output CSV file "
            f"(default: {DEFAULT_OUTPUT_FILE} for --mode pairs, "
            f"{DEFAULT_FEATURES_OUTPUT_FILE} for --mode features)"
        )
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["pairs", "features"],
        default="pairs",
        help=(
            "'pairs': existing method/statement vulnerable-vs-fixed text pair extraction (default). "
            "'features': hierarchical, labeled, per-statement feature table per context.md's schema "
            "(Go/Python/JavaScript/TypeScript/PHP only)."
        )
    )
    parser.add_argument(
        "-g", "--granularity",
        choices=["statement", "method"],
        default=DEFAULT_GRANULARITY,
        help=f"Extraction granularity for --mode pairs: 'statement' or 'method' (default: {DEFAULT_GRANULARITY})"
    )
    parser.add_argument(
        "-s", "--strategy",
        choices=["aligned", "strict"],
        default=DEFAULT_STRATEGY,
        help=f"Pairing strategy: 'aligned' or 'strict' (default: {DEFAULT_STRATEGY})"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=DEFAULT_VERBOSE,
        help="Enable verbose debug logging."
    )
    return parser.parse_args()


def main() -> None:
    # No CLI flags at all -> interactive menu (the simple, recommended path).
    if len(sys.argv) == 1:
        run_interactive_menu()
        return

    args = parse_args()
    output_path = args.output
    if output_path is None:
        output_path = DEFAULT_OUTPUT_FILE if args.mode == "pairs" else DEFAULT_FEATURES_OUTPUT_FILE

    try:
        if args.mode == "features":
            run_features(args.input, output_path, args.verbose)
        else:
            run_pairs(args.input, output_path, args.granularity, args.strategy, args.verbose)
    except Exception as e:
        logging.error(f"Execution failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
