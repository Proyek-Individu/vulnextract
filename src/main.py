"""
CLI Entrypoint for Statement-Level and Method-Level CVE Pair Extraction.
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
    from src.config import DEFAULT_FEATURES_OUTPUT_FILE, DEFAULT_INPUT_FILE, DEFAULT_OUTPUT_FILE
    from src.feature_pipeline import FeatureExtractionPipeline
    from src.pipeline import CveMethodPipeline
    from src.strategies import AlignedPairingStrategy, StrictZipPairingStrategy
except ImportError:
    from config import DEFAULT_FEATURES_OUTPUT_FILE, DEFAULT_INPUT_FILE, DEFAULT_OUTPUT_FILE
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


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract statement-level or method-level vulnerable and fixed code pairs from CVE dataset."
    )
    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=DEFAULT_INPUT_FILE,
        help=f"Path to input CSV file (default: {DEFAULT_INPUT_FILE})"
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
        default="statement",
        help="Extraction granularity for --mode pairs: 'statement' or 'method' (default: statement)"
    )
    parser.add_argument(
        "-s", "--strategy",
        choices=["aligned", "strict"],
        default="aligned",
        help="Pairing strategy: 'aligned' (sequence diff alignment) or 'strict' (exact 1:1 count) (default: aligned)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging."
    )
    return parser.parse_args()


def main() -> None:
    """CLI execution workflow."""
    args = parse_args()
    setup_logging(args.verbose)

    output_path = args.output
    if output_path is None:
        output_path = DEFAULT_OUTPUT_FILE if args.mode == "pairs" else DEFAULT_FEATURES_OUTPUT_FILE

    try:
        if args.mode == "features":
            pipeline = FeatureExtractionPipeline()
            _, stats = pipeline.process_file(input_path=args.input, output_path=output_path)

            print()
            print("Finished!")
            print(f"Mode        : features")
            print(f"Input rows  : {stats.total_input_rows}")
            print(f"Output rows : {stats.total_output_rows}")
            print(f"Positive labels (vulnerable) : {stats.total_positive_labels}")
            print(f"Skipped unsupported language : {stats.skipped_unsupported_language}")
            print(f"Skipped no-code               : {stats.skipped_no_code}")
            print(f"Skipped duplicate input       : {stats.skipped_duplicate_input}")
            print(f"Skipped extraction failure    : {stats.skipped_extraction_failure}")
            print(f"Output file : {output_path}")
            return

        strategy = (
            AlignedPairingStrategy()
            if args.strategy == "aligned"
            else StrictZipPairingStrategy()
        )

        pipeline = CveMethodPipeline(
            pairing_strategy=strategy,
            granularity=args.granularity
        )

        _, stats = pipeline.process_file(
            input_path=args.input,
            output_path=output_path
        )

        print()
        print("Finished!")
        print(f"Mode        : pairs")
        print(f"Granularity : {args.granularity}")
        print(f"Strategy    : {args.strategy}")
        print(f"Input rows  : {stats.total_input_rows}")
        print(f"Output rows : {stats.total_output_rows}")
        print(f"Skipped no-code  : {stats.skipped_no_code}")
        print(f"Skipped mismatch : {stats.skipped_mismatch}")
        print(f"Output file : {output_path}")

    except Exception as e:
        logging.error(f"Execution failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()