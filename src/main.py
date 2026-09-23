"""
CLI Entrypoint for Method-Level CVE Pair Extraction.
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
    from src.config import DEFAULT_INPUT_FILE, DEFAULT_OUTPUT_FILE
    from src.pipeline import CveMethodPipeline
except ImportError:
    from config import DEFAULT_INPUT_FILE, DEFAULT_OUTPUT_FILE
    from pipeline import CveMethodPipeline


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
        description="Extract method-level vulnerable and fixed code pairs from CVE dataset."
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
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path to output CSV file (default: {DEFAULT_OUTPUT_FILE})"
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

    pipeline = CveMethodPipeline()

    try:
        _, stats = pipeline.process_file(
            input_path=args.input,
            output_path=args.output
        )

        print()
        print("Finished!")
        print(f"Input rows  : {stats.total_input_rows}")
        print(f"Output rows : {stats.total_output_rows}")
        print(f"Output file : {args.output}")

    except Exception as e:
        logging.error(f"Execution failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()