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
        DEFAULT_CLASSIFICATION,
        DEFAULT_CLASSIFICATION_OUTPUT_DIR,
        DEFAULT_CLASSIFICATION_RAW_INPUT,
        DEFAULT_CLASSIFICATION_SPLIT_INPUT,
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_GRANULARITY,
        DEFAULT_INPUT_FILE,
        DEFAULT_OUTPUT_FILE,
        DEFAULT_STRATEGY,
        DEFAULT_VERBOSE,
    )
    from src.classification import ClassificationPipeline
    from src.feature_pipeline import FeatureExtractionPipeline
    from src.pipeline import CveMethodPipeline
    from src.strategies import AlignedPairingStrategy, StrictZipPairingStrategy
except ImportError:
    from config import (
        DEFAULT_CLASSIFICATION,
        DEFAULT_CLASSIFICATION_OUTPUT_DIR,
        DEFAULT_CLASSIFICATION_RAW_INPUT,
        DEFAULT_CLASSIFICATION_SPLIT_INPUT,
        DEFAULT_FEATURES_OUTPUT_FILE,
        DEFAULT_GRANULARITY,
        DEFAULT_INPUT_FILE,
        DEFAULT_OUTPUT_FILE,
        DEFAULT_STRATEGY,
        DEFAULT_VERBOSE,
    )
    from classification import ClassificationPipeline
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


def run_classify(overrides: dict, verbose: bool = False) -> None:
    """`overrides` is merged over global.yaml's `classification:` block."""
    setup_logging(verbose)
    result = ClassificationPipeline(overrides).run()

    import pandas as pd
    with pd.option_context("display.width", 200, "display.max_columns", 20, "display.float_format", "{:.3f}".format):
        print()
        print("Selesai!")
        print("Perbandingan (rata-rata antar fold):")
        key_metrics = ["f1", "mcc", "roc_auc", "pr_auc", "balanced_accuracy"]
        table = result.comparison[result.comparison["metric"].isin(key_metrics)]
        table = table[[c for c in table.columns if not c.endswith("(std)")]]
        print(table.to_string(index=False))
    print()
    print(f"Folder hasil : {result.run_dir}")
    for path in result.files:
        print(f"  - {path.relative_to(result.run_dir)}")


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


def _model_names(specs) -> str:
    names = []
    for spec in specs or []:
        names.append(spec if isinstance(spec, str) else (spec.get("label") or spec.get("name") or spec.get("class")))
    return ",".join(str(n) for n in names) or "random_forest"


def models_override(names_csv: str) -> list:
    """Model names typed in the menu / --models -> `classification.models`
    entries. A name that matches an entry in global.yaml (by label or name)
    keeps that entry's params; any other name uses the registry defaults."""
    configured = DEFAULT_CLASSIFICATION.get("models") or []
    by_key = {}
    for spec in configured:
        spec = {"name": spec} if isinstance(spec, str) else spec
        for key in (spec.get("label"), spec.get("name")):
            if key:
                by_key.setdefault(str(key).lower(), spec)
    picked = []
    for name in (n.strip() for n in names_csv.split(",")):
        if name:
            picked.append(by_key.get(name.lower(), {"name": name}))
    return picked


def parse_test_size(value) -> float:
    """Accepts a fraction (0.2) or a percentage (20 / 20%)."""
    number = float(str(value).strip().rstrip("%"))
    return number / 100.0 if number >= 1 else number


def _menu_run_classify() -> None:
    cfg = DEFAULT_CLASSIFICATION
    print()
    print("--- Klasifikasi vulnerability (ML + XAI): data mentah vs data split ---")
    raw_input = _ask("Data mentah (CSV input)", str(DEFAULT_CLASSIFICATION_RAW_INPUT))
    split_input = _ask("Data split (hasil menu 2; dibuat otomatis jika belum ada)", str(DEFAULT_CLASSIFICATION_SPLIT_INPUT))
    output_dir = _ask("Folder output", str(DEFAULT_CLASSIFICATION_OUTPUT_DIR))
    models = _ask("Model (pisahkan koma)", _model_names(cfg.get("models")))
    test_size = _ask("Porsi data test (0.2 atau 20%)", str(cfg["split"]["test_size"]))
    cv_folds = _ask("Jumlah fold k-fold (0 = holdout train/test sekali)", str(cfg["split"]["cv_folds"]))
    formats = _ask("Format output (xlsx,csv)", ",".join(cfg.get("output_formats") or ["xlsx"]))
    xai = _ask_yes_no("Jalankan XAI (SHAP + permutation importance)?", default_yes=bool(cfg["xai"]["enabled"]))
    verbose = _ask_yes_no("Aktifkan log debug?", default_yes=DEFAULT_VERBOSE)

    if not _ask_yes_no("Lanjutkan?", default_yes=True):
        print("Dibatalkan.")
        return

    overrides = {
        "raw_input": raw_input,
        "split_input": split_input,
        "output_dir": output_dir,
        "models": models_override(models),
        "split": {"test_size": parse_test_size(test_size), "cv_folds": int(cv_folds or 0)},
        "output_formats": [f.strip().lower() for f in formats.split(",") if f.strip()],
        "xai": {"enabled": xai},
    }
    run_classify(overrides, verbose)


def run_interactive_menu() -> None:
    """Shown when `python src/main.py` is run with no arguments at all."""
    while True:
        print()
        print("=" * 48)
        print(" vulnextract - CVE Extraction Pipeline")
        print("=" * 48)
        print("  1. Ekstraksi pairs (vulnerable/fixed text pairs)")
        print("  2. Ekstraksi features (statement-level, untuk ML)")
        print("  3. Klasifikasi vulnerability (ML + XAI, mentah vs split)")
        print("  0. Keluar")
        choice = input("Pilih menu [1]: ").strip() or "1"

        try:
            if choice == "1":
                _menu_run_pairs()
            elif choice == "2":
                _menu_run_features()
            elif choice == "3":
                _menu_run_classify()
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
        default=None,
        help=(
            f"Path to input CSV file (default dari global.yaml: {DEFAULT_INPUT_FILE}; "
            f"untuk --mode classify: {DEFAULT_CLASSIFICATION_RAW_INPUT})"
        )
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help=(
            "Path to output CSV file "
            f"(default: {DEFAULT_OUTPUT_FILE} for --mode pairs, "
            f"{DEFAULT_FEATURES_OUTPUT_FILE} for --mode features); "
            f"for --mode classify this is the output FOLDER (default: {DEFAULT_CLASSIFICATION_OUTPUT_DIR})"
        )
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["pairs", "features", "classify"],
        default="pairs",
        help=(
            "'pairs': existing method/statement vulnerable-vs-fixed text pair extraction (default). "
            "'features': hierarchical, labeled, per-statement feature table per context.md's schema "
            "(Go/Python/JavaScript/TypeScript/PHP only). "
            "'classify': train the models in global.yaml on raw vs split data, with XAI + comparison report."
        )
    )
    parser.add_argument(
        "--split-input",
        type=Path,
        default=None,
        help=f"[classify] Data split / hasil mode features (default: {DEFAULT_CLASSIFICATION_SPLIT_INPUT})"
    )
    parser.add_argument(
        "--models",
        default=None,
        help="[classify] Daftar model dipisah koma, mis. random_forest,logistic_regression (default: global.yaml)"
    )
    parser.add_argument(
        "--test-size",
        default=None,
        help="[classify] Porsi data test, 0.2 atau 20%% (default: global.yaml)"
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=None,
        help="[classify] Jumlah fold k-fold; 0 = holdout sekali (default: global.yaml)"
    )
    parser.add_argument(
        "--formats",
        default=None,
        help="[classify] Format output dipisah koma: xlsx,csv (default: global.yaml)"
    )
    parser.add_argument(
        "--no-xai",
        action="store_true",
        help="[classify] Lewati XAI (SHAP/permutation importance)"
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
    input_path = args.input if args.input is not None else DEFAULT_INPUT_FILE
    output_path = args.output
    if output_path is None:
        output_path = DEFAULT_OUTPUT_FILE if args.mode == "pairs" else DEFAULT_FEATURES_OUTPUT_FILE

    try:
        if args.mode == "classify":
            overrides = {}
            if args.input is not None:
                overrides["raw_input"] = str(args.input)
            if args.output is not None:
                overrides["output_dir"] = str(args.output)
            if args.split_input is not None:
                overrides["split_input"] = str(args.split_input)
            if args.models:
                overrides["models"] = models_override(args.models)
            split = {}
            if args.test_size is not None:
                split["test_size"] = parse_test_size(args.test_size)
            if args.cv_folds is not None:
                split["cv_folds"] = args.cv_folds
            if split:
                overrides["split"] = split
            if args.formats:
                overrides["output_formats"] = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
            if args.no_xai:
                overrides["xai"] = {"enabled": False}
            run_classify(overrides, args.verbose)
        elif args.mode == "features":
            run_features(input_path, output_path, args.verbose)
        else:
            run_pairs(input_path, output_path, args.granularity, args.strategy, args.verbose)
    except Exception as e:
        logging.error(f"Execution failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
