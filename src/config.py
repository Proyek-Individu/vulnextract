"""
Configuration and Path Management for CVE Method Pair Processing.

Reads non-secret, user-editable settings from global.yaml at the project
root (input/output file locations, default granularity/strategy, ...) so
running the pipeline doesn't require typing CLI flags every time — and
loads secrets (if any are configured) from .env via python-dotenv, kept
separate from global.yaml since .env is gitignored and global.yaml is not.

Both are optional: if global.yaml is missing/unreadable, or pyyaml/
python-dotenv aren't installed, this falls back to the hardcoded defaults
below rather than failing to import.
"""

from pathlib import Path
from typing import Any, Dict

# Resolve base directories dynamically so code can run from any working directory
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent

GLOBAL_CONFIG_FILE = PROJECT_ROOT / "global.yaml"
ENV_FILE = PROJECT_ROOT / ".env"

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_FILE)  # no-op if .env doesn't exist
except ImportError:
    pass  # python-dotenv not installed — secrets (if any) must come from the real environment instead

_DEFAULTS: Dict[str, Any] = {
    "input_file": str(PROJECT_ROOT / "data" / "input" / "cve_fix_pairs.csv"),
    "output": {
        "pairs": str(PROJECT_ROOT / "data" / "output" / "output_csv_fix_pairs.csv"),
        "features": str(PROJECT_ROOT / "data" / "output" / "output_statement_features.csv"),
    },
    "pairs": {
        "granularity": "statement",
        "strategy": "aligned",
    },
    "verbose": False,
    # Mode "classify" (menu 3). Penjelasan tiap kunci ada di global.yaml.
    "classification": {
        "raw_input": str(PROJECT_ROOT / "data" / "input" / "cve_fix_pairs.csv"),
        "split_input": str(PROJECT_ROOT / "data" / "output" / "output_statement_features.csv"),
        "output_dir": str(PROJECT_ROOT / "data" / "output" / "classification"),
        "output_formats": ["xlsx", "csv"],
        "models": [{"name": "random_forest"}],
        "split": {
            "test_size": 0.2,
            "cv_folds": 0,
            "random_state": 42,
            "group_by": "method",
        },
        "align_samples": True,
        "threshold": 0.5,
        "method_aggregation": "max",
        "raw_features": {
            "max_features": 2000,
            "ngram_range": [1, 2],
            "min_df": 1,
        },
        "split_features": {
            "numeric": [
                "nesting_depth", "num_source_lines", "token_count", "char_length",
                "num_calls", "is_process_exec", "is_db_query", "is_dynamic_eval",
                "is_deserialization", "is_file_io", "is_network_call", "is_output_render",
                "uses_string_concat_or_format", "num_variables_defined", "num_variables_used",
                "uses_only_literals", "guard_count", "inside_error_handler",
                "is_error_handling_statement", "sanitization_call_detected", "is_compound",
                "num_direct_children", "cyclomatic_contribution",
            ],
            "categorical": ["statement_type", "parent_block_type", "call_target_kind", "language"],
            "raw_text_tfidf": False,
            "tfidf_max_features": 500,
        },
        "xai": {
            "enabled": True,
            "top_k": 20,
            "shap": True,
            "shap_max_samples": 300,
            "shap_kernel_fallback": False,
            "permutation": True,
            "permutation_repeats": 5,
            "permutation_scoring": "average_precision",
            "permutation_max_features": 100,
            "local_explanations": 10,
            "save_plots": True,
        },
    },
}


def is_url(value: str) -> bool:
    """True for http(s) URLs — pandas.read_csv accepts these directly, so
    input_file in global.yaml may point at a remote CSV instead of a local path."""
    return str(value).strip().lower().startswith(("http://", "https://"))


def _deep_merge(defaults: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(defaults)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_global_config() -> Dict[str, Any]:
    if not GLOBAL_CONFIG_FILE.exists():
        return dict(_DEFAULTS)
    try:
        import yaml
    except ImportError:
        return dict(_DEFAULTS)
    try:
        with open(GLOBAL_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return dict(_DEFAULTS)
    return _deep_merge(_DEFAULTS, data)


GLOBAL: Dict[str, Any] = _load_global_config()


def _resolve_path(value: str) -> Path:
    """A relative path in global.yaml is anchored to the project root, not
    to the current working directory (which varies depending on where the
    script is invoked from)."""
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


def _as_input_path(value: str):
    """Keeps a URL as a plain string (so pandas fetches it directly);
    resolves a local path to an absolute Path object."""
    return value if is_url(value) else _resolve_path(value)


DEFAULT_INPUT_FILE = _as_input_path(GLOBAL["input_file"])
DEFAULT_OUTPUT_FILE = _resolve_path(GLOBAL["output"]["pairs"])
DEFAULT_FEATURES_OUTPUT_FILE = _resolve_path(GLOBAL["output"]["features"])
DEFAULT_GRANULARITY = GLOBAL["pairs"]["granularity"]
DEFAULT_STRATEGY = GLOBAL["pairs"]["strategy"]
DEFAULT_VERBOSE = bool(GLOBAL["verbose"])

# Mode "classify": seluruh blok `classification:` dari global.yaml (sudah
# di-merge dengan default di atas), plus path-nya yang sudah di-resolve.
DEFAULT_CLASSIFICATION: Dict[str, Any] = GLOBAL["classification"]
DEFAULT_CLASSIFICATION_RAW_INPUT = _as_input_path(DEFAULT_CLASSIFICATION["raw_input"])
DEFAULT_CLASSIFICATION_SPLIT_INPUT = _resolve_path(DEFAULT_CLASSIFICATION["split_input"])
DEFAULT_CLASSIFICATION_OUTPUT_DIR = _resolve_path(DEFAULT_CLASSIFICATION["output_dir"])


def resolve_path(value: str) -> Path:
    """Public wrapper of _resolve_path for modules outside config.py."""
    return _resolve_path(value)


def as_input_path(value: str):
    """Public wrapper of _as_input_path for modules outside config.py."""
    return _as_input_path(value)
