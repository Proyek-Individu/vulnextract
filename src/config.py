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
