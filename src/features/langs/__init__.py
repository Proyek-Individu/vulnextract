"""
Registry of per-language feature schemas, mirroring
src/extractors/__init__.py's ExtractorRegistry factory pattern.
"""

from typing import Dict, Optional

from .base import LanguageFeatureSchema
from . import go, javascript, php, python

# TypeScript reuses JavaScript's schema: tree-sitter-typescript's statement/
# control-flow node types are the same as JS's for the constructs this
# schema covers (function bodies, if/for/while/try/switch/...).
LANGUAGE_FEATURE_SCHEMAS: Dict[str, LanguageFeatureSchema] = {
    "go": go.SCHEMA,
    "golang": go.SCHEMA,
    "python": python.SCHEMA,
    "py": python.SCHEMA,
    "javascript": javascript.SCHEMA,
    "js": javascript.SCHEMA,
    "typescript": javascript.SCHEMA,
    "ts": javascript.SCHEMA,
    "php": php.SCHEMA,
}


def get_schema(language: str) -> Optional[LanguageFeatureSchema]:
    """Retrieve the feature schema instance for a given language, or None
    if unsupported (out of context.md's target-language scope)."""
    if not language:
        return None
    return LANGUAGE_FEATURE_SCHEMAS.get(language.strip().lower())


__all__ = ["LanguageFeatureSchema", "LANGUAGE_FEATURE_SCHEMAS", "get_schema"]
