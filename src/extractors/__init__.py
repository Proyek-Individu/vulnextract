"""
Extractor Registry and Factory for Language-specific Method Extractors.
"""

from typing import Dict, List, Optional
from .base import BaseMethodExtractor
from .c import CMethodExtractor
from .go import GoMethodExtractor
from .java import JavaMethodExtractor
from .javascript import JavascriptMethodExtractor
from .php import PhpMethodExtractor
from .python import PythonMethodExtractor
from .rust import RustMethodExtractor
from .typescript import TypescriptMethodExtractor


class ExtractorRegistry:
    """
    Registry for method extractors across different programming languages.
    Implements Factory pattern and Open-Closed Principle.
    """

    _registry: Dict[str, BaseMethodExtractor] = {}

    @classmethod
    def register(cls, extractor: BaseMethodExtractor, aliases: Optional[List[str]] = None) -> None:
        """Register an instantiated extractor instance with optional aliases."""
        canonical = extractor.language.lower()
        cls._registry[canonical] = extractor
        if aliases:
            for alias in aliases:
                cls._registry[alias.lower()] = extractor

    @classmethod
    def get(cls, language: str) -> Optional[BaseMethodExtractor]:
        """Retrieve the extractor instance for a given language."""
        if not language:
            return None
        return cls._registry.get(language.strip().lower())

    @classmethod
    def supported_languages(cls) -> List[str]:
        """List of all registered canonical and alias language names."""
        return list(cls._registry.keys())


# Register all supported language extractors
ExtractorRegistry.register(JavaMethodExtractor())
ExtractorRegistry.register(PythonMethodExtractor(), aliases=["py"])
ExtractorRegistry.register(GoMethodExtractor(), aliases=["golang"])
ExtractorRegistry.register(PhpMethodExtractor())
ExtractorRegistry.register(JavascriptMethodExtractor(), aliases=["js"])
ExtractorRegistry.register(TypescriptMethodExtractor(), aliases=["ts"])
ExtractorRegistry.register(RustMethodExtractor(), aliases=["rs"])
ExtractorRegistry.register(CMethodExtractor(), aliases=["cpp", "c++"])


def get_extractor(language: str) -> Optional[BaseMethodExtractor]:
    """Convenience helper to retrieve an extractor for a language."""
    return ExtractorRegistry.get(language)


__all__ = [
    "BaseMethodExtractor",
    "JavaMethodExtractor",
    "PythonMethodExtractor",
    "GoMethodExtractor",
    "PhpMethodExtractor",
    "JavascriptMethodExtractor",
    "TypescriptMethodExtractor",
    "RustMethodExtractor",
    "CMethodExtractor",
    "ExtractorRegistry",
    "get_extractor",
]
