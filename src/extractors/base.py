"""
Abstract Base Class for AST and Statement-based Code Extractors.
"""

from abc import ABC, abstractmethod
import re
from typing import List


class BaseMethodExtractor(ABC):
    """
    Abstract interface for language-specific method and statement extractors.
    Any new language support must inherit from this class and implement
    `extract_methods`.
    """

    @property
    @abstractmethod
    def language(self) -> str:
        """The canonical language identifier (e.g. 'java', 'go', 'python')."""
        pass

    @abstractmethod
    def extract_methods(self, source_code: str) -> List[str]:
        """
        Extract method/function declaration source code snippets from a given raw source code string.

        Args:
            source_code: The raw source code of the class, file, or block.

        Returns:
            List[str]: Extracted method source code snippets.
        """
        pass

    def extract_statements(self, source_code: str) -> List[str]:
        """
        Extract statement-level code blocks by splitting on blank newlines (empty lines).
        This breaks down functions/methods into logical statement blocks as requested
        by the client.

        Args:
            source_code: The raw source code string (method or file).

        Returns:
            List[str]: List of statement blocks bounded by blank newlines.
        """
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        # Normalize line endings
        normalized = source_code.replace("\r\n", "\n").replace("\r", "\n")

        # Split on one or more empty/blank lines (blank newline)
        raw_chunks = re.split(r"\n\s*\n+", normalized)

        return [chunk.strip() for chunk in raw_chunks if chunk.strip()]


# Backward compatibility alias
BaseCodeExtractor = BaseMethodExtractor
BaseStatementExtractor = BaseMethodExtractor

