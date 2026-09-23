"""
Abstract Base Class for AST-based Method Extractors.
"""

from abc import ABC, abstractmethod
from typing import List


class BaseMethodExtractor(ABC):
    """
    Abstract interface for language-specific method extractors.
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
