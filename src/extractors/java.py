"""
Java Method and Constructor Extractor using Tree-sitter.
"""

from typing import List
from tree_sitter import Language, Parser
import tree_sitter_java

from .base import BaseMethodExtractor


class JavaMethodExtractor(BaseMethodExtractor):
    """
    Extracts method and constructor declarations from Java source code using Tree-sitter.
    """

    def __init__(self) -> None:
        self._language = Language(tree_sitter_java.language())
        self._parser = Parser(self._language)
        self._statement_parser = self._parser
        self._statement_function_types = ("method_declaration", "constructor_declaration")

    @property
    def language(self) -> str:
        return "java"

    def extract_methods(self, source_code: str) -> List[str]:
        """
        Extract method declarations and constructor declarations from Java source code.

        Args:
            source_code: Java source code string.

        Returns:
            List[str]: List of extracted method/constructor source codes.
        """
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        source_bytes = source_code.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        methods: List[str] = []

        def walk(node) -> None:
            if node.type in ("method_declaration", "constructor_declaration"):
                method_text = source_bytes[node.start_byte:node.end_byte].decode(
                    "utf-8",
                    errors="replace"
                )
                methods.append(method_text)

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return methods
