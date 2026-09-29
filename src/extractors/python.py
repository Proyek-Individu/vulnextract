"""
Python Function and Method Extractor using Tree-sitter.
"""

from typing import List
from tree_sitter import Language, Parser
import tree_sitter_python

from .base import BaseMethodExtractor


class PythonMethodExtractor(BaseMethodExtractor):
    """
    Extracts function and method declarations from Python source code using Tree-sitter.
    """

    def __init__(self) -> None:
        self._language = Language(tree_sitter_python.language())
        self._parser = Parser(self._language)
        self._statement_parser = self._parser
        self._statement_function_types = ("function_definition",)

    @property
    def language(self) -> str:
        return "python"

    def extract_methods(self, source_code: str) -> List[str]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        source_bytes = source_code.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        methods: List[str] = []

        def walk(node) -> None:
            if node.type in ("function_definition",):
                method_text = source_bytes[node.start_byte:node.end_byte].decode(
                    "utf-8",
                    errors="replace"
                )
                methods.append(method_text)
                return  # Capture outermost function/method

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return methods
