"""
Go Function and Method Extractor using Tree-sitter.
"""

from typing import List
from tree_sitter import Language, Parser
import tree_sitter_go

from .base import BaseMethodExtractor


class GoMethodExtractor(BaseMethodExtractor):
    """
    Extracts function declarations and method declarations from Go source code using Tree-sitter.
    """

    def __init__(self) -> None:
        self._language = Language(tree_sitter_go.language())
        self._parser = Parser(self._language)
        self._statement_parser = self._parser
        self._statement_function_types = ("function_declaration", "method_declaration")
        self._statement_unwrap_types = ("statement_list",)

    @property
    def language(self) -> str:
        return "go"

    def extract_methods(self, source_code: str) -> List[str]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        source_bytes = source_code.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        methods: List[str] = []

        def walk(node) -> None:
            if node.type in ("function_declaration", "method_declaration"):
                method_text = source_bytes[node.start_byte:node.end_byte].decode(
                    "utf-8",
                    errors="replace"
                )
                methods.append(method_text)
                return

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return methods
