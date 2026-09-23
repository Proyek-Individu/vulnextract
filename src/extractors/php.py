"""
PHP Function and Method Extractor using Tree-sitter.
"""

from typing import List
from tree_sitter import Language, Parser
import tree_sitter_php

from .base import BaseMethodExtractor


class PhpMethodExtractor(BaseMethodExtractor):
    """
    Extracts function and method declarations from PHP source code using Tree-sitter.
    Supports both snippet format (without <?php) and complete files (with <?php).
    """

    def __init__(self) -> None:
        self._parser_php_only = Parser(Language(tree_sitter_php.language_php_only()))
        self._parser_php = Parser(Language(tree_sitter_php.language_php()))

    @property
    def language(self) -> str:
        return "php"

    def extract_methods(self, source_code: str) -> List[str]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        # If opening tag is present, use language_php; otherwise language_php_only
        if "<?php" in source_code:
            parser = self._parser_php
        else:
            parser = self._parser_php_only

        source_bytes = source_code.encode("utf-8")
        tree = parser.parse(source_bytes)
        methods: List[str] = []

        def walk(node) -> None:
            if node.type in ("function_definition", "method_declaration"):
                method_text = source_bytes[node.start_byte:node.end_byte].decode(
                    "utf-8",
                    errors="replace"
                )
                methods.append(method_text)
                return

            for child in node.children:
                walk(child)

        walk(tree.root_node)

        # Fallback if no methods found with first parser
        if not methods and parser is self._parser_php_only:
            tree = self._parser_php.parse(source_bytes)
            walk(tree.root_node)

        return methods
