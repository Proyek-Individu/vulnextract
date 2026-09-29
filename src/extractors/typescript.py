"""
TypeScript Function and Method Extractor using Tree-sitter.
"""

from typing import List
from tree_sitter import Language, Parser
import tree_sitter_typescript

from .base import BaseMethodExtractor


class TypescriptMethodExtractor(BaseMethodExtractor):
    """
    Extracts function declarations, method definitions, arrow functions,
    and function expressions from TypeScript source code using Tree-sitter.
    Handles isolated class methods with access modifiers (private, protected, public).
    """

    _STATEMENT_FUNCTION_TYPES = (
        "function_declaration",
        "method_definition",
        "arrow_function",
        "function_expression",
    )
    # Guards against arrow functions with an expression body (e.g.
    # `(a, b) => a - b`), where the body is not a block of statements.
    _STATEMENT_CONTAINER_TYPES = ("statement_block",)

    def __init__(self) -> None:
        self._language = Language(tree_sitter_typescript.language_typescript())
        self._parser = Parser(self._language)

    @property
    def language(self) -> str:
        return "typescript"

    @staticmethod
    def _wrap_if_isolated_method(source_code: str) -> str:
        """Wraps an isolated class method with an access modifier in a dummy class,
        since such a snippet is not valid standalone TypeScript on its own."""
        clean_code = source_code.strip()
        needs_class_wrapper = clean_code.startswith(("private ", "public ", "protected ", "readonly ", "static "))
        return f"class Dummy {{\n{source_code}\n}}" if needs_class_wrapper else source_code

    def extract_methods(self, source_code: str) -> List[str]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        effective_code = self._wrap_if_isolated_method(source_code)

        source_bytes = effective_code.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        methods: List[str] = []

        def walk(node) -> None:
            if node.type in (
                "function_declaration",
                "method_definition",
                "arrow_function",
                "function_expression",
            ):
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

    def extract_statements(self, source_code: str) -> List[str]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        effective_code = self._wrap_if_isolated_method(source_code)

        return self._extract_statements_via_ast(
            effective_code,
            parser=self._parser,
            function_node_types=self._STATEMENT_FUNCTION_TYPES,
            container_node_types=self._STATEMENT_CONTAINER_TYPES,
        )
