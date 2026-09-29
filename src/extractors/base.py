"""
Abstract Base Class for AST and Statement-based Code Extractors.
"""

from abc import ABC, abstractmethod
import re
from typing import Any, List, Optional, Tuple

# Node types that represent comments across the supported grammars — excluded
# from statement extraction since a bare comment is not a statement.
_COMMENT_NODE_TYPES = {"comment", "line_comment", "block_comment", "shebang"}


class BaseMethodExtractor(ABC):
    """
    Abstract interface for language-specific method and statement extractors.
    Any new language support must inherit from this class and implement
    `extract_methods`.
    """

    # Subclasses that support AST-based statement extraction set these in
    # their __init__ (parser instance + the node types identifying a
    # function/method). Left unset, extract_statements() falls back to the
    # blank-line heuristic.
    _statement_parser: Optional[Any] = None
    _statement_function_types: Tuple[str, ...] = ()
    _statement_container_types: Optional[Tuple[str, ...]] = None
    # Some grammars (e.g. Go) wrap the sequence of statements inside the
    # function body in an intermediate node (e.g. "statement_list") rather
    # than making them direct children of the body block. When the body has
    # exactly one named child of one of these types, extraction unwraps into
    # it so the actual statements are what gets returned.
    _statement_unwrap_types: Optional[Tuple[str, ...]] = None

    def resolve_statement_parser(self, source_code: str) -> Optional[Any]:
        """
        Returns the tree-sitter Parser to use for `source_code`. Defaults to
        the fixed `_statement_parser`; overridden by extractors that pick a
        parser dynamically per-input (PhpMethodExtractor selects between its
        two grammars based on whether a "<?php" tag is present). Used by
        both this class's own extract_statements() and
        src/features/tree_builder.py's hierarchical extractor, so parser
        selection never drifts between the two pipelines.
        """
        return self._statement_parser

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
        Extract statement-level code blocks.

        Uses AST-based extraction (direct child statements of the enclosing
        function/method body) when the subclass provides a parser via
        `_statement_parser`/`_statement_function_types`. This keeps the
        statement boundaries stable regardless of the blank-line formatting
        a particular commit happens to use, so a vulnerable/fixed pair that
        was reformatted (e.g. collapsed into fewer/more blank-line groups)
        still yields comparable statement counts.

        Falls back to splitting on blank lines when no AST parser is
        configured for this extractor.

        Args:
            source_code: The raw source code string (method or file).

        Returns:
            List[str]: List of extracted statement blocks.
        """
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        if self._statement_parser is None or not self._statement_function_types:
            return self._extract_statements_by_blank_lines(source_code)

        return self._extract_statements_via_ast(
            source_code,
            parser=self._statement_parser,
            function_node_types=self._statement_function_types,
            container_node_types=self._statement_container_types,
            unwrap_container_types=self._statement_unwrap_types,
        )

    @staticmethod
    def _extract_statements_by_blank_lines(source_code: str) -> List[str]:
        """
        Extract statement-level code blocks by splitting on blank newlines (empty lines).
        This is a formatting-based heuristic used only as a fallback when no
        AST-based extraction is configured for the language.

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

    @staticmethod
    def find_enclosing_function(tree_root, function_node_types: Tuple[str, ...]):
        """
        Returns the first node under `tree_root` (pre-order, i.e. document
        order) whose type is in `function_node_types`, or None if none is
        found. Shared by the flat statement extractor below and by
        src/features/tree_builder.py's hierarchical extractor, so both
        pipelines select the identical function/method node for the same
        input and their statement boundaries never drift apart.
        """
        func_node = None

        def find_func(node) -> None:
            nonlocal func_node
            if func_node is not None:
                return
            if node.type in function_node_types:
                func_node = node
                return
            for child in node.children:
                find_func(child)

        find_func(tree_root)
        return func_node

    @staticmethod
    def _extract_statements_via_ast(
        source_code: str,
        parser: Any,
        function_node_types: Tuple[str, ...],
        container_node_types: Optional[Tuple[str, ...]] = None,
        unwrap_container_types: Optional[Tuple[str, ...]] = None,
    ) -> List[str]:
        """
        Splits source code into statement-level chunks by locating the
        enclosing function/method node and returning its body's direct
        (named) children as individual statements.

        This is stable across formatting differences (blank lines, brace
        style) because it relies on the actual AST structure rather than
        whitespace — unlike a blank-line split, a vulnerable snippet and its
        rewritten fixed counterpart are segmented by real statement
        boundaries, not by how many empty lines the author happened to leave.

        Args:
            source_code: Source of a single method/function (or a bare
                fragment of statements without an enclosing function).
            parser: A configured tree-sitter Parser for this language.
            function_node_types: Node types identifying a function/method
                declaration in this grammar.
            container_node_types: If given, the function body node must be
                one of these types to be treated as a statement container
                (guards against e.g. a JS/TS arrow function whose body is a
                bare expression, not a block).
            unwrap_container_types: If given and the body's only named child
                matches one of these types, descend into it (e.g. Go wraps
                statements in a "statement_list" node inside "block").

        Returns:
            List[str]: One entry per top-level statement in the function
            body, or per top-level node in the fragment when no enclosing
            function is found.
        """
        source_bytes = source_code.encode("utf-8")
        tree = parser.parse(source_bytes)

        func_node = BaseMethodExtractor.find_enclosing_function(tree.root_node, function_node_types)

        def node_text(node) -> str:
            return source_bytes[node.start_byte:node.end_byte].decode(
                "utf-8",
                errors="replace"
            ).strip()

        container = None
        if func_node is not None:
            body = func_node.child_by_field_name("body")
            if body is not None and (
                container_node_types is None or body.type in container_node_types
            ):
                container = body

        if container is None:
            container = tree.root_node
        elif unwrap_container_types:
            sole_child = container.named_children
            if len(sole_child) == 1 and sole_child[0].type in unwrap_container_types:
                container = sole_child[0]

        statements = [
            node_text(child)
            for child in container.named_children
            if child.type not in _COMMENT_NODE_TYPES
        ]
        statements = [s for s in statements if s]

        if statements:
            return statements

        # Nothing decomposable found (e.g. a single expression fragment) —
        # treat the whole snippet as one statement rather than dropping it.
        text = source_code.strip()
        return [text] if text else []


# Backward compatibility alias
BaseCodeExtractor = BaseMethodExtractor
BaseStatementExtractor = BaseMethodExtractor
