"""
Recursive hierarchical statement-tree extraction.

Generalizes src/extractors/base.py's flat, single-level
`_extract_statements_via_ast` to every nesting depth: a compound statement
(if/for/while/try/switch/...) gets its own row *and* recurses into its
block-shaped children, which get their own rows too, linked back via
`parent_statement_id`/`nesting_depth` — matching context.md's stated unit of
extraction ("hierarchical — compound statement dan child-nya masing-masing
jadi baris terpisah").

Reuses each language's already-registered BaseMethodExtractor instance (via
get_extractor) for parsing/function-node-selection, so this pipeline's
statement boundaries never drift from the existing flat pair pipeline's.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.extractors import get_extractor
from src.extractors.base import BaseMethodExtractor
from .langs.base import COMMENT_NODE_TYPES, LanguageFeatureSchema


@dataclass
class StatementNode:
    """Internal tree-walking structure — holds a raw tree-sitter Node, so
    (per context.md's "every column must be scalar" rule) this must never
    leak directly into StatementRecord; feature_extractor.py converts each
    StatementNode into a flat StatementRecord."""
    ast_node: object
    statement_id: str
    parent_statement_id: Optional[str]
    nesting_depth: int
    statement_type: str
    parent_block_type: str
    field_name: Optional[str]
    children: List["StatementNode"] = field(default_factory=list)
    # Set by labeler.py after the tree is built; 0 (unchanged) by default —
    # only statements the vulnerable/fixed diff identifies as actually
    # changed get flipped to 1. See label_statements() in labeler.py.
    label: int = 0


def flatten(nodes: List[StatementNode]) -> List[StatementNode]:
    """Pre-order (parent before children) flat list of every node in the tree(s)."""
    out: List[StatementNode] = []
    for n in nodes:
        out.append(n)
        out.extend(flatten(n.children))
    return out


def local_scope_text(node: StatementNode, source_bytes: bytes) -> str:
    """
    `node`'s own source span with its direct recursed children's spans
    excised — i.e. just the "header" content a statement contributes on its
    own (an if's condition + branch keywords, minus the branch bodies).

    Used for two things that must NOT double-count nested content:
    - labeler.py: diffing whether a compound statement's own header changed,
      independent of whether its children changed.
    - feature_extractor.py: local-scope call/variable counting, so a call
      inside a nested if-body isn't counted against both the if's row and
      the child's row.
    """
    ast = node.ast_node
    spans = sorted((c.ast_node.start_byte, c.ast_node.end_byte) for c in node.children)
    pieces = []
    cursor = ast.start_byte
    for start, end in spans:
        if start > cursor:
            pieces.append(source_bytes[cursor:start])
        cursor = max(cursor, end)
    if cursor < ast.end_byte:
        pieces.append(source_bytes[cursor:ast.end_byte])
    return b"".join(pieces).decode("utf-8", errors="replace")


def local_scope_nodes(node: StatementNode, predicate) -> List[object]:
    """
    AST descendant nodes within `node`'s own span for which
    `predicate(ast_node)` is True, excluding anything inside a recursed
    child statement's span. Same boundary concept as local_scope_text, but
    returns matching node objects instead of joined text — used by
    feature_extractor.py to collect calls/identifiers belonging to this
    statement itself, not to its nested child statements.
    """
    excluded = {(c.ast_node.start_byte, c.ast_node.end_byte) for c in node.children}
    found: List[object] = []

    def walk(ast_node) -> None:
        if (ast_node.start_byte, ast_node.end_byte) in excluded:
            return
        if predicate(ast_node):
            found.append(ast_node)
        for child in ast_node.children:
            walk(child)

    walk(node.ast_node)
    return found


def build_statement_tree(
    source_code: str,
    language: str,
    schema: LanguageFeatureSchema,
    id_prefix: str,
) -> Tuple[List[StatementNode], bytes]:
    """
    Builds the hierarchical statement tree for one method's source.

    Args:
        source_code: Source of a single method/function (matches how the
            existing pipeline already treats each CSV row's vulnerable_code/
            fixed_code — the whole method text, not a pre-split snippet).
        language: canonical language key (as ExtractorRegistry knows it).
        schema: this language's LanguageFeatureSchema (see langs/*.py).
        id_prefix: `{repo}:{file}:{function}` per context.md's own
            statement_id scheme — line range + a disambiguating counter are
            appended per emitted statement.

    Returns:
        (roots, source_bytes): the top-level (nesting_depth=0) StatementNodes
        — each carries its own nested `.children`, use flatten() to get every
        node as a flat list — and the exact encoded bytes their `ast_node`
        byte offsets are relative to (not necessarily `source_code.encode()`
        verbatim: TypeScript's isolated-method wrapping prepends a dummy
        class). Callers that slice text by byte offset (labeler.py's
        local_scope_text) must use these bytes, not their own re-encoding.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return [], b""

    extractor = get_extractor(language)
    if extractor is None or not extractor._statement_function_types:
        return [], b""

    # TypeScript's isolated-method wrapping quirk (see extractors/typescript.py)
    wrap = getattr(extractor, "_wrap_if_isolated_method", None)
    effective_source = wrap(source_code) if callable(wrap) else source_code

    parser = extractor.resolve_statement_parser(effective_source)
    if parser is None:
        return [], b""
    function_node_types = extractor._statement_function_types

    source_bytes = effective_source.encode("utf-8")
    tree = parser.parse(source_bytes)

    func_node = BaseMethodExtractor.find_enclosing_function(tree.root_node, function_node_types)
    if func_node is not None:
        body = func_node.child_by_field_name("body")
        container_root = body if body is not None else tree.root_node
    else:
        container_root = tree.root_node

    counter = [0]

    def make_id(node) -> str:
        counter[0] += 1
        return f"{id_prefix}:{node.start_point[0] + 1}-{node.end_point[0] + 1}#{counter[0]}"

    def classify(node_type: str) -> str:
        if node_type in schema.transparent_node_types:
            return "transparent"
        if node_type in schema.statement_node_types:
            return "statement"
        return "leaf"

    def resolve_block_type(parent_type: str, field_name: Optional[str], child_type: str, current: str) -> str:
        if field_name is not None:
            label = schema.block_type_by_field.get((parent_type, field_name))
            if label is not None:
                return label
        label = schema.block_type_by_child_type.get((parent_type, child_type))
        if label is not None:
            return label
        return current

    def walk_container(container_node, parent_statement_id: Optional[str], nesting_depth: int, block_type: str) -> List[StatementNode]:
        results: List[StatementNode] = []
        cursor = container_node.walk()
        if not cursor.goto_first_child():
            return results
        while True:
            child = cursor.node
            child_field = cursor.field_name
            if child.is_named and child.type not in COMMENT_NODE_TYPES:
                kind = classify(child.type)
                new_block_type = resolve_block_type(container_node.type, child_field, child.type, block_type)
                if kind == "statement":
                    stype = schema.refine_statement_type(child) or schema.statement_type_map.get(child.type, child.type)
                    node = StatementNode(
                        ast_node=child,
                        statement_id=make_id(child),
                        parent_statement_id=parent_statement_id,
                        nesting_depth=nesting_depth,
                        statement_type=stype,
                        parent_block_type=new_block_type,
                        field_name=child_field,
                    )
                    node.children = walk_container(child, node.statement_id, nesting_depth + 1, block_type)
                    results.append(node)
                elif kind == "transparent":
                    results.extend(walk_container(child, parent_statement_id, nesting_depth, new_block_type))
                # leaf: part of the enclosing statement's own header/condition text, not recursed
            if not cursor.goto_next_sibling():
                break
        return results

    roots = walk_container(container_root, None, 0, "function_body")
    return roots, source_bytes
