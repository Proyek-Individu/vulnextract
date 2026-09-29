"""
Shared schema contract and helpers for per-language statement-feature
extraction. Each language module in this package (go.py, python.py,
javascript.py, php.py) builds one LanguageFeatureSchema instance describing:

- which AST node types get their own StatementRecord row ("statement" tier),
- which AST node types are transparent (containers like Go's "block", or
  clause wrappers like "except_clause") that get unwrapped rather than
  emitted as a row,
- how to derive the canonical `statement_type` / `parent_block_type` labels,
- the category D (sink) / E (sanitizer) signature dictionaries, transcribed
  directly from context.md's own per-flag, per-language function name lists.

This intentionally does NOT hand-enumerate a per-node-type "which fields to
recurse into" table. Instead tree_builder.py walks every named child of a
container/statement node (via a tree-sitter cursor, which also exposes the
child's field name) and classifies each *child's own node type* as
statement / transparent / leaf. This generalizes for free across grammar
quirks like Go's `if_statement.alternative` sometimes being a `block` and
sometimes another `if_statement` with no wrapper at all.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

# Node types that represent comments across the supported grammars.
COMMENT_NODE_TYPES = frozenset({"comment", "line_comment", "block_comment", "shebang"})


@dataclass(frozen=True)
class SinkFlag:
    """
    A category-D/E boolean flag's match rules. `exact` matches the full
    (possibly qualified) call name; `suffix` matches a trailing qualifier
    (e.g. any call ending in ".query"); `substring` is the loosest, used
    sparingly for package-path-shaped signatures (e.g. Go's "gob.").
    """
    exact: FrozenSet[str] = field(default_factory=frozenset)
    suffix: FrozenSet[str] = field(default_factory=frozenset)
    substring: FrozenSet[str] = field(default_factory=frozenset)

    def matches(self, call_name: str) -> bool:
        if not call_name:
            return False
        if call_name in self.exact:
            return True
        if any(call_name.endswith(s) for s in self.suffix):
            return True
        if any(s in call_name for s in self.substring):
            return True
        return False


@dataclass(frozen=True)
class LanguageFeatureSchema:
    language: str

    # Node types that get their own StatementRecord row. Membership alone
    # decides row-emission; `statement_type_of` (below) decides the
    # canonical label, which may require inspecting the node's own children
    # (e.g. Python/JS/PHP's generic "expression_statement" wrapper).
    statement_node_types: FrozenSet[str]

    # Node types that are transparent for row-emission: both pure block
    # containers (Go's "block"/"statement_list", PHP's "compound_statement")
    # and clause wrappers (else_clause, catch_clause, switch case bodies).
    # Their own named children are recursed into directly.
    transparent_node_types: FrozenSet[str]

    # node.type -> canonical statement_type (context.md category A). Used
    # for statement_node_types whose label doesn't need child inspection.
    statement_type_map: Dict[str, str]

    # Refines statement_type for wrapper-ish statement node types whose
    # real meaning depends on an inner child (e.g. PHP's expression_statement
    # wrapping a throw_expression -> "throw_raise" instead of "call_expr").
    # Returns None to fall back to statement_type_map.
    refine_statement_type: Callable[[object], Optional[str]]

    # (parent_node_type, field_name) -> parent_block_type label. Used when
    # recursing into a *statement* node's own named children (e.g. Go
    # if_statement's "consequence"/"alternative" fields).
    block_type_by_field: Dict[Tuple[str, str], str]

    # (parent_node_type, child_node_type) -> parent_block_type label. Used
    # when recursing into a *transparent* node's children and no field name
    # disambiguates (e.g. Python try_statement's except_clause/else_clause/
    # finally_clause, which attach with no field name since they repeat).
    block_type_by_child_type: Dict[Tuple[str, str], str]

    # Node types that represent "a call" in this grammar (call_expression,
    # function_call_expression, member_call_expression, ...).
    call_node_types: FrozenSet[str]

    # A call node -> its qualified/dotted call name (e.g. "os.system"),
    # or None if it can't be determined.
    call_name_of: Callable[[object], Optional[str]]

    # A statement node -> the identifier-like nodes on its assignment LHS
    # (empty list if the node isn't assignment-shaped). Needs to be a
    # callable rather than a flat field name since some grammars nest the
    # LHS under an intermediate node (e.g. Go's var_declaration -> one or
    # more var_spec children, each with its own "name" field).
    lhs_identifiers_of: Callable[[object], List[object]]

    # Category D sink flags, transcribed from context.md.
    sink_flags: Dict[str, SinkFlag]

    # Category E sanitizer signatures, transcribed from context.md.
    sanitizer_names: SinkFlag

    # Node type representing a plain variable/name reference, used for
    # num_variables_used (identifiers not on an assignment LHS). Go/Python/
    # JS all call this "identifier"; PHP uses "variable_name" ("name" is
    # overloaded there for function/method names too).
    identifier_node_type: str

    # Node types whose presence signals string concatenation/formatting
    # (template/interpolated strings, or a binary "+"/"." expression —
    # disambiguated from other binary operators via `concat_operator`).
    concat_or_format_node_types: FrozenSet[str]

    # The binary operator token that means "string concatenation" in this
    # grammar ("+" for Go/JS/Python, "." for PHP). None if not applicable.
    concat_operator: Optional[str] = None

    # Call names treated as "string formatting" for
    # uses_string_concat_or_format (e.g. Go's fmt.Sprintf, Python's
    # str.format() — a call rather than an operator or interpolation node).
    format_call_signature: SinkFlag = field(default_factory=SinkFlag)

    # Small, deliberately incomplete set of standard-library package/module
    # prefixes for call_target_kind's best-effort stdlib/third_party split.
    # context.md notes real classification needs cross-referencing the
    # repo's own function_def list, which this per-method pipeline doesn't
    # have — this is a documented approximation, not a resolved import table.
    stdlib_prefixes: FrozenSet[str] = field(default_factory=frozenset)

    # Plain substring patterns checked directly against a statement's raw
    # text for is_output_render cases that aren't call-shaped at all (JS
    # `el.innerHTML =`, PHP `echo`/`print`) — a deliberately loose,
    # documented-as-approximate fallback alongside the call-based sink_flags
    # entry for the same column.
    output_render_text_patterns: FrozenSet[str] = field(default_factory=frozenset)

    # Language-specific structural special case, e.g. Go's `if err != nil`
    # shape standing in for a try/catch exception handler (no try/catch
    # exists in Go). Returns True if `node` (an if_statement's condition
    # node) matches the language's "this if is acting as error handling"
    # shape. Default (no special case): always False.
    is_error_guard_condition: Callable[[object], bool] = lambda node: False


def leaf_token_count(node) -> int:
    """Counts leaf tokens (both named and anonymous) under `node`, inclusive."""
    if node.child_count == 0:
        return 1
    return sum(leaf_token_count(child) for child in node.children)


def node_text(source_bytes: bytes, node) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
