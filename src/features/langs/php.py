"""
PHP language feature schema. Grounded empirically against tree-sitter-php
0.24.1. Key finding: `throw` is not its own statement node in this grammar —
it's a `throw_expression` wrapped inside `expression_statement`, so it's
picked up by `_refine_statement_type` like assign/call_expr are. Method
calls (`$obj->method()`) and static calls (`Class::method()`) don't expose a
single pre-joined "function" field the way Go/Python/JS member calls do, so
`_call_name_of` reconstructs the qualified name from separate object/scope +
name fields.
"""

from typing import List, Optional

from .base import LanguageFeatureSchema, SinkFlag

STATEMENT_NODE_TYPES = frozenset({
    "expression_statement", "if_statement", "else_if_clause", "foreach_statement",
    "for_statement", "while_statement", "do_statement", "switch_statement",
    "try_statement", "return_statement", "break_statement", "continue_statement",
    "global_statement", "echo_statement", "goto_statement", "function_definition",
    "const_declaration",
})

TRANSPARENT_NODE_TYPES = frozenset({
    "compound_statement", "else_clause", "catch_clause", "finally_clause",
    "switch_block", "case_statement", "default_statement",
})

STATEMENT_TYPE_MAP = {
    "if_statement": "if",
    "else_if_clause": "if",
    "foreach_statement": "for",
    "for_statement": "for",
    "while_statement": "while",
    "do_statement": "do_while",
    "switch_statement": "switch",
    "try_statement": "try_catch",
    "return_statement": "return",
    "break_statement": "break",
    "continue_statement": "continue",
    "global_statement": "global",
    "echo_statement": "echo",
    "goto_statement": "goto",
    "function_definition": "function_def",
    "const_declaration": "assign",
}

BLOCK_TYPE_BY_FIELD = {
    ("if_statement", "body"): "if_true_branch",
    ("if_statement", "alternative"): "if_false_branch",
    ("else_if_clause", "body"): "if_true_branch",
    ("else_if_clause", "alternative"): "if_false_branch",
    ("foreach_statement", "body"): "loop_body",
    ("for_statement", "body"): "loop_body",
    ("while_statement", "body"): "loop_body",
    ("do_statement", "body"): "loop_body",
    ("function_definition", "body"): "function_body",
    ("try_statement", "body"): "try_body",
}

BLOCK_TYPE_BY_CHILD_TYPE = {
    ("try_statement", "catch_clause"): "exception_handler",
    ("try_statement", "finally_clause"): "finally_block",
    ("switch_block", "case_statement"): "switch_case",
    ("switch_block", "default_statement"): "switch_case",
}

CALL_NODE_TYPES = frozenset({
    "function_call_expression", "member_call_expression", "scoped_call_expression",
})


def _call_name_of(node) -> Optional[str]:
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        return func.text.decode("utf-8", errors="replace") if func is not None else None
    if node.type == "member_call_expression":
        obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name")
        if obj is None or name is None:
            return None
        return f"{obj.text.decode('utf-8', errors='replace')}->{name.text.decode('utf-8', errors='replace')}"
    if node.type == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        if scope is None or name is None:
            return None
        return f"{scope.text.decode('utf-8', errors='replace')}::{name.text.decode('utf-8', errors='replace')}"
    return None


def _lhs_identifiers_of(node) -> List[object]:
    if node.type != "expression_statement" or node.named_child_count != 1:
        return []
    inner = node.named_children[0]
    if inner.type != "assignment_expression":
        return []
    left = inner.child_by_field_name("left")
    if left is None:
        return []
    if left.type == "variable_name":
        return [left]
    return [c for c in left.named_children if c.type == "variable_name"]


# Category D sink signatures, transcribed verbatim from context.md.
# Known gap (documented, not implemented): the backtick shell-exec operator
# and include/require-as-code-execution are not call-shaped nodes in this
# grammar, so they aren't matched here — see context.md's own note that
# include/require need a separate flag.
SINK_FLAGS = {
    "is_process_exec": SinkFlag(exact=frozenset({"exec", "shell_exec", "system", "passthru"})),
    "is_db_query": SinkFlag(
        exact=frozenset({"mysqli_query"}),
        suffix=frozenset({"->query", "->exec"}),
    ),
    "is_dynamic_eval": SinkFlag(exact=frozenset({"eval", "create_function"})),
    "is_deserialization": SinkFlag(exact=frozenset({"unserialize"})),
    "is_file_io": SinkFlag(exact=frozenset({"fopen", "file_get_contents", "unlink"})),
    "is_network_call": SinkFlag(exact=frozenset({"curl_exec", "file_get_contents"})),
    "is_output_render": SinkFlag(),  # "echo"/"print" aren't calls; handled via statement_type == "echo" in feature_extractor.py
}

# Category E sanitizer signatures, transcribed verbatim from context.md.
SANITIZER_NAMES = SinkFlag(exact=frozenset({
    "htmlspecialchars", "filter_var", "mysqli_real_escape_string",
}))

CONCAT_OR_FORMAT_NODE_TYPES = frozenset({"binary_expression", "encapsed_string"})
FORMAT_CALL_SIGNATURE = SinkFlag(exact=frozenset({"sprintf", "vsprintf"}))


def _refine_statement_type(node) -> Optional[str]:
    if node.type != "expression_statement" or node.named_child_count != 1:
        return None
    inner = node.named_children[0]
    if inner.type == "assignment_expression":
        return "assign"
    if inner.type in ("function_call_expression", "member_call_expression", "scoped_call_expression"):
        return "call_expr"
    if inner.type == "throw_expression":
        return "throw_raise"
    return "expr_stmt"


SCHEMA = LanguageFeatureSchema(
    language="php",
    statement_node_types=STATEMENT_NODE_TYPES,
    transparent_node_types=TRANSPARENT_NODE_TYPES,
    statement_type_map=STATEMENT_TYPE_MAP,
    refine_statement_type=_refine_statement_type,
    block_type_by_field=BLOCK_TYPE_BY_FIELD,
    block_type_by_child_type=BLOCK_TYPE_BY_CHILD_TYPE,
    call_node_types=CALL_NODE_TYPES,
    call_name_of=_call_name_of,
    lhs_identifiers_of=_lhs_identifiers_of,
    sink_flags=SINK_FLAGS,
    sanitizer_names=SANITIZER_NAMES,
    identifier_node_type="variable_name",
    concat_or_format_node_types=CONCAT_OR_FORMAT_NODE_TYPES,
    concat_operator=".",
    format_call_signature=FORMAT_CALL_SIGNATURE,
)
