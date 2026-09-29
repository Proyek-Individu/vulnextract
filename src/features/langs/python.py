"""
Python language feature schema. Grounded empirically against
tree-sitter-python 0.25.0. Key finding: `block` nodes hold statements
directly (no extra wrapper level, unlike Go's `block -> statement_list`).
`elif_clause` carries its own condition, so it is treated as a STATEMENT
("if") like Go/PHP's else-if chains, not a transparent wrapper — only the
unconditional `else_clause` is transparent. `try_statement`'s
except/else/finally clauses attach with no field name (they can repeat),
so their parent_block_type is resolved by child node type instead of field.
"""

from typing import List, Optional

from .base import LanguageFeatureSchema, SinkFlag

STATEMENT_NODE_TYPES = frozenset({
    "expression_statement", "if_statement", "elif_clause", "for_statement",
    "while_statement", "try_statement", "with_statement", "return_statement",
    "raise_statement", "import_statement", "import_from_statement",
    "break_statement", "continue_statement", "pass_statement",
    "global_statement", "nonlocal_statement", "assert_statement",
    "delete_statement", "function_definition",
})

TRANSPARENT_NODE_TYPES = frozenset({
    "block", "except_clause", "else_clause", "finally_clause",
})

STATEMENT_TYPE_MAP = {
    "if_statement": "if",
    "elif_clause": "if",
    "for_statement": "for",
    "while_statement": "while",
    "try_statement": "try_catch",
    "with_statement": "with",
    "return_statement": "return",
    "raise_statement": "throw_raise",
    "import_statement": "import",
    "import_from_statement": "import",
    "break_statement": "break",
    "continue_statement": "continue",
    "pass_statement": "pass",
    "global_statement": "global",
    "nonlocal_statement": "nonlocal",
    "assert_statement": "assert",
    "delete_statement": "delete",
    "function_definition": "function_def",
    # expression_statement is refined below by inspecting its single child.
}

BLOCK_TYPE_BY_FIELD = {
    ("if_statement", "consequence"): "if_true_branch",
    ("if_statement", "alternative"): "if_false_branch",
    ("elif_clause", "consequence"): "if_true_branch",
    ("elif_clause", "alternative"): "if_false_branch",
    ("for_statement", "body"): "loop_body",
    ("while_statement", "body"): "loop_body",
    ("with_statement", "body"): "with_body",
    ("function_definition", "body"): "function_body",
    ("try_statement", "body"): "try_body",
    ("else_clause", "body"): None,  # resolved by inherited block type; see note below
}
# else_clause's own body has field=body in the grammar, but which semantic
# label applies depends on *its parent* (if/for/while/try), already set when
# we transitioned into else_clause via block_type_by_child_type below — so
# we deliberately don't override it here (dropped rather than mapped to a
# fixed label). See tree_builder.py: a None value falls through to "keep
# the block type inherited from the caller".
BLOCK_TYPE_BY_FIELD = {k: v for k, v in BLOCK_TYPE_BY_FIELD.items() if v is not None}

BLOCK_TYPE_BY_CHILD_TYPE = {
    ("try_statement", "except_clause"): "exception_handler",
    ("try_statement", "else_clause"): "try_else_branch",
    ("try_statement", "finally_clause"): "finally_block",
    ("for_statement", "else_clause"): "loop_else_branch",
    ("while_statement", "else_clause"): "loop_else_branch",
}

CALL_NODE_TYPES = frozenset({"call"})


def _call_name_of(node) -> Optional[str]:
    func = node.child_by_field_name("function")
    if func is None:
        return None
    return func.text.decode("utf-8", errors="replace")


def _lhs_identifiers_of(node) -> List[object]:
    target = node
    if node.type == "expression_statement" and node.named_child_count == 1:
        inner = node.named_children[0]
        if inner.type in ("assignment", "augmented_assignment"):
            target = inner
    if target.type not in ("assignment", "augmented_assignment"):
        return []
    left = target.child_by_field_name("left")
    if left is None:
        return []
    if left.type == "identifier":
        return [left]
    return [c for c in left.named_children if c.type == "identifier"]


# Category D sink signatures, transcribed verbatim from context.md.
SINK_FLAGS = {
    "is_process_exec": SinkFlag(
        exact=frozenset({"os.system"}),
        suffix=frozenset({".run", ".Popen", ".call"}),
        substring=frozenset({"subprocess."}),
    ),
    "is_db_query": SinkFlag(suffix=frozenset({".execute", ".raw"})),
    "is_dynamic_eval": SinkFlag(exact=frozenset({"eval", "exec"})),
    "is_deserialization": SinkFlag(exact=frozenset({"pickle.loads", "yaml.load"})),
    "is_file_io": SinkFlag(
        exact=frozenset({"open", "os.remove"}),
        substring=frozenset({"shutil."}),
    ),
    "is_network_call": SinkFlag(substring=frozenset({"requests.", "urllib."})),
    "is_output_render": SinkFlag(exact=frozenset({"render_template_string"})),
}

# Category E sanitizer signatures, transcribed verbatim from context.md.
SANITIZER_NAMES = SinkFlag(exact=frozenset({"shlex.quote", "bleach.clean"}))

CONCAT_OR_FORMAT_NODE_TYPES = frozenset({"binary_expression", "interpolation"})  # f-strings hold "interpolation" children
FORMAT_CALL_SIGNATURE = SinkFlag(suffix=frozenset({".format"}))
# Known gap (documented, not implemented): "%"-style formatting ("%s" % x)
# is not detected — distinguishing it from ordinary modulo arithmetic would
# need operand-type inspection this v1 doesn't attempt.

STDLIB_PREFIXES = frozenset({
    "os", "sys", "re", "json", "subprocess", "io", "time", "itertools",
    "collections", "typing", "pathlib", "shutil", "urllib", "http", "socket",
    "pickle", "logging", "functools", "hashlib", "shlex", "glob",
})


def _refine_statement_type(node) -> Optional[str]:
    if node.type != "expression_statement" or node.named_child_count != 1:
        return None
    inner = node.named_children[0]
    if inner.type in ("assignment", "augmented_assignment"):
        return "assign"
    if inner.type == "call":
        return "call_expr"
    return "expr_stmt"


SCHEMA = LanguageFeatureSchema(
    language="python",
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
    stdlib_prefixes=STDLIB_PREFIXES,
    identifier_node_type="identifier",
    concat_or_format_node_types=CONCAT_OR_FORMAT_NODE_TYPES,
    concat_operator="+",
    format_call_signature=FORMAT_CALL_SIGNATURE,
)
