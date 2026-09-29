"""
JavaScript (and TypeScript, which reuses this schema — see langs/__init__.py)
feature schema. Grounded empirically against tree-sitter-javascript 0.25.0.
`statement_block` holds statements directly (no extra wrapper, like Python).
`catch_clause`/`finally_clause` attach to try_statement via dedicated fields
(`handler`/`finalizer`) since JS allows at most one of each — unlike
Python's except/finally, which repeat and so have no field name.
"""

from typing import List, Optional

from .base import LanguageFeatureSchema, SinkFlag

STATEMENT_NODE_TYPES = frozenset({
    "expression_statement", "if_statement", "for_statement", "for_in_statement",
    "while_statement", "do_statement", "switch_statement", "try_statement",
    "throw_statement", "return_statement", "break_statement", "continue_statement",
    "import_statement", "export_statement", "function_declaration",
    "variable_declaration", "lexical_declaration", "labeled_statement",
})

TRANSPARENT_NODE_TYPES = frozenset({
    "statement_block", "else_clause", "catch_clause", "finally_clause",
    "switch_body", "switch_case", "switch_default",
})

STATEMENT_TYPE_MAP = {
    "if_statement": "if",
    "for_statement": "for",
    "for_in_statement": "for",
    "while_statement": "while",
    "do_statement": "do_while",
    "switch_statement": "switch",
    "try_statement": "try_catch",
    "throw_statement": "throw_raise",
    "return_statement": "return",
    "break_statement": "break",
    "continue_statement": "continue",
    "import_statement": "import",
    "export_statement": "export",
    "function_declaration": "function_def",
    "variable_declaration": "assign",
    "lexical_declaration": "assign",
    "labeled_statement": "label",
}

BLOCK_TYPE_BY_FIELD = {
    ("if_statement", "consequence"): "if_true_branch",
    ("if_statement", "alternative"): "if_false_branch",
    ("for_statement", "body"): "loop_body",
    ("for_in_statement", "body"): "loop_body",
    ("while_statement", "body"): "loop_body",
    ("do_statement", "body"): "loop_body",
    ("function_declaration", "body"): "function_body",
    ("try_statement", "body"): "try_body",
    ("try_statement", "handler"): "exception_handler",
    ("try_statement", "finalizer"): "finally_block",
}

BLOCK_TYPE_BY_CHILD_TYPE = {
    ("switch_body", "switch_case"): "switch_case",
    ("switch_body", "switch_default"): "switch_case",
}

CALL_NODE_TYPES = frozenset({"call_expression", "new_expression"})


def _call_name_of(node) -> Optional[str]:
    func = node.child_by_field_name("function")
    if func is None:
        func = node.child_by_field_name("constructor")  # `new Foo(...)`
    if func is None:
        return None
    return func.text.decode("utf-8", errors="replace")


def _lhs_identifiers_of(node) -> List[object]:
    if node.type in ("variable_declaration", "lexical_declaration"):
        idents = []
        for declarator in node.named_children:
            if declarator.type == "variable_declarator":
                name = declarator.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    idents.append(name)
        return idents
    if node.type == "expression_statement" and node.named_child_count == 1:
        inner = node.named_children[0]
        if inner.type == "assignment_expression":
            left = inner.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                return [left]
    return []


# Category D sink signatures, transcribed verbatim from context.md.
SINK_FLAGS = {
    "is_process_exec": SinkFlag(exact=frozenset({
        "child_process.exec", "child_process.execSync", "child_process.spawn",
    })),
    "is_db_query": SinkFlag(suffix=frozenset({".query"})),
    "is_dynamic_eval": SinkFlag(exact=frozenset({"eval", "Function"})),
    "is_deserialization": SinkFlag(exact=frozenset({"JSON.parse"})),
    "is_file_io": SinkFlag(substring=frozenset({"fs."})),
    "is_network_call": SinkFlag(
        exact=frozenset({"fetch", "http.request"}),
        substring=frozenset({"axios."}),
    ),
    "is_output_render": SinkFlag(),  # handled via output_render_text_patterns below
}

# Category E sanitizer signatures, transcribed verbatim from context.md.
SANITIZER_NAMES = SinkFlag(exact=frozenset({"DOMPurify.sanitize", "encodeURIComponent"}))

CONCAT_OR_FORMAT_NODE_TYPES = frozenset({"binary_expression", "template_string"})
FORMAT_CALL_SIGNATURE = SinkFlag()  # JS has no dedicated format-call idiom distinct from template_string

STDLIB_PREFIXES = frozenset({"JSON", "Math", "console", "fs", "path", "http", "https", "crypto", "util"})

OUTPUT_RENDER_TEXT_PATTERNS = frozenset({".innerHTML"})


def _refine_statement_type(node) -> Optional[str]:
    if node.type != "expression_statement" or node.named_child_count != 1:
        return None
    inner = node.named_children[0]
    if inner.type == "assignment_expression":
        return "assign"
    if inner.type == "call_expression":
        return "call_expr"
    return "expr_stmt"


SCHEMA = LanguageFeatureSchema(
    language="javascript",
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
    output_render_text_patterns=OUTPUT_RENDER_TEXT_PATTERNS,
)
