"""
Go language feature schema. Grounded empirically against tree-sitter-go
0.25.0 (see this session's grounding dumps): if_statement.alternative is
either a "block" (plain else) or another "if_statement" (else-if chain, no
wrapper node); Go has no try/catch, so `if err != nil { ... }` is detected
by shape as a stand-in exception handler per context.md's own note.
"""

import re
from typing import List, Optional

from .base import LanguageFeatureSchema, SinkFlag, node_text

STATEMENT_NODE_TYPES = frozenset({
    "short_var_declaration", "assignment_statement", "var_declaration", "const_declaration",
    "inc_statement", "dec_statement", "expression_statement", "return_statement",
    "if_statement", "for_statement", "expression_switch_statement", "type_switch_statement",
    "select_statement", "go_statement", "defer_statement", "break_statement",
    "continue_statement", "labeled_statement", "fallthrough_statement", "send_statement",
    "goto_statement",
})

TRANSPARENT_NODE_TYPES = frozenset({
    "block", "statement_list", "expression_case", "default_case", "type_case",
    "communication_case",
})

STATEMENT_TYPE_MAP = {
    "short_var_declaration": "assign",
    "assignment_statement": "assign",
    "var_declaration": "assign",
    "const_declaration": "assign",
    "inc_statement": "assign",
    "dec_statement": "assign",
    "expression_statement": "call_expr",
    "return_statement": "return",
    "if_statement": "if",
    "for_statement": "for",
    "expression_switch_statement": "switch",
    "type_switch_statement": "switch",
    "select_statement": "switch",
    "go_statement": "go_routine",
    "defer_statement": "defer",
    "break_statement": "break",
    "continue_statement": "continue",
    "labeled_statement": "label",
    "fallthrough_statement": "fallthrough",
    "send_statement": "send",
    "goto_statement": "goto",
}

BLOCK_TYPE_BY_FIELD = {
    ("if_statement", "consequence"): "if_true_branch",
    ("if_statement", "alternative"): "if_false_branch",
    ("for_statement", "body"): "loop_body",
    ("function_declaration", "body"): "function_body",
    ("method_declaration", "body"): "function_body",
}

BLOCK_TYPE_BY_CHILD_TYPE = {
    ("expression_switch_statement", "expression_case"): "switch_case",
    ("expression_switch_statement", "default_case"): "switch_case",
    ("type_switch_statement", "type_case"): "switch_case",
    ("type_switch_statement", "default_case"): "switch_case",
    ("select_statement", "communication_case"): "switch_case",
}

CALL_NODE_TYPES = frozenset({"call_expression"})


def _call_name_of(node) -> Optional[str]:
    func = node.child_by_field_name("function")
    if func is None:
        return None
    return func.text.decode("utf-8", errors="replace")


def _lhs_identifiers_of(node) -> List[object]:
    if node.type in ("short_var_declaration", "assignment_statement"):
        left = node.child_by_field_name("left")
        if left is None:
            return []
        return [c for c in left.named_children if c.type == "identifier"]
    if node.type in ("var_declaration", "const_declaration"):
        idents: List[object] = []
        for spec in node.named_children:
            if spec.type == "var_spec":
                name = spec.child_by_field_name("name")
                if name is not None:
                    idents.append(name)
        return idents
    return []


_ERR_NAME_RE = re.compile(r"(?i)\berr\w*$")


def _is_error_guard_condition(node) -> bool:
    """Detects Go's `if err != nil` shape: a binary_expression whose left
    operand looks like an error variable and operator/right side is `!= nil`.
    Heuristic per context.md's note that Go has no try/catch."""
    if node.type != "binary_expression":
        return False
    operator = node.child_by_field_name("operator")
    right = node.child_by_field_name("right")
    left = node.child_by_field_name("left")
    if operator is None or right is None or left is None:
        return False
    if operator.text.decode("utf-8", errors="replace") != "!=":
        return False
    if right.text.decode("utf-8", errors="replace") != "nil":
        return False
    left_text = left.text.decode("utf-8", errors="replace")
    return bool(_ERR_NAME_RE.search(left_text))


# Category D sink signatures, transcribed verbatim from context.md.
SINK_FLAGS = {
    "is_process_exec": SinkFlag(exact=frozenset({"exec.Command", "exec.CommandContext"})),
    "is_db_query": SinkFlag(
        suffix=frozenset({".Query", ".Exec", ".QueryRow", ".Raw"}),
    ),
    "is_dynamic_eval": SinkFlag(),  # context.md: "biasanya false" for Go
    "is_deserialization": SinkFlag(
        exact=frozenset({"json.Unmarshal"}),
        substring=frozenset({"gob."}),
    ),
    "is_file_io": SinkFlag(
        exact=frozenset({"os.Open", "os.Remove", "os.ReadFile"}),
        substring=frozenset({"ioutil."}),
    ),
    "is_network_call": SinkFlag(
        exact=frozenset({"http.Get", "http.Post", "http.NewRequest"}),
    ),
    "is_output_render": SinkFlag(exact=frozenset({"template.HTML"})),
}

# Category E sanitizer signatures. These functions escape values for
# specific output contexts; a match is a heuristic, not proof that the
# escaped value is the one eventually used by a sink.
SANITIZER_NAMES = SinkFlag(exact=frozenset({
    "html.EscapeString",
    "template.HTMLEscapeString",
    "template.JSEscapeString",
}))

CONCAT_OR_FORMAT_NODE_TYPES = frozenset({"binary_expression"})
FORMAT_CALL_SIGNATURE = SinkFlag(exact=frozenset({"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "fmt.Errorf"}))

STDLIB_PREFIXES = frozenset({
    "fmt", "os", "io", "ioutil", "net", "http", "strings", "strconv", "time",
    "context", "errors", "sync", "bytes", "encoding", "json", "sql", "exec",
    "regexp", "path", "filepath", "log", "reflect", "sort", "gob",
})


def _refine_statement_type(node) -> Optional[str]:
    return None


SCHEMA = LanguageFeatureSchema(
    language="go",
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
    is_error_guard_condition=_is_error_guard_condition,
)
