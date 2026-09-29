"""
Converts one labeled StatementNode into a flat StatementRecord (context.md's
categories A-F). Categories A/B/C/F are purely structural (derived directly
from the tree + row metadata). Categories D (sinks) and E (guard/sanitizer)
match against the signature dictionaries in features/langs/*.py, which are
transcribed verbatim from context.md's own per-flag function-name lists —
and are, by context.md's own admission, inherently incomplete heuristics,
not taint tracking.
"""

import re
from typing import Dict, List, Optional

from .langs.base import LanguageFeatureSchema, leaf_token_count
from .models import StatementRecord
from .tree_builder import StatementNode, local_scope_nodes

COMPOUND_STATEMENT_TYPES = frozenset({
    "if", "for", "while", "do_while", "try_catch", "switch", "function_def", "with",
})
CYCLOMATIC_STATEMENT_TYPES = frozenset({"if", "for", "while", "do_while", "try_catch"})
TRIVIAL_STATEMENT_TYPES = frozenset({
    "pass", "break", "continue", "fallthrough", "goto", "label", "import", "global", "nonlocal",
})

_QUALIFIER_SPLIT_RE = re.compile(r"->|::|\.")


def _call_target_kind(top_level_call_name: str, schema: LanguageFeatureSchema) -> str:
    if not top_level_call_name:
        return "none"
    parts = _QUALIFIER_SPLIT_RE.split(top_level_call_name, maxsplit=1)
    if len(parts) == 1:
        return "user_defined"
    prefix = parts[0]
    return "stdlib" if prefix in schema.stdlib_prefixes else "third_party"


def _is_top_level_call(call, all_calls: List[object]) -> bool:
    for other in all_calls:
        if other is call:
            continue
        if other.start_byte <= call.start_byte and call.end_byte <= other.end_byte:
            return False
    return True


def _local_calls(node: StatementNode, schema: LanguageFeatureSchema) -> List[object]:
    return local_scope_nodes(node, lambda n: n.type in schema.call_node_types)


def _ancestor_chain(node: StatementNode, id_to_node: Dict[str, StatementNode]):
    """Yields (current, parent) pairs walking up from `node` to the root."""
    current = node
    while current.parent_statement_id is not None:
        parent = id_to_node.get(current.parent_statement_id)
        if parent is None:
            return
        yield current, parent
        current = parent


def _guard_count(node: StatementNode, id_to_node: Dict[str, StatementNode]) -> int:
    return sum(1 for _current, parent in _ancestor_chain(node, id_to_node) if parent.statement_type == "if")


def _inside_error_handler(node: StatementNode, id_to_node: Dict[str, StatementNode], schema: LanguageFeatureSchema) -> bool:
    for current, parent in _ancestor_chain(node, id_to_node):
        if current.parent_block_type == "exception_handler":
            return True
        if current.parent_block_type == "if_true_branch" and parent.statement_type == "if":
            condition = parent.ast_node.child_by_field_name("condition")
            if condition is not None and schema.is_error_guard_condition(condition):
                return True
    return False


def _is_error_handling_statement(node: StatementNode, id_to_node: Dict[str, StatementNode]) -> bool:
    if node.parent_statement_id is None:
        return False
    parent = id_to_node.get(node.parent_statement_id)
    if parent is None:
        return False
    return parent.statement_type == "try_catch" and node.parent_block_type == "exception_handler"


def _sanitization_call_detected(node: StatementNode, id_to_node: Dict[str, StatementNode], schema: LanguageFeatureSchema) -> bool:
    current: Optional[StatementNode] = node
    while current is not None:
        for call in _local_calls(current, schema):
            name = schema.call_name_of(call)
            if name and schema.sanitizer_names.matches(name):
                return True
        if current.parent_statement_id is None:
            break
        current = id_to_node.get(current.parent_statement_id)
    return False


def _uses_string_concat_or_format(node: StatementNode, call_names: List[str], schema: LanguageFeatureSchema) -> bool:
    for n in local_scope_nodes(node, lambda n: n.type in schema.concat_or_format_node_types):
        if n.type == "binary_expression" and schema.concat_operator:
            operator = n.child_by_field_name("operator")
            if operator is not None and operator.text.decode("utf-8", errors="replace") == schema.concat_operator:
                return True
        else:
            return True  # presence of a template/interpolated-string node itself counts
    return any(schema.format_call_signature.matches(name) for name in call_names)


def extract_features(
    node: StatementNode,
    id_to_node: Dict[str, StatementNode],
    schema: LanguageFeatureSchema,
    language: str,
    row_meta: Dict[str, str],
) -> StatementRecord:
    ast = node.ast_node
    raw_text = ast.text.decode("utf-8", errors="replace")
    line_start = ast.start_point[0] + 1
    line_end = ast.end_point[0] + 1

    all_calls = _local_calls(node, schema)
    call_names = [schema.call_name_of(c) for c in all_calls]
    call_names = [c for c in call_names if c]

    top_level_calls = sorted((c for c in all_calls if _is_top_level_call(c, all_calls)), key=lambda c: c.start_byte)
    top_level_call_name = ""
    if top_level_calls:
        name = schema.call_name_of(top_level_calls[0])
        top_level_call_name = name or ""

    defined = schema.lhs_identifiers_of(ast)
    defined_spans = {(d.start_byte, d.end_byte) for d in defined}
    all_identifiers = local_scope_nodes(node, lambda n: n.type == schema.identifier_node_type)
    num_variables_used = sum(1 for i in all_identifiers if (i.start_byte, i.end_byte) not in defined_spans)

    record = StatementRecord(
        cve_id=row_meta.get("cve_id", ""),
        vulnerability_type=row_meta.get("vulnerability_type", ""),
        commit_hash=row_meta.get("commit_hash", ""),
        repo=row_meta.get("repo", ""),
        statement_id=node.statement_id,
        parent_statement_id=node.parent_statement_id,
        nesting_depth=node.nesting_depth,
        statement_type=node.statement_type,
        parent_block_type=node.parent_block_type,
        repo_name=row_meta.get("repo", ""),
        file_path=row_meta.get("file", ""),
        function_name=row_meta.get("method", ""),
        language=language,
        line_start=line_start,
        line_end=line_end,
        num_source_lines=line_end - line_start + 1,
        raw_text=raw_text,
        token_count=leaf_token_count(ast),
        char_length=len(raw_text),
        num_calls=len(all_calls),
        top_level_call_name=top_level_call_name,
        call_target_kind=_call_target_kind(top_level_call_name, schema),
        num_variables_defined=len(defined),
        num_variables_used=num_variables_used,
        guard_count=_guard_count(node, id_to_node),
        inside_error_handler=_inside_error_handler(node, id_to_node, schema),
        is_error_handling_statement=_is_error_handling_statement(node, id_to_node),
        sanitization_call_detected=_sanitization_call_detected(node, id_to_node, schema),
        is_compound=bool(node.children) or node.statement_type in COMPOUND_STATEMENT_TYPES,
        num_direct_children=len(node.children),
        cyclomatic_contribution=1 if node.statement_type in CYCLOMATIC_STATEMENT_TYPES else 0,
        label=node.label,
    )

    record.uses_string_concat_or_format = _uses_string_concat_or_format(node, call_names, schema)
    record.uses_only_literals = (
        num_variables_used == 0
        and node.statement_type not in TRIVIAL_STATEMENT_TYPES
        and (record.num_calls > 0 or record.statement_type in ("assign",))
    )

    for flag_name, flag in schema.sink_flags.items():
        if any(flag.matches(name) for name in call_names):
            setattr(record, flag_name, True)

    # is_output_render special cases that aren't call-shaped (PHP echo,
    # JS `el.innerHTML =`) — see langs/*.py's SINK_FLAGS/output_render_text_patterns comments.
    if node.statement_type == "echo":
        record.is_output_render = True
    if any(pattern in raw_text for pattern in schema.output_render_text_patterns):
        record.is_output_render = True

    return record
