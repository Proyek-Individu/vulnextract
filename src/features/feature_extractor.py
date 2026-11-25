"""
Converts one labeled StatementNode into a flat StatementRecord (context.md's
categories A-F). Categories A/B/C/F are purely structural (derived directly
from the tree + row metadata). Categories D (sinks) and E (guard/sanitizer)
match against the signature dictionaries in features/langs/*.py, which are
transcribed verbatim from context.md's own per-flag function-name lists —
and are, by context.md's own admission, inherently incomplete heuristics,
not taint tracking.
"""

import ast as py_ast
import re
from typing import Dict, List, Optional

from .langs.base import LanguageFeatureSchema, leaf_token_count
from .models import StatementRecord
from .tree_builder import StatementNode, local_scope_nodes

COMPOUND_STATEMENT_TYPES = frozenset({
    "if", "for", "while", "do_while", "try_catch", "switch", "switch_case", "catch",
    "function_def", "decorated_def", "with",
})
CYCLOMATIC_STATEMENT_TYPES = frozenset({"if", "for", "while", "do_while", "switch_case", "catch"})
TRIVIAL_STATEMENT_TYPES = frozenset({
    "pass", "break", "continue", "fallthrough", "goto", "label", "import", "global", "global_decl",
    "nonlocal", "unset", "receive",
})

_LITERAL_NODE_TYPES = frozenset({
    "int_literal", "float_literal", "rune_literal", "imaginary_literal", "interpreted_string_literal",
    "raw_string_literal", "true", "false", "nil", "integer", "float", "string", "boolean", "null",
    "none", "integer_literal", "string_literal", "number", "regex", "template_string", "encapsed_string",
})

_QUALIFIER_SPLIT_RE = re.compile(r"->|::|\.")


def _stdlib_or_third_party(module: str, schema: LanguageFeatureSchema) -> str:
    if module.startswith("node:"):
        module = module[len("node:"):]
    first = module.split(".", 1)[0].split("/", 1)[0].lower()
    if first in {prefix.lower() for prefix in schema.stdlib_prefixes}:
        return "stdlib"
    return "third_party"


def _imported_call_kinds(node, schema: LanguageFeatureSchema) -> Dict[str, str]:
    root = node
    while root.parent is not None:
        root = root.parent
    source = root.text.decode("utf-8", errors="replace")
    found: Dict[str, str] = {}
    if schema.language == "python":
        try:
            parsed = py_ast.parse(source)
        except SyntaxError:
            return found
        for item in py_ast.walk(parsed):
            if isinstance(item, py_ast.Import):
                for alias in item.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    found[local] = _stdlib_or_third_party(alias.name, schema)
            elif isinstance(item, py_ast.ImportFrom) and item.module:
                kind = _stdlib_or_third_party(item.module, schema)
                for alias in item.names:
                    found[alias.asname or alias.name] = kind
    elif schema.language in {"javascript", "typescript"}:
        for match in re.finditer(r"\bimport\s+([^;\n]+?)\s+from\s+['\"]([^'\"]+)['\"]", source):
            bindings, module = match.groups()
            kind = _stdlib_or_third_party(module, schema)
            default = bindings.split(",", 1)[0].strip()
            if default and not default.startswith("{") and not default.startswith("*"):
                found[default] = kind
            for alias in re.findall(r"\*\s+as\s+([\w$]+)|([\w$]+)(?:\s+as\s+([\w$]+))?", bindings):
                local = alias[0] or alias[2] or alias[1]
                if local and local not in {"type", "as"}:
                    found[local] = kind
        for local, module in re.findall(
            r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", source
        ):
            found[local] = _stdlib_or_third_party(module, schema)
    elif schema.language == "go":
        for alias, module in re.findall(
            r"(?m)^\s*(?:(\w+)\s+)?['\"]([^'\"]+)['\"]", source
        ):
            local = alias or module.rstrip("/").rsplit("/", 1)[-1]
            found[local] = _stdlib_or_third_party(module, schema)
    elif schema.language == "php":
        for name, alias in re.findall(
            r"(?mi)^\s*use\s+([\\\w]+)(?:\s+as\s+(\w+))?\s*;", source
        ):
            local = alias or name.rsplit("\\", 1)[-1]
            found[local] = "third_party"
    return found


def _defined_call_names(node, schema: LanguageFeatureSchema):
    root = node
    while root.parent is not None:
        root = root.parent
    function_types = {
        "go": {"function_declaration", "method_declaration"},
        "python": {"function_definition"},
        "javascript": {"function_declaration", "method_definition"},
        "typescript": {"function_declaration", "method_definition"},
        "php": {"function_definition", "method_declaration"},
    }.get(schema.language, set())
    names = set()
    for item in _walk_ast(root):
        if item.type not in function_types:
            continue
        name = item.child_by_field_name("name")
        if name is not None:
            names.add(name.text.decode("utf-8", errors="replace"))
    return names


def _call_target_kind(top_level_call_name: str, schema: LanguageFeatureSchema, ast_node=None) -> str:
    if not top_level_call_name:
        return "none"
    imported = _imported_call_kinds(ast_node, schema) if ast_node is not None else {}
    defined = _defined_call_names(ast_node, schema) if ast_node is not None else set()
    parts = _QUALIFIER_SPLIT_RE.split(top_level_call_name, maxsplit=1)
    prefix = parts[0]
    if prefix in imported:
        return imported[prefix]
    if top_level_call_name in defined or prefix in defined:
        return "user_defined"
    if len(parts) == 1:
        if top_level_call_name in schema.stdlib_call_names:
            return "stdlib"
        return "user_defined"
    if prefix.lower() in {"self", "this", "$this"}:
        return "user_defined"
    if prefix in schema.stdlib_call_names:
        return "stdlib"
    return _stdlib_or_third_party(prefix, schema)


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
    if node.parent_block_type != "exception_handler":
        return False
    # Catch/except clause rows are themselves part of the handler; their
    # immediate body statements are also marked, while deeper descendants are
    # only covered by inside_error_handler.
    return (
        parent.statement_type == "catch"
        or (node.statement_type == "catch" and parent.statement_type == "try_catch")
    )


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
        if n.type in {"binary_expression", "binary_operator"}:
            operator = n.child_by_field_name("operator")
            operator_text = operator.text.decode("utf-8", errors="replace") if operator is not None else ""
            if schema.concat_operator and operator_text == schema.concat_operator:
                if schema.language == "php":
                    return True
                if operator_text == "+" and any(
                    descendant.type in {
                        "string", "string_literal", "interpreted_string_literal",
                        "raw_string_literal", "template_string", "encapsed_string",
                    }
                    for descendant in _walk_ast(n)
                ):
                    return True
            if schema.language == "python" and operator_text == "%":
                left = n.child_by_field_name("left")
                if left is not None and any(child.type == "string" for child in _walk_ast(left)):
                    return True
        elif n.type == "template_string":
            if any(child.type == "template_substitution" for child in _walk_ast(n)):
                return True
        elif n.type in schema.concat_or_format_node_types:
            return True  # presence of a template/interpolated-string node itself counts
    return any(schema.format_call_signature.matches(name) for name in call_names)


def _walk_ast(node):
    yield node
    for child in node.children:
        yield from _walk_ast(child)


def extract_features(
    node: StatementNode,
    id_to_node: Dict[str, StatementNode],
    schema: LanguageFeatureSchema,
    language: str,
    row_meta: Dict[str, str],
    origin: str = "vulnerable",
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
    call_target_spans = set()
    for call in all_calls:
        function = call.child_by_field_name("function")
        if function is None:
            continue
        if function.type in {"identifier", "name"}:
            call_target_spans.add((function.start_byte, function.end_byte))
        else:
            for field_name in ("property", "field", "attribute", "name"):
                terminal = function.child_by_field_name(field_name)
                if terminal is not None:
                    call_target_spans.add((terminal.start_byte, terminal.end_byte))
    num_variables_used = sum(
        1 for identifier in all_identifiers
        if (identifier.start_byte, identifier.end_byte) not in defined_spans
        and (identifier.start_byte, identifier.end_byte) not in call_target_spans
    )

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
        line_start=line_start - node.source_line_offset,
        line_end=line_end - node.source_line_offset,
        num_source_lines=line_end - line_start + 1,
        raw_text=raw_text,
        token_count=leaf_token_count(ast),
        char_length=len(raw_text),
        num_calls=len(all_calls),
        top_level_call_name=top_level_call_name,
        call_target_kind=_call_target_kind(top_level_call_name, schema, ast),
        num_variables_defined=len(defined),
        num_variables_used=num_variables_used,
        guard_count=_guard_count(node, id_to_node),
        inside_error_handler=_inside_error_handler(node, id_to_node, schema),
        is_error_handling_statement=_is_error_handling_statement(node, id_to_node),
        sanitization_call_detected=_sanitization_call_detected(node, id_to_node, schema),
        is_compound=bool(node.children) or node.statement_type in COMPOUND_STATEMENT_TYPES,
        num_direct_children=len(node.children),
        cyclomatic_contribution=(
            sum(1 for child in ast.named_children if child.type in {"communication_case", "expression_case", "type_case", "default_case"})
            if schema.language == "go" and node.statement_type == "switch"
            else 1 if node.statement_type in CYCLOMATIC_STATEMENT_TYPES else 0
        ),
        label=node.label,
        origin=origin,
    )

    record.uses_string_concat_or_format = _uses_string_concat_or_format(node, call_names, schema)
    record.uses_only_literals = (
        num_variables_used == 0
        and node.statement_type not in TRIVIAL_STATEMENT_TYPES
        and (
            record.num_calls > 0
            or node.statement_type == "assign"
            or any(
                descendant.type in _LITERAL_NODE_TYPES
                for descendant in local_scope_nodes(node, lambda _n: True)
            )
        )
    )

    for flag_name, flag in schema.sink_flags.items():
        if any(flag.matches(name) for name in call_names):
            setattr(record, flag_name, True)

    # is_output_render special cases that aren't call-shaped (PHP echo,
    # JS `el.innerHTML =`) — see langs/*.py's SINK_FLAGS/output_render_text_patterns comments.
    if node.statement_type == "echo":
        record.is_output_render = not any(
            name.rsplit("->", 1)[-1].rsplit("::", 1)[-1] in {"htmlspecialchars", "htmlentities"}
            for name in call_names
        )
    if any(pattern in raw_text for pattern in schema.output_render_text_patterns):
        record.is_output_render = not any(name == "DOMPurify.sanitize" for name in call_names)
    if schema.language == "php":
        php_include = any(
            descendant.type in {"include_expression", "require_expression"}
            for descendant in local_scope_nodes(node, lambda _n: True)
        )
        if php_include:
            record.is_file_io = True
            record.is_dynamic_eval = True
        if any(
            descendant.type == "shell_command_expression"
            for descendant in local_scope_nodes(node, lambda _n: True)
        ):
            record.is_process_exec = True

    return record
