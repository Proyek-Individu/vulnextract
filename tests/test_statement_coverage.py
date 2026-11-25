import unittest

import pandas as pd

from src.extractors import get_extractor
from src.feature_pipeline import FeatureExtractionPipeline
from src.features.feature_extractor import extract_features
from src.features.langs import get_schema
from src.features.tree_builder import build_statement_tree, flatten


class TestNewStatementNodeMappings(unittest.TestCase):
    @staticmethod
    def _tree(language, source):
        roots, source_bytes = build_statement_tree(source, language, get_schema(language), "test")
        return roots, source_bytes, get_schema(language)

    def test_php_global_and_unset_statements(self):
        roots, source, schema = self._tree(
            "php",
            "function f() {\n    global $mode;\n    unset($mode);\n}",
        )
        self.assertEqual([node.statement_type for node in roots], ["global_decl", "unset"])
        self.assertEqual([node.ast_node.type for node in roots], ["global_declaration", "unset_statement"])
        self.assertEqual([node.ast_node.start_point[0] + 1 for node in roots], [2, 3])
        self.assertTrue(all(node.parent_block_type == "function_body" for node in roots))

    def test_go_receive_case_head_is_not_a_statement_row(self):
        roots, _source, _schema = self._tree(
            "go",
            "func f(ticker *time.Ticker) {\n    select {\n    case <-ticker.C:\n        consume()\n    }\n}",
        )
        flat = flatten(roots)
        schema = get_schema("go")
        self.assertIn("receive_statement", schema.statement_node_types)
        self.assertEqual(schema.statement_type_map["receive_statement"], "receive")
        self.assertEqual([node.statement_type for node in flat], ["switch", "call_expr"])
        self.assertFalse(any(node.ast_node.type == "receive_statement" for node in flat))

    def test_python_decorator_row_includes_decorator_lines(self):
        roots, source, _schema = self._tree(
            "python",
            "def serializable():\n    @staticmethod\n    def unpackb(data: bytes) -> Any:\n        return my_class(**my_unpackb(data))\n",
        )
        self.assertEqual(roots[0].ast_node.type, "decorated_definition")
        self.assertEqual(roots[0].statement_type, "decorated_def")
        self.assertEqual(roots[0].ast_node.start_point[0] + 1, 2)
        self.assertEqual(roots[0].ast_node.end_point[0] + 1, 4)
        self.assertEqual(
            source[roots[0].ast_node.start_byte:roots[0].ast_node.end_byte].decode(),
            "@staticmethod\n    def unpackb(data: bytes) -> Any:\n        return my_class(**my_unpackb(data))",
        )
        self.assertEqual(roots[0].children[0].parent_statement_id, roots[0].statement_id)

    def test_python_future_import_maps_to_import(self):
        roots, _source, _schema = self._tree(
            "python",
            "from __future__ import annotations\n\nimport re\nimport socket\n",
        )
        self.assertEqual(roots[0].ast_node.type, "future_import_statement")
        self.assertEqual(roots[0].statement_type, "import")

    def test_switch_cases_and_catches_each_add_cyclomatic_contribution(self):
        roots, _source, schema = self._tree(
            "javascript",
            "function f(x) { switch (x) { case 1: first(); break; default: second(); } "
            "try { third(); } catch (e) { fourth(); } }",
        )
        flat = flatten(roots)
        records = {
            node.statement_type + ":" + node.ast_node.type + ":" + node.ast_node.text.decode():
                extract_features(node, {n.statement_id: n for n in flat}, schema, "javascript", {})
            for node in flat
        }
        cases = [r for r in records.values() if r.statement_type == "switch_case"]
        catches = [r for r in records.values() if r.statement_type == "catch"]
        self.assertEqual(len(cases), 2)
        self.assertEqual([r.cyclomatic_contribution for r in cases], [1, 1])
        self.assertEqual(len(catches), 1)
        self.assertEqual(catches[0].cyclomatic_contribution, 1)
        cleanup = next(
            r for key, r in records.items()
            if key.startswith("call_expr:") and "fourth();" in key
        )
        self.assertTrue(cleanup.is_error_handling_statement)

    def test_typescript_wrapping_preserves_original_line_numbers_and_ids(self):
        roots, _source, schema = self._tree(
            "typescript", "private foo(): number {\n  return 1\n}"
        )
        record = extract_features(roots[0], {roots[0].statement_id: roots[0]}, schema, "typescript", {})
        self.assertEqual(record.line_start, 2)
        self.assertEqual(record.line_end, 2)
        self.assertIn(":2-2#", record.statement_id)

    def test_python_percent_format_and_literal_return(self):
        roots, _source, schema = self._tree("python", 'def f(value):\n    return "%s" % value\n')
        record = extract_features(roots[0], {roots[0].statement_id: roots[0]}, schema, "python", {})
        self.assertTrue(record.uses_string_concat_or_format)
        self.assertFalse(record.uses_only_literals)

        literal_roots, _source, literal_schema = self._tree("python", "def g():\n    return 1\n")
        literal = extract_features(
            literal_roots[0], {literal_roots[0].statement_id: literal_roots[0]}, literal_schema, "python", {}
        )
        self.assertTrue(literal.uses_only_literals)

    def test_call_target_and_variable_usage_exclude_callee_name(self):
        roots, _source, schema = self._tree("python", "def f(value):\n    return len(value)\n")
        record = extract_features(roots[0], {roots[0].statement_id: roots[0]}, schema, "python", {})
        self.assertEqual(record.call_target_kind, "stdlib")
        self.assertEqual(record.num_variables_used, 1)

    def test_call_target_uses_import_alias_and_local_function(self):
        roots, _source, schema = self._tree(
            "python",
            "import requests as rq\n"
            "def f(value):\n"
            "    def custom(item):\n        return item\n"
            "    return custom(rq.get(value))\n",
        )
        flat = flatten(roots)
        return_node = next(
            node for node in flat if node.statement_type == "return" and "custom(rq.get" in node.ast_node.text.decode()
        )
        record = extract_features(return_node, {n.statement_id: n for n in flat}, schema, "python", {})
        self.assertEqual(record.top_level_call_name, "custom")
        self.assertEqual(record.call_target_kind, "user_defined")

        imported_roots, _source, imported_schema = self._tree(
            "python", "from requests import get as fetch\ndef f(url):\n    return fetch(url)\n"
        )
        imported_record = extract_features(
            imported_roots[0], {n.statement_id: n for n in flatten(imported_roots)},
            imported_schema, "python", {}
        )
        self.assertEqual(imported_record.call_target_kind, "third_party")

    def test_go_select_case_branches_contribute_to_complexity(self):
        roots, _source, schema = self._tree(
            "go",
            "func f(ch chan int) {\n select {\n case <-ch:\n  a()\n case ch <- 1:\n  b()\n }\n}",
        )
        select_node = next(node for node in flatten(roots) if node.statement_type == "switch")
        record = extract_features(
            select_node, {node.statement_id: node for node in flatten(roots)}, schema, "go", {}
        )
        self.assertEqual(record.cyclomatic_contribution, 2)

    def test_node_builtin_import_alias_is_classified_as_stdlib(self):
        roots, _source, schema = self._tree(
            "javascript",
            "const cp = require('node:child_process');\nfunction f(cmd) { cp.exec(cmd); }",
        )
        record = extract_features(roots[0], {n.statement_id: n for n in flatten(roots)}, schema, "javascript", {})
        self.assertEqual(record.top_level_call_name, "cp.exec")
        self.assertEqual(record.call_target_kind, "stdlib")

    def test_concat_flags_avoid_numeric_plus_and_static_templates(self):
        numeric, _source, python_schema = self._tree("python", "def f(a, b):\n    return a + b\n")
        numeric_record = extract_features(
            numeric[0], {numeric[0].statement_id: numeric[0]}, python_schema, "python", {}
        )
        self.assertFalse(numeric_record.uses_string_concat_or_format)

        string, _source, python_schema = self._tree("python", 'def f(a):\n    return "x" + a\n')
        string_record = extract_features(
            string[0], {string[0].statement_id: string[0]}, python_schema, "python", {}
        )
        self.assertTrue(string_record.uses_string_concat_or_format)

        static, _source, js_schema = self._tree("javascript", "function f() { return `constant`; }")
        static_record = extract_features(
            static[0], {static[0].statement_id: static[0]}, js_schema, "javascript", {}
        )
        self.assertFalse(static_record.uses_string_concat_or_format)

    def test_php_safe_echo_backtick_and_include_flags(self):
        roots, _source, schema = self._tree(
            "php",
            "function f($value, $file) {\n"
            "    echo htmlspecialchars($value);\n"
            "    echo $value;\n"
            "    $result = `id`;\n"
            "    include $file;\n"
            "}",
        )
        flat = flatten(roots)
        records = [
            extract_features(node, {n.statement_id: n for n in flat}, schema, "php", {})
            for node in flat
        ]
        echo_records = [record for record in records if record.statement_type == "echo"]
        self.assertEqual([record.is_output_render for record in echo_records], [False, True])
        backtick = next(record for record in records if "`id`" in record.raw_text)
        self.assertTrue(backtick.is_process_exec)
        include = next(record for record in records if "include" in record.raw_text)
        self.assertTrue(include.is_file_io)
        self.assertTrue(include.is_dynamic_eval)

    def test_unknown_statement_nodes_are_counted_and_logged_once(self):
        frame = pd.DataFrame([{
            "cve_id": "CVE-TEST-1",
            "language": "javascript",
            "vulnerable_code": "function f(obj) { with (obj) { run(); } after(); }",
            "fixed_code": "",
            "vulnerability_type": "test",
        }])
        with self.assertLogs("src.feature_pipeline", level="WARNING") as logs:
            output, stats = FeatureExtractionPipeline().process_dataframe(frame)
        self.assertEqual(stats.unknown_statement_nodes, {"javascript": {"with_statement": 1}})
        self.assertEqual(output["raw_text"].tolist(), ["after();"])
        self.assertEqual(sum("with_statement" in line for line in logs.output), 1)

    def test_unknown_typescript_statement_nodes_are_counted(self):
        frame = pd.DataFrame([{
            "cve_id": "CVE-TEST-2",
            "language": "typescript",
            "vulnerable_code": "function f(obj: any) { with (obj) { run(); } after(); }",
            "fixed_code": "",
            "vulnerability_type": "test",
        }])
        with self.assertLogs("src.feature_pipeline", level="WARNING"):
            _output, stats = FeatureExtractionPipeline().process_dataframe(frame)
        self.assertEqual(stats.unknown_statement_nodes, {"typescript": {"with_statement": 1}})

    def test_schema_node_names_exist_in_the_language_grammars(self):
        for language in ("go", "python", "javascript", "typescript", "php"):
            extractor = get_extractor(language)
            parser = extractor.resolve_statement_parser("") if language == "php" else extractor._statement_parser
            grammar = parser.language
            grammar_names = {
                grammar.node_kind_for_id(i)
                for i in range(grammar.node_kind_count)
                if grammar.node_kind_is_named(i)
            }
            schema = get_schema(language)
            schema_names = (
                set(schema.statement_node_types)
                | set(schema.transparent_node_types)
                | set(schema.statement_type_map)
            )
            self.assertFalse(schema_names - grammar_names, (language, sorted(schema_names - grammar_names)))


class TestBodyStatementLineCoverage(unittest.TestCase):
    def test_noncomment_body_code_lines_are_covered_for_each_language(self):
        examples = {
            "go": "func f() {\n    x := 1 // inline\n    if x > 0 {\n        x++\n    }\n}",
            "python": "def f():\n    # comment\n    x = 1\n    if x > 0:\n        x += 1\n    return x\n",
            "javascript": "function f() {\n  const x = 1;\n  if (x > 0) {\n    return x;\n  }\n}",
            "typescript": "function f(): number {\n  const x = 1;\n  if (x > 0) {\n    return x;\n  }\n  return 0;\n}",
            "php": "function f() {\n    $x = 1;\n    if ($x > 0) {\n        return $x;\n    }\n}",
        }
        for language, code in examples.items():
            with self.subTest(language=language):
                roots, _source, _schema = self._tree(language, code)
                spans = [
                    (node.ast_node.start_point[0] + 1, node.ast_node.end_point[0] + 1)
                    for node in flatten(roots)
                ]
                lines = code.splitlines()
                body_lines = {
                    i + 1 for i, line in enumerate(lines)
                    if line.strip()
                    and not line.lstrip().startswith(("#", "//", "/*", "*", "*/"))
                    and line.strip() not in {"{", "}", ";"}
                    and not (i == 0 and ("function " in line or line.lstrip().startswith(("def ", "func "))))
                }
                uncovered = [
                    line for line in sorted(body_lines)
                    if not any(start <= line <= end for start, end in spans)
                ]
                self.assertEqual(uncovered, [])

    @staticmethod
    def _tree(language, source):
        roots, source_bytes = build_statement_tree(source, language, get_schema(language), "test")
        return roots, source_bytes, get_schema(language)


if __name__ == "__main__":
    unittest.main()
