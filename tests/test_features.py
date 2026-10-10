"""
Unit tests for the hierarchical statement-level feature pipeline
(src/features/*, src/feature_pipeline.py).
"""

import unittest

import pandas as pd

from src.feature_pipeline import FeatureExtractionPipeline
from src.features.feature_extractor import extract_features
from src.features.labeler import label_statements
from src.features.langs import get_schema
from src.features.tree_builder import build_statement_tree, flatten


def _tree(language, source):
    schema = get_schema(language)
    roots, source_bytes = build_statement_tree(source, language, schema, id_prefix="repo:file:func")
    return roots, source_bytes, schema


class TestTreeBuilder(unittest.TestCase):
    def test_go_statement_list_unwrap(self):
        roots, _src, _schema = _tree("go", """func f() {
\ta := 1
\tb := 2
}""")
        self.assertEqual(len(roots), 2)
        self.assertEqual(roots[0].statement_type, "assign")
        self.assertEqual(roots[0].parent_block_type, "function_body")

    def test_go_if_else_if_else_block_types(self):
        roots, _src, _schema = _tree("go", """func f() {
\tif err != nil {
\t\treturn err
\t} else if x > 0 {
\t\treturn nil
\t} else {
\t\treturn nil
\t}
}""")
        self.assertEqual(len(roots), 1)
        outer_if = roots[0]
        self.assertEqual(outer_if.statement_type, "if")
        self.assertEqual(len(outer_if.children), 2)
        self.assertEqual(outer_if.children[0].parent_block_type, "if_true_branch")
        nested_if = outer_if.children[1]
        self.assertEqual(nested_if.statement_type, "if")
        self.assertEqual(nested_if.parent_block_type, "if_false_branch")
        self.assertEqual(nested_if.children[0].parent_block_type, "if_true_branch")
        self.assertEqual(nested_if.children[1].parent_block_type, "if_false_branch")

    def test_python_elif_treated_as_nested_if(self):
        roots, _src, _schema = _tree("python", "def f(x):\n    if x > 0:\n        return 1\n    elif x < 0:\n        return 2\n")
        self.assertEqual(roots[0].statement_type, "if")
        nested = roots[0].children[1]
        self.assertEqual(nested.statement_type, "if")
        self.assertEqual(nested.parent_block_type, "if_false_branch")

    def test_python_try_except_finally_block_types(self):
        roots, _src, _schema = _tree("python", "def f():\n    try:\n        a()\n    except ValueError:\n        b()\n    finally:\n        c()\n")
        self.assertEqual(roots[0].statement_type, "try_catch")
        block_types = {c.parent_block_type for c in roots[0].children}
        self.assertEqual(block_types, {"try_body", "exception_handler", "finally_block"})

    def test_php_throw_refined_from_expression_statement(self):
        roots, _src, _schema = _tree("php", "function f() {\n    throw new Exception(\"x\");\n}")
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0].statement_type, "throw_raise")

    def test_typescript_tree_builder_and_labeler(self):
        vulnerable = "function f(value: string) { process(value); }"
        fixed = "function f(value: string) { processSafely(value); }"
        roots, v_src, _schema = _tree("typescript", vulnerable)
        fixed_roots, f_src, _schema = _tree("typescript", fixed)

        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0].statement_type, "call_expr")
        label_statements(roots, fixed_roots, v_src, f_src)
        self.assertEqual(roots[0].label, 1)

    def test_unsupported_language_has_no_schema(self):
        # java/rust/c extractors exist (src/extractors/), but context.md scopes
        # this feature pipeline to Go/Python/JS/TS/PHP only — no schema for them.
        self.assertIsNone(get_schema("java"))
        self.assertIsNone(get_schema("rust"))
        self.assertIsNone(get_schema("c"))


class TestLabeler(unittest.TestCase):
    def _label(self, language, vuln, fixed):
        v_roots, v_src, schema = _tree(language, vuln)
        f_roots, f_src, _ = _tree(language, fixed)
        label_statements(v_roots, f_roots, v_src, f_src)
        return v_roots

    def test_fully_unchanged_all_zero(self):
        roots = self._label(
            "python",
            "def f(x):\n    a = 1\n    b = 2\n    return a + b\n",
            "def f(x):\n    a = 1\n    b = 2\n    return a + b\n",
        )
        self.assertTrue(all(n.label == 0 for n in flatten(roots)))

    def test_condition_only_change_labels_if_not_children(self):
        roots = self._label(
            "javascript",
            "function f(x, y) {\n  if (x > 0) {\n    return 1;\n  } else {\n    return 2;\n  }\n}",
            "function f(x, y) {\n  if (x > 0 && y) {\n    return 1;\n  } else {\n    return 2;\n  }\n}",
        )
        self.assertEqual(roots[0].label, 1)
        self.assertTrue(all(c.label == 0 for c in roots[0].children))

    def test_pure_reorder_labels_zero(self):
        roots = self._label(
            "javascript",
            "function f() {\n  a();\n  b();\n}",
            "function f() {\n  b();\n  a();\n}",
        )
        self.assertTrue(all(n.label == 0 for n in roots))

    def test_cosmetic_whitespace_labels_zero(self):
        roots = self._label(
            "javascript",
            "function f() {\n  a();\n  b();\n}",
            "function f() {\n  a();   \n\n  b();\n}",
        )
        self.assertTrue(all(n.label == 0 for n in roots))

    def test_compound_type_change_labels_whole_subtree(self):
        roots = self._label(
            "javascript",
            "function f(x) {\n  if (x) {\n    y();\n  }\n}",
            "function f(x) {\n  x ? y() : null;\n}",
        )
        self.assertTrue(all(n.label == 1 for n in flatten(roots)))

    def test_deep_single_statement_change_isolated(self):
        roots = self._label(
            "python",
            "def f(x):\n    if x > 0:\n        a = 1\n        b = 2\n        return a + b\n    return 0\n",
            "def f(x):\n    if x > 0:\n        a = 1\n        b = 3\n        return a + b\n    return 0\n",
        )
        flat = {n.ast_node.text.decode(): n.label for n in flatten(roots)}
        self.assertEqual(flat["b = 2"], 1)
        self.assertEqual(flat["a = 1"], 0)
        self.assertEqual(flat["return a + b"], 0)
        self.assertEqual(roots[0].label, 0)  # the containing if itself didn't change

    def test_unequal_count_replace_marks_all_changed(self):
        """Anchor case: CVE-2026-8462 (Go, SQL-builder rewrite) — a 4-statement
        vulnerable block collapsed into 1 fixed statement must label all 4
        vulnerable statements as changed, not fabricate positional pairs."""
        roots = self._label(
            "go",
            """func (d validateJsonPathQuery) toSQL() (string, []interface{}) {
\tsb := sqlbuilder.ClickHouse.NewSelectBuilder()
\tsb.Select(fmt.Sprintf("JSON_VALUE('{}', '%s')", sqlbuilder.Escape(d.jsonPath)))

\tsql, args := sb.Build()

\treturn sql, args
}""",
            """func (d validateJsonPathQuery) toSQL() (string, []interface{}) {
\treturn sqlbuilder.Buildf("SELECT JSON_VALUE('{}', %v)", d.jsonPath).
\t\tBuildWithFlavor(sqlbuilder.ClickHouse)
}""",
        )
        self.assertEqual(len(roots), 4)
        self.assertTrue(all(n.label == 1 for n in roots))


class TestFeatureExtractor(unittest.TestCase):
    def test_sink_and_sanitizer_flags_across_languages(self):
        cases = [
            ("go", "is_process_exec", 'func f() { exec.Command("sh") }'),
            ("go", "is_db_query", 'func f() { db.Query("SELECT 1") }'),
            ("go", "is_deserialization", "func f() { json.Unmarshal(data, &value) }"),
            ("go", "is_file_io", 'func f() { os.Open("file.txt") }'),
            ("go", "is_network_call", 'func f() { http.Get("https://example.com") }'),
            ("go", "is_output_render", 'func f() { template.HTML(value) }'),
            ("go", "sanitization_call_detected", 'func f() { html.EscapeString(value) }'),
            ("go", "sanitization_call_detected", 'func f() { template.HTMLEscapeString(value) }'),
            ("go", "sanitization_call_detected", 'func f() { template.JSEscapeString(value) }'),
            ("python", "is_process_exec", "def f():\n    subprocess.run(['echo', 'ok'])\n"),
            ("python", "is_db_query", "def f():\n    cursor.execute(query)\n"),
            ("python", "is_dynamic_eval", "def f():\n    eval(code)\n"),
            ("python", "is_deserialization", "def f():\n    pickle.loads(data)\n"),
            ("python", "is_file_io", "def f():\n    open(path)\n"),
            ("python", "is_network_call", "def f():\n    requests.get(url)\n"),
            ("python", "is_output_render", "def f():\n    render_template_string(template)\n"),
            ("python", "sanitization_call_detected", "def f():\n    shlex.quote(value)\n"),
            ("javascript", "is_process_exec", 'function f() { child_process.exec("echo ok"); }'),
            ("javascript", "is_db_query", 'function f() { db.query("SELECT 1"); }'),
            ("javascript", "is_dynamic_eval", "function f(code) { eval(code); }"),
            ("javascript", "is_deserialization", "function f(data) { JSON.parse(data); }"),
            ("javascript", "is_file_io", "function f(path) { fs.readFile(path); }"),
            ("javascript", "is_network_call", "function f(url) { fetch(url); }"),
            ("javascript", "is_output_render", "function f(el, input) { el.innerHTML = input; }"),
            ("javascript", "sanitization_call_detected", "function f(input) { DOMPurify.sanitize(input); }"),
            ("typescript", "is_process_exec", 'function f() { child_process.exec("echo ok"); }'),
            ("typescript", "is_db_query", 'function f() { db.query("SELECT 1"); }'),
            ("typescript", "is_dynamic_eval", "function f(code: string) { eval(code); }"),
            ("typescript", "is_deserialization", "function f(data: string) { JSON.parse(data); }"),
            ("typescript", "is_file_io", "function f(path: string) { fs.readFile(path); }"),
            ("typescript", "is_network_call", "function f(url: string) { fetch(url); }"),
            ("typescript", "is_output_render", "function f(el: Element, input: string) { el.innerHTML = input; }"),
            ("typescript", "sanitization_call_detected", "function f(input: string) { DOMPurify.sanitize(input); }"),
            ("php", "is_process_exec", '<?php function f() { shell_exec("echo ok"); }'),
            ("php", "is_db_query", '<?php function f($conn, $sql) { mysqli_query($conn, $sql); }'),
            ("php", "is_dynamic_eval", "<?php function f($code) { eval($code); }"),
            ("php", "is_deserialization", "<?php function f($data) { unserialize($data); }"),
            ("php", "is_file_io", "<?php function f($path) { fopen($path, 'r'); }"),
            ("php", "is_network_call", "<?php function f($url) { curl_exec($url); }"),
            ("php", "is_output_render", "<?php function f($input) { echo $input; }"),
            ("php", "sanitization_call_detected", "<?php function f($input) { htmlspecialchars($input); }"),
        ]

        for language, flag_name, source in cases:
            with self.subTest(language=language, flag=flag_name, source=source):
                roots, _src, schema = _tree(language, source)
                assert schema is not None
                id_to_node = {node.statement_id: node for node in flatten(roots)}
                records = [
                    extract_features(node, id_to_node, schema, language, {})
                    for node in flatten(roots)
                ]
                self.assertTrue(
                    any(getattr(record, flag_name) for record in records),
                    f"{language} did not set {flag_name} for {source!r}",
                )

    def test_sink_and_concat_flags_on_cve_anchor(self):
        v_roots, v_src, schema = _tree("go", """func (d validateJsonPathQuery) toSQL() (string, []interface{}) {
\tsb.Select(fmt.Sprintf("JSON_VALUE('{}', '%s')", sqlbuilder.Escape(d.jsonPath)))
}""")
        id_to_node = {n.statement_id: n for n in flatten(v_roots)}
        node = v_roots[0]
        record = extract_features(node, id_to_node, schema, "go", {"repo": "r", "file": "f.go", "method": "toSQL"})
        self.assertEqual(record.statement_type, "call_expr")
        self.assertTrue(record.uses_string_concat_or_format)
        self.assertEqual(record.top_level_call_name, "sb.Select")
        self.assertGreaterEqual(record.num_calls, 2)

    def test_guard_count_and_error_handler_flags(self):
        v_roots, v_src, schema = _tree("python", "def f():\n    try:\n        risky()\n    except ValueError:\n        cleanup()\n")
        id_to_node = {n.statement_id: n for n in flatten(v_roots)}
        catch_child = v_roots[0].children[1]  # cleanup() inside except_clause
        record = extract_features(catch_child, id_to_node, schema, "python", {})
        self.assertTrue(record.inside_error_handler)
        self.assertTrue(record.is_error_handling_statement)


class TestFeaturePipeline(unittest.TestCase):
    def test_process_dataframe_end_to_end(self):
        data = {
            "cve_id": ["CVE-TEST-1"],
            "vulnerability_type": ["SQL Injection"],
            "language": ["Go"],
            "file": ["f.go"],
            "method": ["toSQL"],
            "vulnerable_code": ["""func (d q) toSQL() string {
\tsb := build()
\tsb.Select(fmt.Sprintf("X %s", d.v))
\treturn sb.Build()
}"""],
            "fixed_code": ["""func (d q) toSQL() string {
\treturn build().Buildf("X %v", d.v)
}"""],
            "commit_hash": ["abc123"],
            "repo": ["https://example.com/r"],
        }
        df = pd.DataFrame(data)
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)

        self.assertEqual(stats.total_input_rows, 1)
        self.assertGreater(stats.total_output_rows, 0)
        self.assertGreater(stats.total_positive_labels, 0)
        self.assertTrue((output_df["language"] == "go").all())
        self.assertTrue((output_df["cve_id"] == "CVE-TEST-1").all())

    def test_unsupported_language_skipped(self):
        data = {
            "cve_id": ["CVE-TEST-2"],
            "language": ["Java"],
            "vulnerable_code": ["void f() {}"],
            "fixed_code": ["void f() {}"],
            "file": ["f.java"],
            "method": ["f"],
            "commit_hash": [""],
            "repo": [""],
            "vulnerability_type": [""],
        }
        df = pd.DataFrame(data)
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)
        self.assertEqual(stats.skipped_unsupported_language, 1)
        self.assertEqual(stats.total_output_rows, 0)


if __name__ == "__main__":
    unittest.main()
