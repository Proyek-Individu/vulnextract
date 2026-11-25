"""
Unit tests for the hierarchical statement-level feature pipeline
(src/features/*, src/feature_pipeline.py).
"""

import unittest
import urllib.error
from unittest.mock import patch

import pandas as pd

from src.dataset_loader import normalize_dataframe
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
    def test_vulnerability_type_follows_final_label_for_each_origin(self):
        changed = "def changed(x):\n    check(x)\n    return x\n"
        fixed = "def changed(x):\n    check(x)\n    return x + 1\n"
        same = "def unchanged(x):\n    return x\n"
        blank_type_vulnerable = "def no_type(x):\n    return 1\n"
        blank_type_fixed = "def no_type(x):\n    return 2\n"
        df = pd.DataFrame([
            {
                "cve_id": "CVE-TYPE-1", "vulnerability_type": "SQL Injection",
                "language": "python", "file": "a.py", "method": "changed",
                "vulnerable_code": changed, "fixed_code": fixed, "commit_hash": "h1",
            },
            {
                "cve_id": "CVE-TYPE-2", "vulnerability_type": "XSS",
                "language": "python", "file": "b.py", "method": "unchanged",
                "vulnerable_code": same, "fixed_code": same, "commit_hash": "h2",
            },
            {
                "cve_id": "CVE-TYPE-3", "vulnerability_type": "",
                "language": "python", "file": "c.py", "method": "no_type",
                "vulnerable_code": blank_type_vulnerable, "fixed_code": blank_type_fixed,
                "commit_hash": "h3",
            },
            {
                "cve_id": "CVE-TYPE-4", "vulnerability_type": "Path Traversal",
                "language": "python", "file": "d.py", "method": "fixed_only",
                "vulnerable_code": "", "fixed_code": "def fixed_only():\n    return 0\n",
                "commit_hash": "h4",
            },
        ])
        output_df, _stats = FeatureExtractionPipeline().process_dataframe(df)
        self.assertEqual(set(output_df["origin"]), {"vulnerable", "fixed", "unchanged"})
        self.assertEqual(
            set(map(tuple, output_df[["origin", "label"]].drop_duplicates().to_numpy())),
            {("vulnerable", 0), ("vulnerable", 1), ("fixed", 0), ("unchanged", 0)},
        )
        self.assertTrue((output_df.loc[output_df["label"] == 0, "vulnerability_type"] == "none").all())
        positive = output_df[output_df["label"] == 1]
        self.assertTrue((positive.loc[positive["cve_id"] == "CVE-TYPE-1", "vulnerability_type"] == "SQL Injection").all())
        self.assertTrue((positive.loc[positive["cve_id"] == "CVE-TYPE-3", "vulnerability_type"] == "unknown").all())

    def test_paired_loader_preserves_each_commit_hash_alias(self):
        aliases = (
            "commit_hash", "hash", "sha", "commit", "commit_id", "commit_sha",
            "fix_commit", "fixing_commit",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                df = pd.DataFrame({
                    "cve_id": ["CVE-ALIAS"],
                    "language": ["python"],
                    "vulnerable_code": ["def f(x):\n    return x\n"],
                    "fixed_code": ["def f(x):\n    return x + 1\n"],
                    alias: ["abc123"],
                })
                normalized = normalize_dataframe(df)
                self.assertEqual(normalized.loc[0, "commit_hash"], "abc123")
                output_df, _stats = FeatureExtractionPipeline().process_dataframe(df)
                self.assertGreater(len(output_df), 0)
                self.assertTrue((output_df["commit_hash"] == "abc123").all())

    def test_advisory_synthesis_is_disabled_by_default_and_opt_in(self):
        advisory = pd.DataFrame({
            "Title": ["Sample SQL injection advisory"],
            "Summary": ["CVE-2024-12345 affects example (pypi)"],
            "Severity": ["Moderate"],
            "Link": ["https://github.com/advisories/GHSA-1234-abcd-efgh"],
        })
        with patch(
            "src.dataset_loader.urllib.request.urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            output_df, stats = FeatureExtractionPipeline().process_dataframe(advisory)
            self.assertEqual(stats.total_input_rows, 1)
            self.assertEqual(stats.total_output_rows, 0)
            self.assertEqual(stats.skipped_advisory_no_commit_diff, 1)

            synthetic_df, synthetic_stats = FeatureExtractionPipeline(
                allow_synthetic_fallback=True
            ).process_dataframe(advisory)
        self.assertGreater(synthetic_stats.total_output_rows, 0)
        self.assertGreater(len(synthetic_df), 0)
        self.assertEqual(synthetic_stats.skipped_advisory_no_commit_diff, 0)

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

        # Both classes must be present: the vulnerable side (diffed) and the
        # fixed side (independently extracted, always safe).
        self.assertEqual(set(output_df["origin"]), {"vulnerable", "fixed"})
        fixed_rows = output_df[output_df["origin"] == "fixed"]
        self.assertGreater(len(fixed_rows), 0)
        self.assertTrue((fixed_rows["label"] == 0).all())
        self.assertTrue((fixed_rows["vulnerability_type"] == "none").all())
        vuln_rows = output_df[output_df["origin"] == "vulnerable"]
        self.assertTrue((vuln_rows.loc[vuln_rows["label"] == 0, "vulnerability_type"] == "none").all())
        self.assertTrue((vuln_rows.loc[vuln_rows["label"] == 1, "vulnerability_type"] == "SQL Injection").all())
        # statement_id must not collide between the two origins for the same method.
        self.assertEqual(len(output_df["statement_id"].unique()), len(output_df))

    def test_fixed_code_contributes_safe_class(self):
        data = {
            "cve_id": ["CVE-TEST-3"],
            "vulnerability_type": ["Missing Validation"],
            "language": ["Python"],
            "file": ["f.py"],
            "method": ["add_filtered_relation"],
            "vulnerable_code": ["def f(alias):\n    check_alias(alias)\n    use(alias)\n"],
            "fixed_code": [
                "def f(alias):\n"
                "    if '.' in alias:\n"
                "        raise ValueError('bad alias')\n"
                "    check_alias(alias)\n"
                "    use(alias)\n"
            ],
            "commit_hash": ["def456"],
            "repo": ["https://example.com/r"],
        }
        df = pd.DataFrame(data)
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)

        # A pure-insertion fix (nothing in vulnerable_code itself changed)
        # yields zero positive labels on the vulnerable side...
        vuln_rows = output_df[output_df["origin"] == "vulnerable"]
        self.assertTrue((vuln_rows["label"] == 0).all())
        # ...but the fixed side still contributes real safe-class statements,
        # including the newly added validation check itself.
        fixed_rows = output_df[output_df["origin"] == "fixed"]
        self.assertGreater(len(fixed_rows), 0)
        self.assertTrue((fixed_rows["label"] == 0).all())
        self.assertTrue((fixed_rows["vulnerability_type"] == "none").all())
        self.assertIn("if", set(fixed_rows["statement_type"]))
        self.assertGreater(stats.total_from_fixed_side, 0)

    def test_unchanged_row_emits_safe_class_once(self):
        source = "def f(x):\n    a = 1\n    return a\n"
        data = {
            "cve_id": ["CVE-TEST-4"],
            "vulnerability_type": ["SQL Injection"],
            "language": ["Python"],
            "file": ["f.py"],
            "method": ["f"],
            "vulnerable_code": [source],
            "fixed_code": [source],
            "commit_hash": [""],
            "repo": [""],
        }
        df = pd.DataFrame(data)
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)

        # Identical vulnerable/fixed code must be extracted exactly once
        # (not duplicated as both "vulnerable" and "fixed").
        self.assertEqual(set(output_df["origin"]), {"unchanged"})
        self.assertEqual(len(output_df), 2)  # a = 1; return a
        self.assertTrue((output_df["label"] == 0).all())
        self.assertTrue((output_df["vulnerability_type"] == "none").all())
        self.assertEqual(stats.total_from_unchanged_rows, 2)
        self.assertEqual(stats.total_from_vulnerable_side, 0)
        self.assertEqual(stats.total_from_fixed_side, 0)

    def test_duplicate_input_rows_are_skipped_before_extraction(self):
        row = {
            "cve_id": "CVE-DUP",
            "vulnerability_type": "Path Traversal",
            "language": "Python",
            "file": "f.py",
            "method": "g",
            "vulnerable_code": "def g(x):\n    a = 1\n    return a\n",
            "fixed_code": "def g(x):\n    a = 2\n    return a\n",
            "commit_hash": "same",
            "repo": "https://example.com/r",
        }
        df = pd.DataFrame([row, row])  # two identical rows
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)
        self.assertEqual(len(output_df), len(output_df["statement_id"].unique()))
        self.assertEqual(stats.skipped_duplicate_input_rows, 1)

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

    def test_code_vulnerabilities_dataset_features(self):
        df = pd.DataFrame({
            "Code Snippet": [
                "cursor.execute('SELECT * FROM users WHERE username = ' + user_input)",
                "document.getElementById('input').innerHTML = user_input;",
            ],
            "Vulnerability Type": ["SQLi", "XSS"],
            "Location": [8, 10],
            "Preprocessed Tokens": ["[]", "[]"],
        })
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)
        self.assertEqual(stats.total_input_rows, 2)
        self.assertEqual(stats.total_output_rows, 2)
        self.assertEqual(stats.total_positive_labels, 2)
        self.assertEqual(set(output_df["origin"]), {"vulnerable"})
        self.assertTrue((output_df["label"] == 1).all())

    def test_cvefixes_dataset_features(self):
        df = pd.DataFrame({
            "code": [
                "def vuln(u):\n    x = 1\n    return cursor.execute('SELECT ' + u)\n",
                "def safe(u):\n    return cursor.execute('SELECT %s', (u,))\n",
            ],
            "language": ["py", "py"],
            "safety": ["vulnerable", "safe"],
        })
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(df)
        self.assertEqual(stats.total_input_rows, 2)
        self.assertEqual(set(output_df["origin"]), {"vulnerable", "fixed"})
        self.assertGreater(stats.total_positive_labels, 0)
        self.assertGreater(stats.total_from_fixed_side, 0)
        fixed_rows = output_df[output_df["origin"] == "fixed"]
        self.assertTrue((fixed_rows["label"] == 0).all())

    def test_security_vulnerabilities_dataset_features(self):
        df = pd.DataFrame({
            "Title": ["Scancode.io Reflected Cross-Site Scripting (XSS) in license endpoint"],
            "Date": ["2023-08-15T20:04:49Z"],
            "Severity": ["Moderate"],
            "Summary": ["CVE-2023-40024was published\n                        forscancodeio(pip)Aug 15, 2023"],
            "Link": ["https://github.com/advisories/GHSA-6xcx-gx7r-rccj"],
        })
        norm_df = normalize_dataframe(df, fetch_github=False, allow_synthetic_fallback=True)
        pipeline = FeatureExtractionPipeline()
        output_df, stats = pipeline.process_dataframe(norm_df)
        self.assertEqual(stats.total_input_rows, 1)
        self.assertGreater(stats.total_output_rows, 0)
        self.assertGreater(stats.total_positive_labels, 0)
        self.assertEqual(set(output_df["origin"]), {"vulnerable", "fixed"})


if __name__ == "__main__":
    unittest.main()
