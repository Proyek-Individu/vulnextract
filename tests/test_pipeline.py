"""
Unit tests for modular CVE statement and method extraction pipeline across supported languages.
"""

import unittest
import pandas as pd

from src.extractors import ExtractorRegistry, get_extractor
from src.extractors.c import CMethodExtractor
from src.extractors.go import GoMethodExtractor
from src.extractors.java import JavaMethodExtractor
from src.extractors.javascript import JavascriptMethodExtractor
from src.extractors.php import PhpMethodExtractor
from src.extractors.python import PythonMethodExtractor
from src.extractors.rust import RustMethodExtractor
from src.extractors.typescript import TypescriptMethodExtractor
from src.models import PairingStatus
from src.strategies.pairing import AlignedPairingStrategy, StrictZipPairingStrategy
from src.pipeline import CveMethodPipeline


class TestLanguageExtractors(unittest.TestCase):
    def test_java_extractor(self):
        extractor = JavaMethodExtractor()
        code = "public class A { public A() {} void test() {} }"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 2)

    def test_python_extractor(self):
        extractor = PythonMethodExtractor()
        code = "def foo(x):\n    return x * 2\n\ndef bar():\n    pass\n"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 2)
        self.assertTrue(any("def foo" in m for m in methods))

    def test_go_extractor(self):
        extractor = GoMethodExtractor()
        code = "func Foo() {}\nfunc (s *Service) Bar() error { return nil }\n"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 2)

    def test_php_extractor(self):
        extractor = PhpMethodExtractor()
        code = "function cleanInput($data) { return trim($data); }"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 1)

    def test_javascript_extractor(self):
        extractor = JavascriptMethodExtractor()
        code = "function add(a, b) { return a + b; }\nconst sub = (a, b) => a - b;"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 2)

    def test_typescript_extractor(self):
        extractor = TypescriptMethodExtractor()
        code = "private handleReq(opts?: Options): void { return; }"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 1)

    def test_rust_extractor(self):
        extractor = RustMethodExtractor()
        code = "fn calculate(val: u32) -> u32 { val * 2 }"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 1)

    def test_c_extractor(self):
        extractor = CMethodExtractor()
        code = "int process_buffer(char *buf, int len) { return 0; }"
        methods = extractor.extract_methods(code)
        self.assertEqual(len(methods), 1)

    def test_extract_statements_blank_newlines(self):
        extractor = JavaMethodExtractor()
        code = (
            "List<SearchResult> result = new ArrayList<SearchResult>();\n\n"
            "if (StringUtils.isEmpty(keywords)) {\n    return result;\n}\n\n"
            "return result;"
        )
        statements = extractor.extract_statements(code)
        self.assertEqual(len(statements), 3)
        self.assertTrue(statements[0].startswith("List<SearchResult>"))
        self.assertTrue(statements[1].startswith("if (StringUtils.isEmpty"))
        self.assertEqual(statements[2], "return result;")


class TestPairingStrategy(unittest.TestCase):
    def setUp(self):
        self.strict_strategy = StrictZipPairingStrategy()
        self.aligned_strategy = AlignedPairingStrategy()

    def test_strict_pair_matching_counts(self):
        v_snippets = ["void vuln1() {}", "void vuln2() {}"]
        f_snippets = ["void fix1() {}", "void fix2() {}"]
        result = self.strict_strategy.pair(v_snippets, f_snippets)

        self.assertEqual(result.status, PairingStatus.SUCCESS)
        self.assertEqual(len(result.pairs), 2)
        self.assertEqual(result.pairs[0].vulnerable_code, "void vuln1() {}")
        self.assertEqual(result.pairs[0].fixed_code, "void fix1() {}")

    def test_strict_pair_mismatch(self):
        v_snippets = ["void vuln1() {}"]
        f_snippets = ["void fix1() {}", "void fix2() {}"]
        result = self.strict_strategy.pair(v_snippets, f_snippets)

        self.assertEqual(result.status, PairingStatus.MISMATCH)
        self.assertEqual(len(result.pairs), 0)

    def test_strict_pair_no_vulnerable_snippets(self):
        result = self.strict_strategy.pair([], ["void fix1() {}"])
        self.assertEqual(result.status, PairingStatus.NO_VULNERABLE_CODE)

    def test_aligned_pair_with_insertion(self):
        v_snippets = ["stmt1();", "stmt3();"]
        f_snippets = ["stmt1();", "inserted();", "stmt3();"]
        result = self.aligned_strategy.pair(v_snippets, f_snippets)

        self.assertEqual(result.status, PairingStatus.SUCCESS)
        self.assertEqual(len(result.pairs), 3)
        self.assertEqual(result.pairs[0].vulnerable_code, "stmt1();")
        self.assertEqual(result.pairs[0].fixed_code, "stmt1();")
        self.assertEqual(result.pairs[1].vulnerable_code, "")
        self.assertEqual(result.pairs[1].fixed_code, "inserted();")
        self.assertEqual(result.pairs[2].vulnerable_code, "stmt3();")
        self.assertEqual(result.pairs[2].fixed_code, "stmt3();")


class TestExtractorRegistry(unittest.TestCase):
    def test_supported_languages_presence(self):
        languages = ["java", "python", "go", "php", "javascript", "typescript", "rust", "c"]
        for lang in languages:
            extractor = get_extractor(lang)
            self.assertIsNotNone(extractor, f"Extractor for {lang} should be registered")

    def test_get_unknown_extractor(self):
        extractor = get_extractor("unknown_language")
        self.assertIsNone(extractor)


class TestPipeline(unittest.TestCase):
    def test_pipeline_method_granularity(self):
        data = {
            "cve_id": ["CVE-1", "CVE-2"],
            "language": ["Python", "Go"],
            "vulnerable_code": [
                "def test():\n    return 1",
                "func Test() int { return 1 }"
            ],
            "fixed_code": [
                "def test():\n    return 2",
                "func Test() int { return 2 }"
            ],
            "file": ["test.py", "test.go"],
            "method": ["test", "Test"],
            "granularity": ["file", "file"]
        }
        df = pd.DataFrame(data)
        pipeline = CveMethodPipeline(granularity="method")
        output_df, stats = pipeline.process_dataframe(df)

        self.assertEqual(stats.total_input_rows, 2)
        self.assertEqual(stats.total_output_rows, 2)
        self.assertTrue((output_df["granularity"] == "method").all())

    def test_pipeline_statement_granularity(self):
        data = {
            "cve_id": ["CVE-1"],
            "language": ["Python"],
            "vulnerable_code": [
                "a = 1\n\nb = 2\n\nreturn a + b"
            ],
            "fixed_code": [
                "a = 1\n\nb = 3\n\nreturn a + b"
            ],
            "file": ["test.py"],
            "method": ["test"],
            "granularity": ["method"]
        }
        df = pd.DataFrame(data)
        pipeline = CveMethodPipeline(granularity="statement")
        output_df, stats = pipeline.process_dataframe(df)

        self.assertEqual(stats.total_input_rows, 1)
        self.assertEqual(stats.total_output_rows, 3)
        self.assertTrue((output_df["granularity"] == "statement").all())
        self.assertEqual(output_df.iloc[1]["vulnerable_code"], "b = 2")
        self.assertEqual(output_df.iloc[1]["fixed_code"], "b = 3")


if __name__ == "__main__":
    unittest.main()

