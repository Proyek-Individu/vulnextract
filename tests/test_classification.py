"""
Unit tests for the classification mode (src/classification/*).
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.classification import ClassificationPipeline, build_model_spec, build_model_specs
from src.classification.datasets import (
    StatementFeatureBuilder,
    build_raw_methods,
    build_statements,
    make_folds,
)
from src.classification.metrics import aggregate_to_methods
from src.feature_pipeline import FeatureExtractionPipeline


def _synthetic_raw_df(n_pairs: int = 16) -> pd.DataFrame:
    rows = []
    for i in range(n_pairs):
        if i % 2 == 0:
            vulnerable = (
                f"def run_{i}(cmd):\n"
                f"    name = cmd.strip()\n"
                f"    os.system('ls ' + name)\n"
                f"    return {i}\n"
            )
            fixed = (
                f"def run_{i}(cmd):\n"
                f"    name = cmd.strip()\n"
                f"    if not name.isalnum():\n"
                f"        raise ValueError(name)\n"
                f"    subprocess.run(['ls', shlex.quote(name)])\n"
                f"    return {i}\n"
            )
            language = "python"
        else:
            vulnerable = (
                f"func Read{i}(p string) ([]byte, error) {{\n"
                f"\tfull := \"/data/\" + p\n"
                f"\treturn os.ReadFile(full)\n"
                f"}}"
            )
            fixed = (
                f"func Read{i}(p string) ([]byte, error) {{\n"
                f"\tif strings.Contains(p, \"..\") {{\n"
                f"\t\treturn nil, errors.New(\"bad\")\n"
                f"\t}}\n"
                f"\tfull := filepath.Join(\"/data\", filepath.Clean(p))\n"
                f"\treturn os.ReadFile(full)\n"
                f"}}"
            )
            language = "go"
        rows.append({
            "cve_id": f"CVE-2026-{1000 + i}",
            "vulnerability_type": "Command Injection" if i % 2 == 0 else "Path Traversal",
            "language": language,
            "file": f"file_{i}.{'py' if language == 'python' else 'go'}",
            "method": f"run_{i}" if language == "python" else f"Read{i}",
            "vulnerable_code": vulnerable,
            "fixed_code": fixed,
            "commit_hash": f"hash{i}",
            "repo": "https://example.com/repo",
            "commit_msg": "fix",
        })
    return pd.DataFrame(rows)


class TestModelRegistry(unittest.TestCase):
    def test_default_is_random_forest(self):
        specs = build_model_specs([], random_state=1)
        self.assertEqual(specs[0].label, "random_forest")
        self.assertEqual(type(specs[0].estimator).__name__, "RandomForestClassifier")
        self.assertEqual(specs[0].estimator.get_params()["random_state"], 1)

    def test_user_params_override_defaults(self):
        spec = build_model_spec({"name": "random_forest", "params": {"n_estimators": 7, "class_weight": None}})
        params = spec.estimator.get_params()
        self.assertEqual(params["n_estimators"], 7)
        self.assertIsNone(params["class_weight"])

    def test_class_path_and_scale_flag(self):
        spec = build_model_spec({"class": "sklearn.linear_model.LogisticRegression", "scale": True})
        self.assertEqual(type(spec.estimator).__name__, "LogisticRegression")
        self.assertTrue(spec.scale)

    def test_unknown_model_raises(self):
        with self.assertRaises(ValueError):
            build_model_spec("not_a_model")

    def test_duplicate_labels_made_unique(self):
        specs = build_model_specs(["random_forest", "random_forest"])
        self.assertEqual([s.label for s in specs], ["random_forest", "random_forest_2"])


class TestDatasets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw_df = _synthetic_raw_df()
        cls.split_df, _ = FeatureExtractionPipeline().process_dataframe(cls.raw_df)

    def test_raw_methods_one_sample_per_side(self):
        methods = build_raw_methods(self.raw_df)
        self.assertEqual(len(methods), 2 * len(self.raw_df))
        self.assertEqual(set(methods.groupby("side")["label"].first().items()), {("vulnerable", 1), ("fixed", 0)})

    def test_unchanged_row_gives_single_safe_sample(self):
        df = self.raw_df.head(1).copy()
        df["fixed_code"] = df["vulnerable_code"]
        methods = build_raw_methods(df)
        self.assertEqual(methods["side"].tolist(), ["unchanged"])
        self.assertEqual(methods["label"].tolist(), [0])

    def test_statements_linked_to_raw_rows(self):
        statements = build_statements(self.split_df, self.raw_df)
        self.assertEqual(len(statements), len(self.split_df))
        expected = self.raw_df.loc[statements["row_index"], "cve_id"].to_numpy()
        self.assertTrue((statements["cve_id"].to_numpy() == expected).all())
        fixed = statements[statements["side"] == "fixed"]
        self.assertTrue((fixed["method_label"] == 0).all())

    def test_folds_never_split_a_group(self):
        methods = build_raw_methods(self.raw_df)
        statements = build_statements(self.split_df, self.raw_df)
        for cv in (0, 3):
            folds = make_folds(methods, statements, test_size=0.25, cv_folds=cv, random_state=0)
            self.assertEqual(len(folds), 1 if cv == 0 else 3)
            for train_groups, test_groups in folds:
                self.assertFalse(train_groups & test_groups)
                self.assertTrue(test_groups)

    def test_leaky_columns_are_dropped(self):
        builder = StatementFeatureBuilder({"numeric": ["token_count", "label"],
                                           "categorical": ["origin", "statement_type"]})
        builder.fit_transform(self.split_df)
        names = builder.feature_names
        self.assertIn("token_count", names)
        self.assertFalse(any(n.startswith(("origin", "label")) for n in names))

    def test_aggregate_to_methods_uses_max(self):
        preds = pd.DataFrame({
            "method_id": ["0:vulnerable", "0:vulnerable", "0:fixed"],
            "method_label": [1, 1, 0],
            "group": ["g", "g", "g"],
            "y_score": [0.1, 0.9, 0.3],
        })
        agg = aggregate_to_methods(preds, "max").set_index("method_id")
        self.assertAlmostEqual(agg.loc["0:vulnerable", "y_score"], 0.9)
        self.assertEqual(agg.loc["0:vulnerable", "n_statements"], 2)


class TestClassificationPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_end_to_end_report(self):
        raw_df = _synthetic_raw_df()
        split_df, _ = FeatureExtractionPipeline().process_dataframe(raw_df)
        pipeline = ClassificationPipeline({
            "models": [{"name": "random_forest", "params": {"n_estimators": 10}},
                       {"name": "logistic_regression"}],
            "split": {"test_size": 0.25, "cv_folds": 0, "random_state": 0},
            "output_formats": ["xlsx", "csv"],
            "xai": {"enabled": True, "save_plots": False, "permutation_repeats": 2, "local_explanations": 2},
        })
        result = pipeline.run_frames(raw_df, split_df, self.tmp)

        levels = set(zip(result.metrics["approach"], result.metrics["eval_level"]))
        self.assertEqual(levels, {("raw", "method"), ("split", "statement"), ("split", "method")})

        # Same method-level test set for both approaches (align_samples=True).
        method_rows = result.metrics[result.metrics["eval_level"] == "method"]
        self.assertEqual(method_rows.groupby("approach")["n_test"].first().nunique(), 1)

        self.assertIn("selisih (split - raw) @method", result.comparison.columns)
        self.assertEqual(set(result.comparison["model"]), {"random_forest", "logistic_regression"})

        names = {p.name for p in result.files}
        self.assertIn("classification_report.xlsx", names)
        self.assertIn("comparison.csv", names)
        sheets = pd.ExcelFile(result.run_dir / "classification_report.xlsx").sheet_names
        for sheet in ("comparison", "feature_importance", "local_explanations", "predictions"):
            self.assertIn(sheet, sheets)
        importance = pd.read_csv(result.run_dir / "feature_importance.csv")
        self.assertTrue(importance["permutation_mean"].notna().any())


if __name__ == "__main__":
    unittest.main()
