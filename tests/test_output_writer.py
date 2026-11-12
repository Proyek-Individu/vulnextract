"""Tests for the shared append-only statement feature output."""

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from src.feature_pipeline import FeatureExtractionPipeline
from src.output_writer import append_statement_features


class TestSharedFeatureOutput(unittest.TestCase):
    def test_feature_pipeline_appends_dataset_a_b_then_a_again(self):
        canonical_input = Path(__file__).resolve().parents[1] / "data" / "input" / "cve_fix_pairs.csv"
        source_df = pd.read_csv(canonical_input, dtype=str, keep_default_na=False)
        supported_df = source_df[
            source_df["language"].str.strip().str.lower().isin(
                {"go", "python", "javascript", "typescript", "php"}
            )
        ]
        dataset_a = supported_df.iloc[[0]]
        dataset_b = supported_df.iloc[[2]]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_a = temp_path / "dataset_a.csv"
            input_b = temp_path / "dataset_b.csv"
            output_path = temp_path / "output_statement_features.csv"
            dataset_a.to_csv(input_a, index=False)
            dataset_b.to_csv(input_b, index=False)

            with patch("src.feature_pipeline.DEFAULT_FEATURES_OUTPUT_FILE", output_path):
                pipeline = FeatureExtractionPipeline(max_rows=None)
                features_a, stats_a = pipeline.process_file(input_a)
                self.assertGreater(stats_a.total_output_rows, 0)
                original_output = output_path.read_bytes()
                features_b, stats_b = pipeline.process_file(input_b)
                self.assertGreater(stats_b.total_output_rows, 0)
                self.assertTrue(output_path.read_bytes().startswith(original_output))
                pipeline.process_file(input_a)

            with output_path.open("r", encoding="utf-8", newline="") as output_file:
                reader = csv.reader(output_file)
                header = next(reader)
                rows = list(reader)

            self.assertEqual(header, list(features_a.columns))
            self.assertEqual(list(features_b.columns), header)
            self.assertEqual(len(rows), len(features_a) * 2 + len(features_b))
            self.assertEqual(sum(row[0] == "cve_id" for row in rows), 0)
            self.assertEqual(stats_a.total_output_rows, len(features_a))
            self.assertEqual(stats_b.total_output_rows, len(features_b))
            self.assertEqual(output_path.read_bytes()[: len(original_output)], original_output)

    def test_reorders_matching_schema_and_rejects_different_schema_unchanged(self):
        original = pd.DataFrame({"first": ["old"], "second": ["value"]})
        reordered = pd.DataFrame({"second": ["new"], "first": ["row"]})

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"
            append_statement_features(original, output_path)
            append_statement_features(reordered, output_path)

            stored = pd.read_csv(output_path)
            self.assertEqual(list(stored.columns), ["first", "second"])
            self.assertEqual(stored.iloc[1].tolist(), ["row", "new"])

            previous_bytes = output_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "schema does not match"):
                append_statement_features(
                    pd.DataFrame({"first": ["bad"], "extra": ["column"]}),
                    output_path,
                )
            self.assertEqual(output_path.read_bytes(), previous_bytes)

    def test_append_separates_existing_csv_without_final_newline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"
            append_statement_features(pd.DataFrame({"feature": ["old"]}), output_path)
            output_path.write_bytes(output_path.read_bytes().rstrip(b"\n"))

            append_statement_features(pd.DataFrame({"feature": ["new"]}), output_path)

            self.assertEqual(pd.read_csv(output_path)["feature"].tolist(), ["old", "new"])


if __name__ == "__main__":
    unittest.main()
