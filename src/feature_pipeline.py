"""
Orchestrates the statement-level feature pipeline: for each CVE fix-pair CSV
row, builds hierarchical statement trees for both vulnerable_code and
fixed_code, labels the vulnerable-side tree via a recursive diff against the
fixed-side tree, extracts context.md's category A-F features for every
vulnerable-side statement, and writes one flat labeled row per statement.

Additive and independent of src/pipeline.py (the existing method/statement
pair-based CLI mode) — reads the same input CSV, but neither pipeline calls
into the other.
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Union

import pandas as pd

from .features.feature_extractor import extract_features
from .features.labeler import label_statements
from .features.langs import get_schema
from .features.models import FeaturePipelineStats
from .features.tree_builder import build_statement_tree, flatten

logger = logging.getLogger(__name__)

DUPLICATE_INPUT_KEY_COLUMNS = (
    "cve_id",
    "commit_hash",
    "language",
    "file",
    "method",
    "vulnerable_code",
    "fixed_code",
)
_MISSING_DUPLICATE_KEY_VALUE = object()


class FeatureExtractionPipeline:
    """
    Produces a flat, labeled, per-statement feature table matching
    context.md's schema, scoped to context.md's target languages (Go,
    Python, JavaScript/TypeScript, PHP).
    """

    def process_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path] = None,
    ) -> Tuple[pd.DataFrame, FeaturePipelineStats]:
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found at: {input_path}")

        logger.info(f"Loading input dataset from {input_path}...")
        df = pd.read_csv(input_path)

        output_df, stats = self.process_dataframe(df)

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Saving {len(output_df)} statement rows to {output_path}...")
            output_df.to_csv(output_path, index=False, encoding="utf-8")

        return output_df, stats

    def process_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, FeaturePipelineStats]:
        stats = FeaturePipelineStats(total_input_rows=len(df))
        rows: List[dict] = []
        seen_input_keys = set()

        for index, row in df.iterrows():
            language = str(row.get("language", "")).strip().lower()
            schema = get_schema(language)
            if schema is None:
                logger.warning(f"Unsupported/out-of-scope language '{language}' at row {index}")
                stats.skipped_unsupported_language += 1
                continue

            vulnerable_code = row.get("vulnerable_code")
            fixed_code = row.get("fixed_code")
            if not isinstance(vulnerable_code, str) or not vulnerable_code.strip():
                stats.skipped_no_code += 1
                continue

            duplicate_key_values = []
            for column in DUPLICATE_INPUT_KEY_COLUMNS:
                value = row.get(column)
                duplicate_key_values.append(
                    _MISSING_DUPLICATE_KEY_VALUE if pd.isna(value) else value
                )
            duplicate_key = tuple(duplicate_key_values)
            if duplicate_key in seen_input_keys:
                stats.skipped_duplicate_input += 1
                logger.debug("Skipping duplicate feature input row %s", index)
                continue
            seen_input_keys.add(duplicate_key)

            row_meta: Dict[str, str] = {
                "cve_id": str(row.get("cve_id", "") or ""),
                "vulnerability_type": str(row.get("vulnerability_type", "") or ""),
                "commit_hash": str(row.get("commit_hash", "") or ""),
                "repo": str(row.get("repo", "") or ""),
                "file": str(row.get("file", "") or ""),
                "method": str(row.get("method", "") or ""),
            }
            commit_hash = row.get("commit_hash", "")
            commit_hash = "" if pd.isna(commit_hash) else str(commit_hash).strip()
            commit_id = commit_hash[:8] if commit_hash else "nohash"
            id_prefix = (
                f"{row_meta['cve_id']}:{commit_id}:{row_meta['repo']}:"
                f"{row_meta['file']}:{row_meta['method']}"
            )

            try:
                v_roots, v_source = build_statement_tree(vulnerable_code, language, schema, id_prefix)
                f_roots, f_source = build_statement_tree(
                    fixed_code if isinstance(fixed_code, str) else "", language, schema, id_prefix
                )
            except Exception as e:
                logger.warning(f"Statement extraction failed at row {index}: {e}")
                stats.skipped_extraction_failure += 1
                continue

            if not v_roots:
                stats.skipped_no_code += 1
                continue

            label_statements(v_roots, f_roots, v_source, f_source)

            flat_nodes = flatten(v_roots)
            id_to_node = {n.statement_id: n for n in flat_nodes}

            for node in flat_nodes:
                record = extract_features(node, id_to_node, schema, language, row_meta)
                if record.label == 0:
                    record.vulnerability_type = "none"
                else:
                    vulnerability_type = row.get("vulnerability_type", "")
                    if pd.isna(vulnerability_type) or not str(vulnerability_type).strip():
                        record.vulnerability_type = "unknown"
                    else:
                        record.vulnerability_type = str(vulnerability_type)
                rows.append(record.__dict__)
                if record.label:
                    stats.total_positive_labels += 1

        output_df = pd.DataFrame(rows)
        stats.total_output_rows = len(output_df)

        return output_df, stats
