"""
Orchestrates the statement-level feature pipeline: for each CVE fix-pair CSV
row, builds hierarchical statement trees and extracts context.md's category
A-F features for every statement, producing BOTH classes needed for ML/DL
training — not just vulnerable statements:

- "vulnerable": vulnerable_code's own statements, labeled via a recursive
  diff against fixed_code (label 0 = unchanged, 1 = actually changed).
- "fixed": fixed_code's own statements, from a row where it actually
  differs from vulnerable_code — i.e. the fix itself, always label 0,
  vulnerability_type forced to "none" (this is safe code, not an instance
  of the original vulnerability).
- "unchanged": rows where vulnerable_code was already identical to
  fixed_code (safe from the start) — always label 0, vulnerability_type
  forced to "none". Extracted once, not twice, to avoid emitting the same
  statements under two different origins.

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

            base_meta: Dict[str, str] = {
                "cve_id": str(row.get("cve_id", "") or ""),
                "vulnerability_type": str(row.get("vulnerability_type", "") or ""),
                "commit_hash": str(row.get("commit_hash", "") or ""),
                "repo": str(row.get("repo", "") or ""),
                "file": str(row.get("file", "") or ""),
                "method": str(row.get("method", "") or ""),
            }
            # Row index guarantees uniqueness even when (repo, file, method,
            # commit_hash) collides across input rows — this dataset has a
            # handful of literal duplicate rows and same-method-fixed-twice
            # cases (see data/input/cve_fix_pairs.csv), which would otherwise
            # produce colliding statement_ids across CSV rows.
            id_base = f"{base_meta['repo']}:{base_meta['file']}:{base_meta['method']}:{index}"

            has_fixed_code = isinstance(fixed_code, str) and bool(fixed_code.strip())
            is_unchanged = has_fixed_code and vulnerable_code.strip() == fixed_code.strip()

            try:
                if is_unchanged:
                    # Safe from the start — extract once (not duplicated as
                    # both "vulnerable" and "fixed", which would just be the
                    # same statements twice), vulnerability_type -> "none".
                    safe_meta = {**base_meta, "vulnerability_type": "none"}
                    safe_roots, _safe_source = build_statement_tree(
                        vulnerable_code, language, schema, f"{id_base}:unchanged"
                    )
                    self._emit(safe_roots, schema, language, safe_meta, "unchanged", force_label_zero=True, rows=rows, stats=stats)
                else:
                    v_roots, v_source = build_statement_tree(vulnerable_code, language, schema, f"{id_base}:vulnerable")
                    f_roots, f_source = build_statement_tree(
                        fixed_code if has_fixed_code else "", language, schema, f"{id_base}:fixed_ref"
                    )
                    label_statements(v_roots, f_roots, v_source, f_source)
                    self._emit(v_roots, schema, language, base_meta, "vulnerable", force_label_zero=False, rows=rows, stats=stats)

                    if has_fixed_code:
                        # The fix itself — genuinely safe code, extracted
                        # independently (not reused from the diff above) so
                        # it carries its own complete statement tree.
                        fixed_safe_meta = {**base_meta, "vulnerability_type": "none"}
                        fixed_safe_roots, _fs_source = build_statement_tree(
                            fixed_code, language, schema, f"{id_base}:fixed"
                        )
                        self._emit(fixed_safe_roots, schema, language, fixed_safe_meta, "fixed", force_label_zero=True, rows=rows, stats=stats)

            except Exception as e:
                logger.warning(f"Statement extraction failed at row {index}: {e}")
                stats.skipped_extraction_failure += 1
                continue

        output_df = pd.DataFrame(rows)
        stats.total_output_rows = len(output_df)

        return output_df, stats

    @staticmethod
    def _emit(
        roots,
        schema,
        language: str,
        row_meta: Dict[str, str],
        origin: str,
        force_label_zero: bool,
        rows: List[dict],
        stats: FeaturePipelineStats,
    ) -> None:
        if not roots:
            return

        flat_nodes = flatten(roots)
        if force_label_zero:
            for node in flat_nodes:
                node.label = 0
        id_to_node = {n.statement_id: n for n in flat_nodes}

        for node in flat_nodes:
            record = extract_features(node, id_to_node, schema, language, row_meta, origin=origin)
            rows.append(record.__dict__)
            if record.label:
                stats.total_positive_labels += 1
            if origin == "vulnerable":
                stats.total_from_vulnerable_side += 1
            elif origin == "fixed":
                stats.total_from_fixed_side += 1
            elif origin == "unchanged":
                stats.total_from_unchanged_rows += 1
