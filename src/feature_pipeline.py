"""
Orchestrates the statement-level feature pipeline: for each vulnerability
dataset row, builds hierarchical statement trees and extracts context.md's
category A-F features for every statement, producing BOTH classes needed for
ML/DL training — not just vulnerable statements:

- "vulnerable": vulnerable_code's own statements, labeled via a recursive
  diff against fixed_code when fixed_code is available (label 0 = unchanged,
  1 = actually changed), or via sink-aware labeling when unpaired.
- "fixed": fixed_code's own statements, from a row where it differs from
  vulnerable_code or from an unpaired safe row (e.g. CVEFixes safety="safe")
  — always label 0, vulnerability_type forced to "none".
- "unchanged": rows where vulnerable_code was already identical to
  fixed_code (safe from the start) — always label 0, vulnerability_type
  forced to "none". Extracted once, not twice.
"""

from dataclasses import fields
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import pandas as pd

from .config import DEFAULT_MAX_ROWS
from .dataset_loader import load_dataset, normalize_dataframe
from .features.feature_extractor import extract_features
from .features.labeler import label_statements
from .features.langs import get_schema
from .features.models import FeaturePipelineStats, StatementRecord
from .features.tree_builder import build_statement_tree, flatten

logger = logging.getLogger(__name__)

_STATEMENT_RECORD_COLUMNS: List[str] = [f.name for f in fields(StatementRecord)]


def _has_dangerous_sink(record: StatementRecord) -> bool:
    return bool(
        record.is_process_exec
        or record.is_db_query
        or record.is_dynamic_eval
        or record.is_deserialization
        or record.is_file_io
        or record.is_network_call
        or record.is_output_render
        or record.uses_string_concat_or_format
    )


class FeatureExtractionPipeline:
    """
    Produces a flat, labeled, per-statement feature table matching
    context.md's schema, scoped to context.md's target languages (Go,
    Python, JavaScript/TypeScript, PHP).
    """

    def __init__(self, max_rows: Optional[int] = DEFAULT_MAX_ROWS) -> None:
        self.max_rows = max_rows

    def process_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        max_rows: Optional[int] = None,
    ) -> Tuple[pd.DataFrame, FeaturePipelineStats]:
        effective_max_rows = max_rows if max_rows is not None else self.max_rows
        df = load_dataset(input_path, max_rows=effective_max_rows)

        output_df, stats = self.process_dataframe(df)

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Saving {len(output_df)} statement rows to {output_path}...")
            output_df.to_csv(output_path, index=False, encoding="utf-8")

        return output_df, stats

    def process_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, FeaturePipelineStats]:
        df = normalize_dataframe(df)
        stats = FeaturePipelineStats(total_input_rows=len(df))
        rows: List[dict] = []

        for index, row in df.iterrows():
            raw_lang = str(row.get("language", "") or "").strip().lower()
            schema = get_schema(raw_lang)
            if schema is None:
                logger.warning(f"Unsupported/out-of-scope language '{raw_lang}' at row {index}")
                stats.skipped_unsupported_language += 1
                continue

            language = "typescript" if raw_lang in ("typescript", "ts", "tsx") else schema.language

            vulnerable_code = row.get("vulnerable_code")
            fixed_code = row.get("fixed_code")
            has_vulnerable_code = isinstance(vulnerable_code, str) and bool(vulnerable_code.strip())
            has_fixed_code = isinstance(fixed_code, str) and bool(fixed_code.strip())

            if not has_vulnerable_code and not has_fixed_code:
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
            id_base = f"{base_meta['repo']}:{base_meta['file']}:{base_meta['method']}:{index}"
            is_unchanged = has_vulnerable_code and has_fixed_code and vulnerable_code.strip() == fixed_code.strip()

            try:
                if is_unchanged:
                    safe_meta = {**base_meta, "vulnerability_type": "none"}
                    safe_roots, _safe_source = build_statement_tree(
                        vulnerable_code, language, schema, f"{id_base}:unchanged"
                    )
                    if not safe_roots:
                        stats.skipped_no_code += 1
                        continue
                    self._emit(safe_roots, schema, language, safe_meta, "unchanged", force_label_zero=True, rows=rows, stats=stats)

                elif has_vulnerable_code and has_fixed_code:
                    v_roots, v_source = build_statement_tree(vulnerable_code, language, schema, f"{id_base}:vulnerable")
                    f_roots, f_source = build_statement_tree(fixed_code, language, schema, f"{id_base}:fixed_ref")
                    label_statements(v_roots, f_roots, v_source, f_source)
                    self._emit(v_roots, schema, language, base_meta, "vulnerable", force_label_zero=False, rows=rows, stats=stats)

                    fixed_safe_meta = {**base_meta, "vulnerability_type": "none"}
                    fixed_safe_roots, _fs_source = build_statement_tree(
                        fixed_code, language, schema, f"{id_base}:fixed"
                    )
                    self._emit(fixed_safe_roots, schema, language, fixed_safe_meta, "fixed", force_label_zero=True, rows=rows, stats=stats)

                    if not v_roots and not fixed_safe_roots:
                        stats.skipped_no_code += 1

                elif has_vulnerable_code and not has_fixed_code:
                    # Unpaired vulnerable row (e.g. code_vulnerabilities.csv or CVEFixes safety="vulnerable")
                    v_roots, _v_source = build_statement_tree(vulnerable_code, language, schema, f"{id_base}:vulnerable")
                    if not v_roots:
                        stats.skipped_no_code += 1
                        continue
                    self._emit_unpaired_vulnerable(v_roots, schema, language, base_meta, rows=rows, stats=stats)

                else:
                    # Unpaired safe/fixed row (e.g. CVEFixes safety="safe")
                    fixed_safe_meta = {**base_meta, "vulnerability_type": "none"}
                    fixed_safe_roots, _fs_source = build_statement_tree(
                        fixed_code, language, schema, f"{id_base}:fixed"
                    )
                    if not fixed_safe_roots:
                        stats.skipped_no_code += 1
                        continue
                    self._emit(fixed_safe_roots, schema, language, fixed_safe_meta, "fixed", force_label_zero=True, rows=rows, stats=stats)

            except Exception as e:
                logger.warning(f"Statement extraction failed at row {index}: {e}")
                stats.skipped_extraction_failure += 1
                continue

        output_df = pd.DataFrame(rows, columns=_STATEMENT_RECORD_COLUMNS) if rows else pd.DataFrame(columns=_STATEMENT_RECORD_COLUMNS)
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

    @staticmethod
    def _emit_unpaired_vulnerable(
        roots,
        schema,
        language: str,
        row_meta: Dict[str, str],
        rows: List[dict],
        stats: FeaturePipelineStats,
    ) -> None:
        """
        Emits statements for a vulnerable row that has no `fixed_code` to diff
        against. If the code contains multiple statements and at least one
        matches a Category D dangerous sink/concat signature, only those sink
        statements receive label=1 (while non-sink boilerplate receives label=0).
        Otherwise (e.g. a single-statement snippet or a vulnerability pattern
        outside the sink dictionary), all statements in the vulnerable snippet
        receive label=1.
        """
        if not roots:
            return

        flat_nodes = flatten(roots)
        id_to_node = {n.statement_id: n for n in flat_nodes}
        records = [
            extract_features(node, id_to_node, schema, language, row_meta, origin="vulnerable")
            for node in flat_nodes
        ]

        sink_Flags = [_has_dangerous_sink(r) for r in records]
        if len(records) > 1 and any(sink_Flags):
            for rec, is_sink in zip(records, sink_Flags):
                rec.label = 1 if is_sink else 0
        else:
            for rec in records:
                rec.label = 1

        for rec in records:
            rows.append(rec.__dict__)
            if rec.label:
                stats.total_positive_labels += 1
            stats.total_from_vulnerable_side += 1
