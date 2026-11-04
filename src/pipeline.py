"""
Core Data Pipeline for CVE Code Pair Processing (Statement-level and Method-level).
"""

import logging
from pathlib import Path
from typing import Optional, Tuple, Union

import pandas as pd

from .config import DEFAULT_MAX_ROWS
from .dataset_loader import CANONICAL_COLUMNS, load_dataset, normalize_dataframe
from .extractors import get_extractor
from .models import CodePair, PairingResult, PairingStatus, PipelineStats
from .strategies import AlignedPairingStrategy, BasePairingStrategy, StrictZipPairingStrategy

logger = logging.getLogger(__name__)


class CveMethodPipeline:
    """
    Orchestrates the transformation of raw vulnerability dataset records into
    statement-level or method-level granularity pairs.
    """

    def __init__(
        self,
        pairing_strategy: Optional[BasePairingStrategy] = None,
        granularity: str = "statement",
        max_rows: Optional[int] = DEFAULT_MAX_ROWS,
    ) -> None:
        self.granularity = granularity.lower().strip()
        self.max_rows = max_rows
        if pairing_strategy is not None:
            self.pairing_strategy = pairing_strategy
        else:
            self.pairing_strategy = (
                AlignedPairingStrategy()
                if self.granularity == "statement"
                else StrictZipPairingStrategy()
            )

    def process_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        max_rows: Optional[int] = None,
    ) -> Tuple[pd.DataFrame, PipelineStats]:
        """
        Reads input CSV (any supported format), normalizes schema, extracts code
        snippets, pairs them, and optionally writes output CSV.
        """
        effective_max_rows = max_rows if max_rows is not None else self.max_rows
        df = load_dataset(input_path, max_rows=effective_max_rows)

        output_df, stats = self.process_dataframe(df)

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Saving {len(output_df)} processed rows to {output_path}...")
            output_df.to_csv(output_path, index=False, encoding="utf-8")

        return output_df, stats

    def process_dataframe(
        self,
        df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, PipelineStats]:
        """
        Processes an in-memory DataFrame row by row after normalizing its schema.
        Supports both paired (vulnerable_code + fixed_code) and single-sided
        (vulnerable-only or safe/fixed-only) datasets.
        """
        df = normalize_dataframe(df)
        stats = PipelineStats(total_input_rows=len(df))
        output_rows = []

        for index, row in df.iterrows():
            language = str(row.get("language", "") or "").strip().lower()
            vulnerable_code = row.get("vulnerable_code")
            fixed_code = row.get("fixed_code")

            extractor = get_extractor(language)
            if not extractor:
                logger.warning(
                    f"Unsupported language '{language}' at row {index}"
                )
                stats.skipped_unsupported_language += 1
                continue

            has_vulnerable = isinstance(vulnerable_code, str) and bool(vulnerable_code.strip())
            has_fixed = isinstance(fixed_code, str) and bool(fixed_code.strip())

            if not has_vulnerable and not has_fixed:
                logger.warning(f"No code snippets found at row {index}")
                stats.skipped_no_code += 1
                continue

            row_orig_granularity = str(row.get("granularity", "") or "").strip().lower()

            if self.granularity == "statement":
                vulnerable_snippets = extractor.extract_statements(vulnerable_code) if has_vulnerable else []
                fixed_snippets = extractor.extract_statements(fixed_code) if has_fixed else []
            else:
                vulnerable_snippets = extractor.extract_methods(vulnerable_code) if has_vulnerable else []
                if has_vulnerable and not vulnerable_snippets and row_orig_granularity == "statement":
                    vulnerable_snippets = extractor.extract_statements(vulnerable_code)
                fixed_snippets = extractor.extract_methods(fixed_code) if has_fixed else []
                if has_fixed and not fixed_snippets and row_orig_granularity == "statement":
                    fixed_snippets = extractor.extract_statements(fixed_code)

            if has_vulnerable and has_fixed:
                pairing_result = self.pairing_strategy.pair(
                    vulnerable_snippets=vulnerable_snippets,
                    fixed_snippets=fixed_snippets,
                )
            elif has_vulnerable and not has_fixed:
                if not vulnerable_snippets:
                    pairing_result = PairingResult(status=PairingStatus.NO_VULNERABLE_CODE)
                else:
                    pairing_result = PairingResult(
                        status=PairingStatus.SUCCESS,
                        pairs=[CodePair(vulnerable_code=v, fixed_code="") for v in vulnerable_snippets],
                    )
            else:
                # Safe / fixed-only row (e.g. safety="safe" in CVEFixes.csv)
                if not fixed_snippets:
                    pairing_result = PairingResult(status=PairingStatus.NO_VULNERABLE_CODE)
                else:
                    pairing_result = PairingResult(
                        status=PairingStatus.SUCCESS,
                        pairs=[CodePair(vulnerable_code="", fixed_code=f) for f in fixed_snippets],
                    )

            if pairing_result.status in (PairingStatus.NO_VULNERABLE_CODE, PairingStatus.NO_VULNERABLE_METHODS):
                logger.warning(f"No snippets found at row {index}")
                stats.skipped_no_code += 1
                continue

            elif pairing_result.status == PairingStatus.MISMATCH:
                logger.warning(
                    f"Snippet count mismatch at row {index}: "
                    f"vulnerable={len(vulnerable_snippets)}, "
                    f"fixed={len(fixed_snippets)}"
                )
                stats.skipped_mismatch += 1
                continue

            elif pairing_result.status == PairingStatus.SUCCESS:
                for pair in pairing_result.pairs:
                    new_row = row.to_dict()
                    new_row["vulnerable_code"] = pair.vulnerable_code
                    new_row["fixed_code"] = pair.fixed_code
                    new_row["granularity"] = self.granularity
                    output_rows.append(new_row)

        if output_rows:
            output_df = pd.DataFrame(output_rows)
            ordered = [c for c in CANONICAL_COLUMNS if c in output_df.columns]
            extra = [c for c in output_df.columns if c not in ordered]
            output_df = output_df[ordered + extra]
        else:
            output_df = pd.DataFrame(columns=CANONICAL_COLUMNS)

        stats.total_output_rows = len(output_df)
        return output_df, stats


# Backward compatibility alias
CvePipeline = CveMethodPipeline
