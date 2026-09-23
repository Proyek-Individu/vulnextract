"""
Core Data Pipeline for CVE Method Pair Processing.
"""

import logging
from pathlib import Path
from typing import Optional, Tuple, Union

import pandas as pd

from .extractors import get_extractor
from .models import PairingStatus, PipelineStats
from .strategies import BasePairingStrategy, StrictZipPairingStrategy

logger = logging.getLogger(__name__)


class CveMethodPipeline:
    """
    Orchestrates the transformation of raw CVE commit records into method-level granularity pairs.
    """

    def __init__(
        self,
        pairing_strategy: Optional[BasePairingStrategy] = None
    ) -> None:
        self.pairing_strategy = pairing_strategy or StrictZipPairingStrategy()

    def process_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None
    ) -> Tuple[pd.DataFrame, PipelineStats]:
        """
        Reads input CSV, extracts methods, pairs them, and optionally writes output CSV.

        Args:
            input_path: Path to the input CSV file.
            output_path: Optional path to save the resulting DataFrame.

        Returns:
            Tuple[pd.DataFrame, PipelineStats]: Processed DataFrame and pipeline metrics.
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found at: {input_path}")

        logger.info(f"Loading input dataset from {input_path}...")
        df = pd.read_csv(input_path)

        output_df, stats = self.process_dataframe(df)

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info(f"Saving {len(output_df)} processed rows to {output_path}...")
            output_df.to_csv(output_path, index=False, encoding="utf-8")

        return output_df, stats

    def process_dataframe(
        self,
        df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, PipelineStats]:
        """
        Processes an in-memory DataFrame row by row.

        Args:
            df: Raw DataFrame containing vulnerable_code and fixed_code.

        Returns:
            Tuple[pd.DataFrame, PipelineStats]: Transformed DataFrame and execution metrics.
        """
        stats = PipelineStats(total_input_rows=len(df))
        output_rows = []

        for index, row in df.iterrows():
            language = str(row.get("language", "")).strip().lower()
            vulnerable_code = row.get("vulnerable_code")
            fixed_code = row.get("fixed_code")

            extractor = get_extractor(language)
            if not extractor:
                logger.warning(
                    f"Unsupported language '{language}' at row {index}"
                )
                stats.skipped_unsupported_language += 1
                continue

            vulnerable_methods = extractor.extract_methods(vulnerable_code)
            fixed_methods = extractor.extract_methods(fixed_code)

            pairing_result = self.pairing_strategy.pair(
                vulnerable_methods=vulnerable_methods,
                fixed_methods=fixed_methods
            )

            if pairing_result.status == PairingStatus.NO_VULNERABLE_METHODS:
                logger.warning(
                    f"No vulnerable method found at row {index}"
                )
                stats.skipped_no_methods += 1
                continue

            elif pairing_result.status == PairingStatus.MISMATCH:
                logger.warning(
                    f"Method count mismatch at row {index}: "
                    f"vulnerable={len(vulnerable_methods)}, "
                    f"fixed={len(fixed_methods)}"
                )
                stats.skipped_mismatch += 1
                continue

            elif pairing_result.status == PairingStatus.SUCCESS:
                for pair in pairing_result.pairs:
                    new_row = row.to_dict()
                    new_row["vulnerable_code"] = pair.vulnerable_method
                    new_row["fixed_code"] = pair.fixed_method
                    new_row["granularity"] = "method"
                    output_rows.append(new_row)

        output_df = pd.DataFrame(output_rows)
        stats.total_output_rows = len(output_df)

        return output_df, stats
