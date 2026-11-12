"""Shared append-only writer for statement-level feature CSV output."""

import csv
import logging
import sys
from pathlib import Path
from typing import Optional, Union

import pandas as pd

from .config import DEFAULT_FEATURES_OUTPUT_FILE

logger = logging.getLogger(__name__)


def _csv_row_count(path: Path) -> int:
    csv.field_size_limit(sys.maxsize)
    with path.open("r", encoding="utf-8-sig", newline="") as output_file:
        reader = csv.reader(output_file)
        next(reader, None)
        return sum(1 for _ in reader)


def append_statement_features(
    output_df: pd.DataFrame,
    output_path: Optional[Union[str, Path]] = None,
) -> Path:
    """Append feature rows without rewriting existing data or repeating its header."""
    path = Path(output_path) if output_path is not None else DEFAULT_FEATURES_OUTPUT_FILE
    columns = list(output_df.columns)
    if len(columns) != len(set(columns)):
        raise ValueError("Feature output contains duplicate column names.")

    path.parent.mkdir(parents=True, exist_ok=True)
    has_existing_data = path.exists() and path.stat().st_size > 0

    if has_existing_data:
        with path.open("r", encoding="utf-8-sig", newline="") as output_file:
            existing_columns = next(csv.reader(output_file), [])
        if len(existing_columns) != len(set(existing_columns)):
            raise ValueError(f"Existing feature output has duplicate columns: {path}")
        if set(columns) != set(existing_columns):
            raise ValueError(
                "Feature output schema does not match the existing file. "
                f"Existing columns: {existing_columns}; new columns: {columns}. "
                "Existing output was not changed."
            )
        output_df = output_df[existing_columns]
        rows_before = _csv_row_count(path)
    else:
        rows_before = 0

    if has_existing_data and output_df.empty:
        return path

    if has_existing_data:
        with path.open("rb") as output_file:
            output_file.seek(-1, 2)
            if output_file.read(1) not in (b"\n", b"\r"):
                with path.open("ab") as output_file:
                    output_file.write(b"\n")

    output_df.to_csv(
        path,
        mode="a",
        index=False,
        header=not has_existing_data,
        encoding="utf-8",
        lineterminator="\n",
    )

    rows_after = _csv_row_count(path)
    expected_rows = rows_before + len(output_df)
    if rows_after != expected_rows:
        raise RuntimeError(
            f"Feature output row-count validation failed for {path}: "
            f"expected {expected_rows}, found {rows_after}."
        )

    logger.info(
        "Appended %s statement feature rows to %s (total rows: %s).",
        len(output_df),
        path,
        rows_after,
    )
    return path
