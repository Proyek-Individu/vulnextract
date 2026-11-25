"""Shared append-only writer for statement-level feature CSV output."""

import csv
import logging
import sys
from pathlib import Path
from typing import Optional, Union

import pandas as pd

from .config import DEFAULT_FEATURES_OUTPUT_FILE

logger = logging.getLogger(__name__)

_STATEMENT_DEDUPE_COLUMNS = (
    "cve_id", "commit_hash", "language", "file_path", "function_name",
    "line_start", "line_end", "raw_text", "origin",
)


def _dedupe_value(value) -> str:
    return "" if value is None or pd.isna(value) else str(value)


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
    caller_output_df = output_df

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

    skipped_duplicate_rows = 0
    if set(_STATEMENT_DEDUPE_COLUMNS).issubset(output_df.columns):
        if has_existing_data:
            existing = pd.read_csv(
                path,
                dtype=str,
                keep_default_na=False,
                encoding="utf-8-sig",
                usecols=list(_STATEMENT_DEDUPE_COLUMNS),
            )
            seen = {
                tuple(row[col] for col in _STATEMENT_DEDUPE_COLUMNS)
                for _, row in existing.iterrows()
            }
        else:
            seen = set()

        keep_indices = []
        for index, row in output_df.iterrows():
            key = tuple(_dedupe_value(row[col]) for col in _STATEMENT_DEDUPE_COLUMNS)
            if key in seen:
                skipped_duplicate_rows += 1
                continue
            seen.add(key)
            keep_indices.append(index)
        output_df = output_df.loc[keep_indices]
    caller_output_df.attrs["skipped_duplicate_output_rows"] = skipped_duplicate_rows

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
