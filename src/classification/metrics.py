"""Evaluation metrics shared by every approach / evaluation level."""

from typing import Dict

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Order of metric columns in every report sheet.
METRIC_COLUMNS = [
    "accuracy", "balanced_accuracy", "precision", "recall", "f1", "mcc", "roc_auc", "pr_auc",
    "tp", "fp", "tn", "fn",
]


def compute_metrics(y_true, y_score, threshold: float = 0.5) -> Dict[str, float]:
    y_true = np.asarray(y_true, dtype=int)
    y_score = np.asarray(y_score, dtype=float)
    y_pred = (y_score >= threshold).astype(int)
    both_classes = len(np.unique(y_true)) == 2
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred) if both_classes else np.nan,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred) if both_classes else np.nan,
        # Threshold-free metrics: undefined when the test fold has one class only.
        "roc_auc": roc_auc_score(y_true, y_score) if both_classes else np.nan,
        "pr_auc": average_precision_score(y_true, y_score) if both_classes else np.nan,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def aggregate_to_methods(statement_preds: pd.DataFrame, how: str = "max") -> pd.DataFrame:
    """Statement-level scores -> one score per method version, so the split
    approach can be scored on exactly the same unit as the raw approach.
    `max`: a method is as suspicious as its most suspicious statement."""
    agg = "mean" if how == "mean" else "max"
    return (
        statement_preds.groupby("method_id", sort=False)
        .agg(y_true=("method_label", "first"), y_score=("y_score", agg), group=("group", "first"),
             n_statements=("y_score", "size"))
        .reset_index()
    )
