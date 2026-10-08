"""
Explainable AI (XAI) for every trained model, model-agnostic where possible:

- native importance : feature_importances_ (tree models) or |coef_| (linear
                      models) — free, but model-specific and biased toward
                      high-cardinality features for trees.
- permutation       : drop in test-set score when one feature column is
                      shuffled — model-agnostic, measured on held-out data.
- SHAP              : per-sample additive contributions (TreeExplainer for
                      tree models, LinearExplainer for linear models,
                      optional KernelExplainer for anything else). Gives
                      both a global ranking (mean |SHAP|) and LOCAL
                      explanations: why THIS method/statement was flagged.

SHAP is optional: if the `shap` package isn't installed the run continues
with native + permutation importance only.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    f1_score,
    roc_auc_score,
)

from .model_registry import predict_scores

logger = logging.getLogger(__name__)


@dataclass
class Explanation:
    global_importance: pd.DataFrame
    local: pd.DataFrame
    notes: List[str] = field(default_factory=list)


def _native_importance(model) -> Optional[np.ndarray]:
    if hasattr(model, "feature_importances_"):
        return np.asarray(model.feature_importances_, dtype=float)
    if hasattr(model, "coef_"):
        coef = np.asarray(model.coef_, dtype=float)
        return np.abs(coef).reshape(coef.shape[0], -1).mean(axis=0) if coef.ndim > 1 else np.abs(coef)
    return None


def _scorer(name: str, threshold: float):
    if name == "roc_auc":
        return lambda y, s: roc_auc_score(y, s)
    if name == "f1":
        return lambda y, s: f1_score(y, (s >= threshold).astype(int), zero_division=0)
    if name == "accuracy":
        return lambda y, s: accuracy_score(y, (s >= threshold).astype(int))
    if name == "balanced_accuracy":
        return lambda y, s: balanced_accuracy_score(y, (s >= threshold).astype(int))
    return lambda y, s: average_precision_score(y, s)


def _positive_class_slice(values, base, model):
    """Normalizes the many shapes SHAP returns to (n_samples, n_features)
    for class 1, plus a scalar base value."""
    classes = list(getattr(model, "classes_", [0, 1]))
    pos = classes.index(1) if 1 in classes else -1
    if isinstance(values, list):
        values = values[pos] if len(values) > 1 else values[0]
    values = np.asarray(values, dtype=float)
    if values.ndim == 3:
        values = values[:, :, pos]
    base = np.asarray(base, dtype=float).ravel()
    base_value = float(base[pos] if base.size > 1 else base[0]) if base.size else float("nan")
    return values, base_value


def _shap_values(model, X_background: np.ndarray, X_explain: np.ndarray, cfg: Dict[str, Any], rng):
    try:
        import shap
    except ImportError:
        return None, None, "shap tidak terinstall (pip install shap) — SHAP dilewati"

    try:
        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(X_explain, check_additivity=False)
        values, base = _positive_class_slice(values, explainer.expected_value, model)
        return values, base, "SHAP TreeExplainer"
    except Exception:
        pass

    if hasattr(model, "coef_"):
        try:
            if len(X_background) > 100:  # same cap SHAP applies itself, minus its warning
                X_background = X_background[rng.choice(len(X_background), 100, replace=False)]
            explainer = shap.LinearExplainer(model, X_background)
            values, base = _positive_class_slice(explainer.shap_values(X_explain), explainer.expected_value, model)
            return values, base, "SHAP LinearExplainer (satuan log-odds/margin)"
        except Exception as e:
            logger.debug(f"LinearExplainer gagal: {e}")

    if cfg.get("shap_kernel_fallback"):
        n_bg = min(50, len(X_background))
        background = X_background[rng.choice(len(X_background), n_bg, replace=False)]
        explainer = shap.KernelExplainer(lambda X: predict_scores(model, X), background)
        values = explainer.shap_values(X_explain, nsamples="auto", silent=True)
        values, base = _positive_class_slice(values, explainer.expected_value, model)
        return values, base, "SHAP KernelExplainer (lambat, model-agnostik)"

    return None, None, (
        "model ini tidak didukung Tree/LinearExplainer — SHAP dilewati "
        "(set classification.xai.shap_kernel_fallback: true untuk KernelExplainer)"
    )


def _column_corr(X: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Per-feature Pearson correlation between feature value and SHAP value
    (NaN where either is constant)."""
    xc = X - X.mean(axis=0)
    vc = values - values.mean(axis=0)
    denom = np.sqrt((xc ** 2).sum(axis=0) * (vc ** 2).sum(axis=0))
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(denom > 0, (xc * vc).sum(axis=0) / denom, np.nan)


def _permutation_importance(model, X, y, candidates, repeats, scorer, rng):
    base = scorer(y, predict_scores(model, X))
    work = X.copy()
    means, stds = {}, {}
    for j in candidates:
        original = work[:, j].copy()
        drops = []
        for _ in range(repeats):
            work[:, j] = rng.permutation(original)
            drops.append(base - scorer(y, predict_scores(model, work)))
        work[:, j] = original
        means[j], stds[j] = float(np.mean(drops)), float(np.std(drops))
    return means, stds


def explain_model(
    model,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    scores: np.ndarray,
    feature_names: List[str],
    sample_ids: List[str],
    X_test_display: np.ndarray,
    cfg: Dict[str, Any],
    threshold: float = 0.5,
    random_state: int = 42,
) -> Explanation:
    """`X_train`/`X_test` are what the model was fit on (possibly scaled);
    `X_test_display` holds the same rows unscaled, so local explanations
    report human-readable feature values."""
    rng = np.random.default_rng(random_state)
    n_features = X_test.shape[1]
    # Permutation calls predict hundreds of times on small matrices, where
    # spinning up a parallel pool per call costs more than the prediction.
    if "n_jobs" in model.get_params():
        try:
            model.set_params(n_jobs=1)
        except Exception:
            pass
    y_test = np.asarray(y_test, dtype=int)
    notes: List[str] = []
    table = pd.DataFrame({"feature": feature_names})

    native = _native_importance(model)
    table["native_importance"] = native if native is not None and len(native) == n_features else np.nan

    # --- SHAP (global mean |SHAP| + local explanations) ---
    local_df = pd.DataFrame()
    shap_mean_abs = None
    if cfg.get("shap", True):
        n_local = int(cfg.get("local_explanations", 10))
        cap = int(cfg.get("shap_max_samples", 300))
        order = np.argsort(-scores)
        top_idx = list(order[:n_local])
        if cap >= len(X_test):
            explain_idx = np.arange(len(X_test))
        else:
            rest = np.setdiff1d(np.arange(len(X_test)), top_idx)
            extra = rng.choice(rest, max(0, min(len(rest), cap - len(top_idx))), replace=False)
            explain_idx = np.array(sorted(set(top_idx) | set(extra.tolist())))

        values, base, note = _shap_values(model, X_train, X_test[explain_idx], cfg, rng)
        notes.append(note)
        if values is not None:
            shap_mean_abs = np.abs(values).mean(axis=0)
            table["shap_mean_abs"] = shap_mean_abs
            table["shap_mean"] = values.mean(axis=0)  # sign: >0 pushes toward "vulnerable" on average
            # Direction like a SHAP beeswarm: >0 = HIGHER feature value pushes
            # toward "vulnerable", <0 = higher value pushes toward "aman".
            table["shap_value_corr"] = _column_corr(X_test_display[explain_idx], values)

            position = {idx: k for k, idx in enumerate(explain_idx)}
            top_k = int(cfg.get("top_k", 20))
            local_rows = []
            for rank_sample, idx in enumerate(top_idx, start=1):
                contrib = values[position[idx]]
                for rank_feat, j in enumerate(np.argsort(-np.abs(contrib))[:top_k], start=1):
                    if contrib[j] == 0:
                        break
                    local_rows.append({
                        "sample_rank": rank_sample,
                        "sample_id": sample_ids[idx],
                        "y_true": int(y_test[idx]),
                        "y_score": float(scores[idx]),
                        "y_pred": int(scores[idx] >= threshold),
                        "base_value": base,
                        "contribution_rank": rank_feat,
                        "feature": feature_names[j],
                        "feature_value": float(X_test_display[idx, j]),
                        "shap_value": float(contrib[j]),
                        "direction": "-> vulnerable" if contrib[j] > 0 else "-> aman",
                    })
            local_df = pd.DataFrame(local_rows)
    else:
        notes.append("SHAP dimatikan (classification.xai.shap: false)")

    # --- permutation importance (held-out test set) ---
    table["permutation_mean"] = np.nan
    table["permutation_std"] = np.nan
    if cfg.get("permutation", True):
        scoring = str(cfg.get("permutation_scoring", "average_precision"))
        if scoring in ("average_precision", "roc_auc") and len(np.unique(y_test)) < 2:
            notes.append(f"permutation dilewati: test fold hanya punya satu kelas (scoring={scoring})")
        else:
            max_features = int(cfg.get("permutation_max_features", 100))
            if n_features <= max_features:
                candidates = np.arange(n_features)
            else:
                ranking = shap_mean_abs if shap_mean_abs is not None else (
                    native if native is not None else X_test.var(axis=0))
                candidates = np.argsort(-ranking)[:max_features]
                notes.append(f"permutation hanya untuk {max_features} fitur teratas (dari {n_features})")
            means, stds = _permutation_importance(
                model, X_test, y_test, candidates, int(cfg.get("permutation_repeats", 5)),
                _scorer(scoring, threshold), rng,
            )
            table.loc[list(means), "permutation_mean"] = list(means.values())
            table.loc[list(stds), "permutation_std"] = list(stds.values())

    primary = next((c for c in ("shap_mean_abs", "permutation_mean", "native_importance")
                    if c in table and table[c].notna().any()), None)
    table["importance_basis"] = primary or ""
    if primary:
        table = table.sort_values(primary, ascending=False, na_position="last")
    table.insert(0, "rank", range(1, len(table) + 1))
    return Explanation(global_importance=table.reset_index(drop=True), local=local_df, notes=notes)
