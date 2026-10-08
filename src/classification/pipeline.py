"""
Mode "classify" (menu 3): trains the models configured in global.yaml on
both the raw method-level data and the split statement-level data, with
the same group-level train/test partition, explains every model (XAI), and
writes a comparison report (CSV/XLSX).
"""

import copy
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from ..config import (
    DEFAULT_CLASSIFICATION,
    as_input_path,
    is_url,
    resolve_path,
)
from ..feature_pipeline import FeatureExtractionPipeline
from . import report
from .datasets import (
    RawFeatureBuilder,
    StatementFeatureBuilder,
    build_raw_methods,
    build_statements,
    make_folds,
)
from .explain import explain_model
from .metrics import aggregate_to_methods, compute_metrics
from .model_registry import ModelSpec, build_model_specs, predict_scores

logger = logging.getLogger(__name__)

_TEXT_PREVIEW = 300  # chars of raw code/statement kept in the predictions sheet


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class ClassificationResult:
    run_dir: Path
    metrics: pd.DataFrame
    summary: pd.DataFrame
    comparison: pd.DataFrame
    files: List[Path] = field(default_factory=list)


class ClassificationPipeline:
    def __init__(self, overrides: Optional[Dict[str, Any]] = None):
        """`overrides` is merged over global.yaml's `classification:` block
        (used by the interactive menu / CLI flags for one-off changes)."""
        self.cfg = _deep_merge(DEFAULT_CLASSIFICATION, overrides or {})

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    def run(self) -> ClassificationResult:
        raw_input = as_input_path(str(self.cfg["raw_input"]))
        split_input = resolve_path(str(self.cfg["split_input"]))

        if not is_url(str(raw_input)) and not Path(raw_input).exists():
            raise FileNotFoundError(f"Data mentah tidak ditemukan: {raw_input}")
        logger.info(f"Membaca data mentah dari {raw_input}...")
        raw_df = pd.read_csv(raw_input)

        if split_input.exists():
            logger.info(f"Membaca data split dari {split_input}...")
            split_df = pd.read_csv(split_input)
        else:
            logger.info(f"Data split belum ada di {split_input} — menjalankan ekstraksi features dulu...")
            split_df, _ = FeatureExtractionPipeline().process_file(raw_input, split_input)

        return self.run_frames(raw_df, split_df, resolve_path(str(self.cfg["output_dir"])))

    def run_frames(self, raw_df: pd.DataFrame, split_df: pd.DataFrame, output_dir: Union[str, Path]) -> ClassificationResult:
        cfg = self.cfg
        split_cfg = cfg["split"]
        xai_cfg = cfg["xai"]
        random_state = int(split_cfg.get("random_state", 42))
        threshold = float(cfg.get("threshold", 0.5))
        group_by = str(split_cfg.get("group_by", "method"))

        raw_methods = build_raw_methods(raw_df, group_by)
        statements = build_statements(split_df, raw_df, group_by)
        if cfg.get("align_samples", True):
            before = len(raw_methods)
            raw_methods = raw_methods[raw_methods["method_id"].isin(set(statements["method_id"]))].reset_index(drop=True)
            if before != len(raw_methods):
                logger.info(
                    f"align_samples: data mentah dipersempit {before} -> {len(raw_methods)} method "
                    "(hanya method yang juga ada di data split, mis. bahasa yang didukung mode features)"
                )
        if raw_methods.empty or statements.empty:
            raise ValueError("Data kosong setelah diproses — cek input mentah & data split")

        folds = make_folds(raw_methods, statements, float(split_cfg.get("test_size", 0.2)),
                           int(split_cfg.get("cv_folds", 0) or 0), random_state)
        specs = build_model_specs(cfg.get("models"), random_state)
        logger.info(f"Model: {', '.join(s.label for s in specs)} | fold: {len(folds)} | grup: {group_by}")

        metric_rows, pred_frames, importance_frames, local_frames, info_rows, note_rows = [], [], [], [], [], []
        method_meta = raw_methods.set_index("method_id")

        for fold_no, (train_groups, test_groups) in enumerate(folds, start=1):
            raw_tr = raw_methods[raw_methods["group"].isin(train_groups)].reset_index(drop=True)
            raw_te = raw_methods[raw_methods["group"].isin(test_groups)].reset_index(drop=True)
            st_tr = statements[statements["group"].isin(train_groups)].reset_index(drop=True)
            st_te = statements[statements["group"].isin(test_groups)].reset_index(drop=True)

            raw_builder = RawFeatureBuilder(cfg.get("raw_features") or {})
            st_builder = StatementFeatureBuilder(cfg.get("split_features") or {})
            datasets = {
                "raw": (raw_tr, raw_te, raw_builder.fit_transform(raw_tr), raw_builder.transform(raw_te),
                        raw_builder.feature_names, "method_id"),
                "split": (st_tr, st_te, st_builder.fit_transform(st_tr), st_builder.transform(st_te),
                          st_builder.feature_names, "statement_id"),
            }

            for approach, (tr, te, X_tr, X_te, names, id_col) in datasets.items():
                info_rows.append({
                    "fold": fold_no, "approach": approach,
                    "unit": "method" if approach == "raw" else "statement",
                    "n_train": len(tr), "n_train_pos": int(tr["label"].sum()),
                    "n_test": len(te), "n_test_pos": int(te["label"].sum()),
                    "n_features": X_tr.shape[1],
                    "n_train_groups": tr["group"].nunique(), "n_test_groups": te["group"].nunique(),
                })

            for spec in specs:
                for approach, (tr, te, X_tr, X_te, names, id_col) in datasets.items():
                    y_tr = tr["label"].to_numpy()
                    y_te = te["label"].to_numpy()
                    if len(np.unique(y_tr)) < 2 or len(te) == 0:
                        logger.warning(f"[fold {fold_no}] {approach}/{spec.label}: train hanya 1 kelas atau test kosong — dilewati")
                        continue

                    model, scores, seconds, X_tr_m, X_te_m = self._fit_predict(spec, X_tr, y_tr, X_te)
                    level = "method" if approach == "raw" else "statement"
                    metric_rows.append(self._metric_row(fold_no, approach, level, spec.label, y_te, scores,
                                                        threshold, seconds))
                    pred_frames.append(self._predictions(fold_no, approach, level, spec.label, te, scores,
                                                         threshold, id_col))

                    if approach == "split":
                        st_pred = te[["method_id", "method_label", "group"]].assign(y_score=scores)
                        agg = aggregate_to_methods(st_pred, str(cfg.get("method_aggregation", "max")))
                        metric_rows.append(self._metric_row(fold_no, "split", "method", spec.label,
                                                            agg["y_true"], agg["y_score"], threshold, seconds))
                        pred_frames.append(self._aggregated_predictions(fold_no, spec.label, agg, threshold, method_meta))

                    if xai_cfg.get("enabled", True):
                        logger.info(f"[fold {fold_no}] XAI {approach}/{spec.label}...")
                        expl = explain_model(model, X_tr_m, X_te_m, y_te, scores, names,
                                             te[id_col].astype(str).tolist(), X_te, xai_cfg,
                                             threshold, random_state)
                        tag = {"fold": fold_no, "approach": approach, "model": spec.label}
                        importance_frames.append(expl.global_importance.assign(**tag))
                        if not expl.local.empty:
                            text_col = "code" if approach == "raw" else "raw_text"
                            preview = (te.set_index(te[id_col].astype(str))[text_col]
                                       .fillna("").astype(str).str.slice(0, _TEXT_PREVIEW))
                            preview = preview[~preview.index.duplicated()]
                            local = expl.local.assign(**tag)
                            local["text_preview"] = local["sample_id"].map(preview)
                            local_frames.append(local)
                        note_rows.extend({**tag, "note": n} for n in expl.notes)

        if not metric_rows:
            raise ValueError("Tidak ada model yang berhasil dilatih (cek distribusi label / konfigurasi split)")

        metrics = pd.DataFrame(metric_rows)
        summary = report.build_summary(metrics)
        comparison = report.build_comparison(metrics)
        importance = _concat_front(importance_frames, ["fold", "approach", "model"])
        importance_mean = report.mean_importance(importance)

        tables = {
            "README": report.readme_table(),
            "comparison": comparison,
            "summary": summary,
            "metrics_per_fold": metrics,
            "feature_importance": importance_mean,
            "feature_importance_folds": importance,
            "local_explanations": _concat_front(local_frames, ["fold", "approach", "model"]),
            "predictions": pd.concat(pred_frames, ignore_index=True),
            "dataset_info": pd.DataFrame(info_rows),
            "xai_notes": pd.DataFrame(note_rows),
            "config": report.config_table(cfg),
        }
        if len(folds) == 1:
            tables.pop("feature_importance_folds")  # identical to feature_importance

        run_dir = Path(output_dir) / f"run_{datetime.now():%Y%m%d_%H%M%S}"
        files = report.write_outputs(tables, run_dir, cfg.get("output_formats") or ["xlsx"])
        if xai_cfg.get("enabled", True) and xai_cfg.get("save_plots", True) and not importance_mean.empty:
            files += report.save_plots(importance_mean, run_dir / "plots", int(xai_cfg.get("top_k", 20)))

        return ClassificationResult(run_dir=run_dir, metrics=metrics, summary=summary,
                                    comparison=comparison, files=files)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fit_predict(spec: ModelSpec, X_tr: np.ndarray, y_tr: np.ndarray, X_te: np.ndarray):
        if spec.scale:
            scaler = StandardScaler().fit(X_tr)
            X_tr, X_te = scaler.transform(X_tr), scaler.transform(X_te)
        model = spec.new_estimator()
        start = time.perf_counter()
        model.fit(X_tr, y_tr)
        seconds = time.perf_counter() - start
        return model, predict_scores(model, X_te), seconds, X_tr, X_te

    @staticmethod
    def _metric_row(fold, approach, level, model, y_true, scores, threshold, seconds) -> Dict[str, Any]:
        y_true = np.asarray(y_true, dtype=int)
        return {
            "fold": fold, "approach": approach, "eval_level": level, "model": model,
            "n_test": len(y_true), "n_test_pos": int(y_true.sum()),
            **compute_metrics(y_true, scores, threshold),
            "train_seconds": round(seconds, 3),
        }

    @staticmethod
    def _predictions(fold, approach, level, model, te: pd.DataFrame, scores, threshold, id_col) -> pd.DataFrame:
        if approach == "raw":
            meta_cols = ["method_id", "cve_id", "vulnerability_type", "language", "method", "side"]
            text = te["code"]
        else:
            meta_cols = ["statement_id", "method_id", "cve_id", "vulnerability_type", "language",
                         "function_name", "side", "statement_type"]
            text = te["raw_text"]
        out = pd.DataFrame({
            "fold": fold, "approach": approach, "eval_level": level, "model": model,
            "sample_id": te[id_col].astype(str), "group": te["group"],
            "y_true": te["label"].astype(int), "y_score": scores,
            "y_pred": (np.asarray(scores) >= threshold).astype(int),
        })
        for col in meta_cols:
            if col in te:
                out[col] = te[col].to_numpy()
        out["text_preview"] = text.fillna("").astype(str).str.slice(0, _TEXT_PREVIEW).to_numpy()
        return out

    @staticmethod
    def _aggregated_predictions(fold, model, agg: pd.DataFrame, threshold, method_meta: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame({
            "fold": fold, "approach": "split", "eval_level": "method", "model": model,
            "sample_id": agg["method_id"], "group": agg["group"],
            "y_true": agg["y_true"].astype(int), "y_score": agg["y_score"],
            "y_pred": (agg["y_score"] >= threshold).astype(int),
            "method_id": agg["method_id"], "n_statements": agg["n_statements"],
        })
        for col in ("cve_id", "vulnerability_type", "language", "method", "side"):
            out[col] = agg["method_id"].map(method_meta[col]) if col in method_meta else ""
        return out


def _concat_front(frames: List[pd.DataFrame], front: List[str]) -> pd.DataFrame:
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    return df[front + [c for c in df.columns if c not in front]]
