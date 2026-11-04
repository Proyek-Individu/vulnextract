"""
Turns the per-fold results into comparison tables and writes them as
CSV and/or XLSX (one sheet per table), plus optional importance plots.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from .metrics import METRIC_COLUMNS

logger = logging.getLogger(__name__)

# (approach, eval_level) -> column title in the comparison sheet.
COMPARISON_COLUMNS = [
    (("raw", "method"), "raw | method"),
    (("split", "method"), "split | method (agregasi statement)"),
    (("split", "statement"), "split | statement"),
]
DELTA_COLUMN = "selisih (split - raw) @method"

README_ROWS = [
    ("Tujuan", "Membandingkan klasifikasi vulnerable vs aman dari DATA MENTAH vs DATA HASIL SPLIT (aturan statement-level)."),
    ("approach = raw", "1 sampel = 1 method dari CSV mentah. vulnerable_code -> label 1, fixed_code -> label 0. "
                       "Fitur: TF-IDF token kode utuh (tanpa AST/aturan split)."),
    ("approach = split", "1 sampel = 1 statement dari hasil menu 2 (features). Label dari diff (1 = statement yang berubah di fix). "
                         "Fitur: kolom terstruktur kategori A-F (context.md)."),
    ("eval_level = statement", "Skor per statement (hanya approach split)."),
    ("eval_level = method", "Skor per method. Untuk split: skor method = agregasi (max/mean) skor statement-nya, "
                            "label method = 1 bila berasal dari vulnerable_code. Unit & sampel test SAMA dengan raw -> "
                            "inilah perbandingan apple-to-apple."),
    ("Pembagian data", "Train/test dibagi per GRUP (default: per method) dan dipakai identik oleh kedua approach, "
                       "sehingga versi vulnerable & fixed dari method yang sama tidak terpisah (mencegah kebocoran)."),
    ("comparison", "Ringkasan utama: tiap baris = (model, metrik), kolom = approach/level. Nilai = rata-rata antar fold."),
    ("summary", "Rata-rata (& std bila k-fold) semua metrik per approach/level/model."),
    ("metrics_per_fold", "Metrik mentah tiap fold."),
    ("feature_importance", "XAI global: native importance, permutation importance (penurunan skor test saat fitur diacak), "
                           "mean |SHAP| (besar pengaruh), shap_value_corr (arah: >0 = nilai fitur tinggi mendorong ke vulnerable)."),
    ("local_explanations", "XAI lokal (SHAP): untuk sampel test dengan skor tertinggi, fitur apa yang mendorong prediksi."),
    ("predictions", "Prediksi tiap sampel test (y_true, y_score, y_pred) + metadata untuk ditelusuri balik."),
    ("dataset_info", "Jumlah sampel/positif/fitur/grup per fold dan approach."),
    ("xai_notes", "Catatan metode XAI yang dipakai/dilewati per model."),
    ("pr_auc / mcc", "Lebih informatif dari accuracy untuk data tidak seimbang (label 1 di level statement sangat sedikit)."),
]


def build_summary(metrics: pd.DataFrame) -> pd.DataFrame:
    keys = ["approach", "eval_level", "model"]
    numeric = [c for c in METRIC_COLUMNS + ["n_test", "n_test_pos", "train_seconds"] if c in metrics]
    grouped = metrics.groupby(keys, sort=False)[numeric]
    summary = grouped.mean()
    if metrics["fold"].nunique() > 1:
        std = grouped.std().add_suffix("_std")
        summary = summary.join(std)
    summary.insert(0, "n_folds", metrics.groupby(keys, sort=False)["fold"].nunique())
    return summary.reset_index()


def build_comparison(metrics: pd.DataFrame) -> pd.DataFrame:
    multi_fold = metrics["fold"].nunique() > 1
    metric_names = [m for m in METRIC_COLUMNS if m not in ("tp", "fp", "tn", "fn")]
    rows = []
    for model, model_df in metrics.groupby("model", sort=False):
        for metric in metric_names:
            row: Dict[str, Any] = {"model": model, "metric": metric}
            for (approach, level), title in COMPARISON_COLUMNS:
                values = model_df.loc[(model_df["approach"] == approach) & (model_df["eval_level"] == level), metric]
                row[title] = values.mean() if len(values) else np.nan
                if multi_fold:
                    row[f"{title} (std)"] = values.std() if len(values) else np.nan
            row[DELTA_COLUMN] = row["split | method (agregasi statement)"] - row["raw | method"]
            rows.append(row)
    return pd.DataFrame(rows)


def mean_importance(importance: pd.DataFrame) -> pd.DataFrame:
    """Importance averaged across folds (identical to the fold table when holdout)."""
    if importance.empty:
        return importance
    value_cols = [c for c in ("native_importance", "permutation_mean", "permutation_std",
                              "shap_mean_abs", "shap_mean", "shap_value_corr") if c in importance]
    out = (importance.groupby(["approach", "model", "feature"], sort=False)[value_cols]
           .mean().reset_index())
    basis = importance.groupby(["approach", "model"], sort=False)["importance_basis"].first()
    frames = []
    for (approach, model), df in out.groupby(["approach", "model"], sort=False):
        b = basis.get((approach, model), "")
        if b in df:
            df = df.sort_values(b, ascending=False, na_position="last")
        df = df.copy()
        df.insert(3, "rank", range(1, len(df) + 1))
        df["importance_basis"] = b
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def _flatten_config(cfg: Dict[str, Any], prefix: str = "") -> List[Dict[str, str]]:
    rows = []
    for key, value in cfg.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            rows.extend(_flatten_config(value, f"{name}."))
        else:
            rows.append({"key": name, "value": json.dumps(value, ensure_ascii=False, default=str)})
    return rows


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)


def save_plots(importance_mean: pd.DataFrame, plot_dir: Path, top_k: int) -> List[Path]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib tidak terinstall — plot XAI dilewati")
        return []

    plot_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for (approach, model), df in importance_mean.groupby(["approach", "model"], sort=False):
        basis = df["importance_basis"].iloc[0]
        if not basis or basis not in df or df[basis].isna().all():
            continue
        top = df.dropna(subset=[basis]).head(top_k).iloc[::-1]
        if "shap_value_corr" in top and basis == "shap_mean_abs":
            colors = ["#c0392b" if v > 0 else "#2471a3" if v < 0 else "#95a5a6"
                      for v in top["shap_value_corr"].fillna(0)]
        else:
            colors = "#566573"
        fig, ax = plt.subplots(figsize=(9, max(3, 0.35 * len(top) + 1)))
        ax.barh(top["feature"].astype(str), top[basis], color=colors)
        ax.set_xlabel(basis)
        title = f"{approach} - {model}: top {len(top)} fitur ({basis})"
        if basis == "shap_mean_abs":
            title += "\nmerah = nilai fitur makin tinggi -> makin vulnerable, biru = makin aman"
        ax.set_title(title, fontsize=10)
        fig.tight_layout()
        path = plot_dir / f"importance_{_safe_name(approach)}_{_safe_name(model)}.png"
        fig.savefig(path, dpi=120)
        plt.close(fig)
        paths.append(path)
    return paths


def _autosize(worksheet, df: pd.DataFrame) -> None:
    from openpyxl.utils import get_column_letter
    for i, col in enumerate(df.columns, start=1):
        sample = df[col].head(200).map(lambda v: len(str(v)))
        width = min(60, max(len(str(col)), int(sample.max()) if len(sample) else 0) + 2)
        worksheet.column_dimensions[get_column_letter(i)].width = width
    worksheet.freeze_panes = "A2"


def write_outputs(tables: Dict[str, pd.DataFrame], run_dir: Path, formats: List[str]) -> List[Path]:
    """`tables` keys become CSV file names / XLSX sheet names (<=31 chars)."""
    run_dir.mkdir(parents=True, exist_ok=True)
    formats = [f.lower() for f in (formats or ["xlsx"])]
    tables = {name: df for name, df in tables.items() if not df.empty}  # e.g. XAI tables when XAI is off
    written: List[Path] = []

    if "csv" in formats:
        for name, df in tables.items():
            path = run_dir / f"{name}.csv"
            df.to_csv(path, index=False, encoding="utf-8-sig")
            written.append(path)

    if "xlsx" in formats:
        path = run_dir / "classification_report.xlsx"
        try:
            with pd.ExcelWriter(path, engine="openpyxl") as writer:
                for name, df in tables.items():
                    df.to_excel(writer, sheet_name=name[:31], index=False)
                    _autosize(writer.sheets[name[:31]], df)
            written.append(path)
        except ImportError:
            logger.error("openpyxl tidak terinstall (pip install openpyxl) — output xlsx dilewati")

    return written


def readme_table() -> pd.DataFrame:
    return pd.DataFrame(README_ROWS, columns=["item", "penjelasan"])


def config_table(cfg: Dict[str, Any]) -> pd.DataFrame:
    return pd.DataFrame(_flatten_config(cfg))
