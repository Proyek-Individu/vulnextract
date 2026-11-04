"""
Builds the two datasets compared by the classification mode, plus the
shared train/test partition and the feature matrices.

- "raw" (data mentah): one sample per METHOD straight from the input CSV —
  vulnerable_code -> label 1, fixed_code -> label 0 (rows where both are
  identical -> one "unchanged" sample, label 0). Features are a TF-IDF bag
  of code tokens over the whole method text: no AST, no splitting rules.
- "split" (data hasil split): one sample per STATEMENT from mode
  "features" (src/feature_pipeline.py), labeled by the recursive diff, with
  context.md's structured A-F columns as features.

Both datasets are partitioned with the SAME group-level split, so a
method's vulnerable and fixed versions (and every statement extracted from
them) always land on the same side — otherwise the near-identical
vulnerable/fixed pair would leak between train and test.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import KFold, StratifiedKFold, train_test_split
from sklearn.preprocessing import OneHotEncoder

logger = logging.getLogger(__name__)

SIDE_LABEL = {"vulnerable": 1, "fixed": 0, "unchanged": 0}

# statement_id = f"{repo}:{file}:{method}:{row_index}:{origin}:..." (see
# FeatureExtractionPipeline.process_dataframe). The CSV row index is what
# links a statement back to its raw row.
_ROW_INDEX_RE = re.compile(r":(\d+):(vulnerable|fixed|unchanged):")

# Tokens for raw code: identifiers/keywords, numbers, and single punctuation/
# operator characters (so `+`, `(`, `'` etc. count as tokens too).
CODE_TOKEN_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]"

# Columns that must never be used as split features: identifiers, location,
# and label proxies (`origin` and `vulnerability_type` are derived from the
# same vulnerable/fixed side the label comes from -> direct leakage).
LEAKY_OR_ID_COLUMNS = {
    "cve_id", "vulnerability_type", "commit_hash", "repo", "origin", "statement_id",
    "parent_statement_id", "repo_name", "file_path", "function_name", "line_start",
    "line_end", "label",
}


def _group_key(row: pd.Series, row_index: int, group_by: str) -> str:
    if group_by == "row":
        return f"row:{row_index}"
    if group_by == "cve":
        return f"cve:{row.get('cve_id', '')}"
    # "method": duplicates / the same method fixed twice share one group
    return f"method:{row.get('repo', '')}|{row.get('file', '')}|{row.get('method', '')}"


def build_raw_methods(raw_df: pd.DataFrame, group_by: str = "method") -> pd.DataFrame:
    """One row per method version (vulnerable / fixed / unchanged)."""
    records: List[Dict[str, Any]] = []
    for row_index, row in raw_df.iterrows():
        vulnerable_code = row.get("vulnerable_code")
        fixed_code = row.get("fixed_code")
        has_v = isinstance(vulnerable_code, str) and bool(vulnerable_code.strip())
        has_f = isinstance(fixed_code, str) and bool(fixed_code.strip())
        if not has_v:
            continue
        base = {
            "row_index": int(row_index),
            "group": _group_key(row, int(row_index), group_by),
            "cve_id": str(row.get("cve_id", "") or ""),
            "vulnerability_type": str(row.get("vulnerability_type", "") or ""),
            "language": str(row.get("language", "") or "").strip().lower(),
            "repo": str(row.get("repo", "") or ""),
            "file": str(row.get("file", "") or ""),
            "method": str(row.get("method", "") or ""),
        }
        if has_f and vulnerable_code.strip() == fixed_code.strip():
            sides = [("unchanged", vulnerable_code)]
        else:
            sides = [("vulnerable", vulnerable_code)] + ([("fixed", fixed_code)] if has_f else [])
        for side, code in sides:
            records.append({
                **base,
                "side": side,
                "method_id": f"{row_index}:{side}",
                "code": code,
                "label": SIDE_LABEL[side],
            })
    return pd.DataFrame(records)


def build_statements(split_df: pd.DataFrame, raw_df: pd.DataFrame, group_by: str = "method") -> pd.DataFrame:
    """Statement table + the raw row / method / group each statement belongs to."""
    df = split_df.copy()
    matches = df["statement_id"].astype(str).map(
        lambda s: (_ROW_INDEX_RE.findall(s) or [(None, None)])[-1]
    )
    df["row_index"] = [m[0] for m in matches]
    df["side"] = df["origin"].astype(str)

    unresolved = df["row_index"].isna()
    if unresolved.any():
        logger.warning(f"{int(unresolved.sum())} statement tidak bisa ditautkan ke baris CSV mentah — dibuang")
        df = df[~unresolved].copy()
    df["row_index"] = df["row_index"].astype(int)

    out_of_range = ~df["row_index"].isin(raw_df.index)
    if out_of_range.any():
        raise ValueError(
            "Data split tidak cocok dengan data mentah (row index di statement_id tidak ada di CSV mentah). "
            "Jalankan ulang menu 2 (ekstraksi features) dengan input mentah yang sama."
        )
    if "cve_id" in df.columns and "cve_id" in raw_df.columns:
        raw_cve = raw_df.loc[df["row_index"], "cve_id"].astype(str).to_numpy()
        mismatched = int((df["cve_id"].astype(str).to_numpy() != raw_cve).sum())
        if mismatched:
            logger.warning(
                f"{mismatched} statement punya cve_id berbeda dari baris mentahnya — "
                "data split kemungkinan dibuat dari CSV mentah lain."
            )

    groups = {int(i): _group_key(row, int(i), group_by) for i, row in raw_df.iterrows()}
    df["group"] = df["row_index"].map(groups)
    df["method_id"] = df["row_index"].astype(str) + ":" + df["side"]
    df["method_label"] = df["side"].map(SIDE_LABEL).fillna(0).astype(int)
    df["label"] = df["label"].astype(int)
    return df.reset_index(drop=True)


def make_folds(
    raw_methods: pd.DataFrame,
    statements: pd.DataFrame,
    test_size: float,
    cv_folds: int,
    random_state: int,
) -> List[Tuple[set, set]]:
    """Group-level partition shared by both approaches. Groups are
    stratified on "contains at least one label-1 statement" so the rare
    positive statements are spread over train and test."""
    groups = sorted(set(raw_methods["group"]) | set(statements["group"]))
    positive_groups = set(statements.loc[statements["label"] == 1, "group"])
    strata = np.array([1 if g in positive_groups else 0 for g in groups])
    groups_arr = np.array(groups, dtype=object)
    min_stratum = int(min(np.bincount(strata, minlength=2)))

    if cv_folds and cv_folds >= 2:
        if min_stratum >= cv_folds:
            splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
            split_iter = splitter.split(groups_arr, strata)
        else:
            logger.warning("Grup positif terlalu sedikit untuk stratifikasi k-fold — memakai KFold biasa")
            split_iter = KFold(n_splits=cv_folds, shuffle=True, random_state=random_state).split(groups_arr)
        return [(set(groups_arr[tr]), set(groups_arr[te])) for tr, te in split_iter]

    stratify = strata if min_stratum >= 2 else None
    train_groups, test_groups = train_test_split(
        groups_arr, test_size=test_size, random_state=random_state, stratify=stratify
    )
    return [(set(train_groups), set(test_groups))]


# ---------------------------------------------------------------------------
# Feature matrices (fitted on the training fold only)
# ---------------------------------------------------------------------------

class RawFeatureBuilder:
    """TF-IDF over raw method code — the "no splitting rules" baseline."""

    def __init__(self, cfg: Dict[str, Any]):
        ngram = cfg.get("ngram_range") or [1, 2]
        self.vectorizer = TfidfVectorizer(
            token_pattern=CODE_TOKEN_PATTERN,
            lowercase=False,
            ngram_range=(int(ngram[0]), int(ngram[1])),
            max_features=cfg.get("max_features") or None,
            min_df=cfg.get("min_df", 1),
            sublinear_tf=True,
        )

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.vectorizer.fit_transform(df["code"]).toarray()

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.vectorizer.transform(df["code"]).toarray()

    @property
    def feature_names(self) -> List[str]:
        return [f"tok:{t}" for t in self.vectorizer.get_feature_names_out()]


def _to_number(series: pd.Series) -> pd.Series:
    """Numeric/bool column -> float; also accepts "True"/"False" strings
    (how bool columns come back when a CSV is read with mixed values)."""
    if pd.api.types.is_bool_dtype(series):
        return series.astype(float)
    numbers = pd.to_numeric(series, errors="coerce")
    flags = series.astype(str).str.strip().str.lower().map({"true": 1.0, "false": 0.0})
    return numbers.fillna(flags).fillna(0.0).astype(float)


def _onehot_name(feature: str, category: Any) -> str:
    return f"{feature}={category}"


class StatementFeatureBuilder:
    """context.md A-F structured columns (+ optional TF-IDF of raw_text)."""

    def __init__(self, cfg: Dict[str, Any]):
        self.numeric = [c for c in (cfg.get("numeric") or []) if c not in LEAKY_OR_ID_COLUMNS]
        self.categorical = [c for c in (cfg.get("categorical") or []) if c not in LEAKY_OR_ID_COLUMNS]
        dropped = set((cfg.get("numeric") or []) + (cfg.get("categorical") or [])) & LEAKY_OR_ID_COLUMNS
        if dropped:
            logger.warning(f"Kolom berikut dibuang dari fitur split (ID/bocor label): {sorted(dropped)}")
        self.use_text = bool(cfg.get("raw_text_tfidf", False))
        self.tfidf_max_features = cfg.get("tfidf_max_features") or None
        self.transformer: Optional[ColumnTransformer] = None

    def _prepare(self, df: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in self.numeric + self.categorical if c not in df.columns]
        if missing:
            raise ValueError(f"Kolom fitur tidak ada di data split: {missing}")
        out = pd.DataFrame(index=df.index)
        for col in self.numeric:
            out[col] = _to_number(df[col])
        for col in self.categorical:
            out[col] = df[col].fillna("none").astype(str)
        if self.use_text:
            out["raw_text"] = df["raw_text"].fillna("").astype(str)
        return out

    def _build(self) -> ColumnTransformer:
        parts = []
        if self.numeric:
            parts.append(("num", "passthrough", self.numeric))
        if self.categorical:
            parts.append(("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False,
                                               feature_name_combiner=_onehot_name), self.categorical))
        if self.use_text:
            parts.append(("txt", TfidfVectorizer(token_pattern=CODE_TOKEN_PATTERN, lowercase=False,
                                                 max_features=self.tfidf_max_features, sublinear_tf=True),
                          "raw_text"))
        if not parts:
            raise ValueError("Tidak ada kolom fitur split yang dipilih (classification.split_features)")
        return ColumnTransformer(parts, sparse_threshold=0.0)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        self.transformer = self._build()
        return np.asarray(self.transformer.fit_transform(self._prepare(df)), dtype=float)

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        return np.asarray(self.transformer.transform(self._prepare(df)), dtype=float)

    @property
    def feature_names(self) -> List[str]:
        names = []
        for name in self.transformer.get_feature_names_out():
            prefix, _, rest = name.partition("__")
            names.append(f"tok:{rest}" if prefix == "txt" else rest)
        return names
