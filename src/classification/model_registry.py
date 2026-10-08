"""
Model registry for the classification mode.

Models are declared in global.yaml (`classification.models`) — either by a
short alias (`random_forest`, `xgboost`, ...) or by a fully qualified class
path (`class: sklearn.ensemble.RandomForestClassifier`) for anything not in
the alias table. Any estimator following the scikit-learn API
(fit/predict_proba or decision_function) works.
"""

import importlib
from dataclasses import dataclass
from typing import Any, Dict, List, Union

import numpy as np
from sklearn.base import clone

# alias -> (module, class, default params, scale features by default?)
# Default params are merged UNDER the user's params from global.yaml, so
# anything set there wins (set a key to null to drop a default, e.g.
# `class_weight: null`).
MODEL_ALIASES: Dict[str, tuple] = {
    "random_forest": ("sklearn.ensemble", "RandomForestClassifier",
                      {"n_estimators": 300, "class_weight": "balanced", "n_jobs": -1}, False),
    "extra_trees": ("sklearn.ensemble", "ExtraTreesClassifier",
                    {"n_estimators": 300, "class_weight": "balanced", "n_jobs": -1}, False),
    "decision_tree": ("sklearn.tree", "DecisionTreeClassifier",
                      {"class_weight": "balanced"}, False),
    "gradient_boosting": ("sklearn.ensemble", "GradientBoostingClassifier", {}, False),
    "hist_gradient_boosting": ("sklearn.ensemble", "HistGradientBoostingClassifier",
                               {"class_weight": "balanced"}, False),
    "adaboost": ("sklearn.ensemble", "AdaBoostClassifier", {}, False),
    "logistic_regression": ("sklearn.linear_model", "LogisticRegression",
                            {"max_iter": 5000, "class_weight": "balanced"}, True),
    "svm": ("sklearn.svm", "SVC",
            {"probability": True, "class_weight": "balanced"}, True),
    "linear_svm": ("sklearn.svm", "LinearSVC",
                   {"class_weight": "balanced", "max_iter": 10000}, True),
    "knn": ("sklearn.neighbors", "KNeighborsClassifier", {"n_neighbors": 5}, True),
    "naive_bayes": ("sklearn.naive_bayes", "GaussianNB", {}, False),
    "mlp": ("sklearn.neural_network", "MLPClassifier",
            {"hidden_layer_sizes": [100], "max_iter": 2000}, True),
    "xgboost": ("xgboost", "XGBClassifier", {"eval_metric": "logloss", "n_jobs": -1}, False),
    "lightgbm": ("lightgbm", "LGBMClassifier",
                 {"class_weight": "balanced", "verbose": -1, "n_jobs": -1}, False),
}


@dataclass
class ModelSpec:
    label: str          # display name in reports (unique per run)
    estimator: Any      # unfitted prototype; cloned for every fold/approach
    scale: bool         # standardize the feature matrix before fitting

    def new_estimator(self):
        return clone(self.estimator)


def _import_class(dotted: str):
    module_name, _, class_name = dotted.rpartition(".")
    if not module_name:
        raise ValueError(f"'class' harus berupa path lengkap (module.ClassName), bukan '{dotted}'")
    return getattr(importlib.import_module(module_name), class_name)


def build_model_spec(raw: Union[str, Dict[str, Any]], random_state: int = None) -> ModelSpec:
    """Turns one `classification.models` entry into a ModelSpec."""
    if isinstance(raw, str):
        raw = {"name": raw}
    raw = dict(raw or {})
    name = str(raw.get("name") or "").strip().lower()
    user_params = dict(raw.get("params") or {})

    if raw.get("class"):
        cls = _import_class(str(raw["class"]))
        params = user_params
        default_scale = False
        label = raw.get("label") or name or cls.__name__
    elif name in MODEL_ALIASES:
        module_name, class_name, defaults, default_scale = MODEL_ALIASES[name]
        try:
            cls = getattr(importlib.import_module(module_name), class_name)
        except ImportError as e:
            raise ImportError(
                f"Model '{name}' butuh package '{module_name}' (pip install {module_name})"
            ) from e
        params = {**defaults, **user_params}
        label = raw.get("label") or name
    else:
        raise ValueError(
            f"Model '{name}' tidak dikenal. Pilih salah satu: {', '.join(sorted(MODEL_ALIASES))}, "
            "atau isi 'class: module.ClassName'."
        )

    # YAML lists -> tuples where sklearn expects tuples (e.g. MLP layers).
    if "hidden_layer_sizes" in params and isinstance(params["hidden_layer_sizes"], list):
        params["hidden_layer_sizes"] = tuple(params["hidden_layer_sizes"])

    estimator = cls(**params)
    if random_state is not None and "random_state" not in user_params:
        if "random_state" in estimator.get_params():
            estimator.set_params(random_state=random_state)

    return ModelSpec(label=str(label), estimator=estimator, scale=bool(raw.get("scale", default_scale)))


def build_model_specs(raw_list: List[Any], random_state: int = None) -> List[ModelSpec]:
    specs = [build_model_spec(raw, random_state) for raw in (raw_list or [])]
    if not specs:
        specs = [build_model_spec("random_forest", random_state)]
    # Make labels unique so two configs of the same model don't collide in reports.
    seen: Dict[str, int] = {}
    for spec in specs:
        if spec.label in seen:
            seen[spec.label] += 1
            spec.label = f"{spec.label}_{seen[spec.label]}"
        else:
            seen[spec.label] = 1
    return specs


def predict_scores(model, X) -> np.ndarray:
    """Probability of class 1 (vulnerable). Models without predict_proba
    (e.g. LinearSVC) get their decision_function squashed through a
    logistic so 0.5 still corresponds to the decision boundary."""
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        classes = list(model.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(proba))
    decision = np.asarray(model.decision_function(X), dtype=float)
    return 1.0 / (1.0 + np.exp(-decision))
