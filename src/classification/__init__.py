"""
Classification mode (menu 3): configurable ML models + XAI, comparing
classification on the RAW method-level data against classification on the
statement-level data produced by mode "features" (the defined split rules).

Additive package: reads the outputs of the other modes, never modifies them.
"""

from .model_registry import MODEL_ALIASES, build_model_spec, build_model_specs
from .pipeline import ClassificationPipeline, ClassificationResult

__all__ = [
    "MODEL_ALIASES",
    "build_model_spec",
    "build_model_specs",
    "ClassificationPipeline",
    "ClassificationResult",
]
