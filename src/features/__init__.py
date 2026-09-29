"""
Hierarchical statement-level feature extraction for ML/DL vulnerability detection.

Additive package: reads the same input CSV as the existing pair-based
pipeline (src/pipeline.py) but emits a flat, labeled, per-statement feature
table matching context.md's schema (categories A-F), scoped to context.md's
stated target languages: Go, Python, JavaScript/TypeScript, PHP.
"""
