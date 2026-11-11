"""Prompt-injection guard: two-layer detection engine.

Layer 1 (detectors.py): heuristic/regex detectors for known injection patterns.
Layer 2 (scorer.py):    a lightweight statistical (token log-odds) scorer
                        trained on the bundled labeled dataset. This is a
                        statistical scorer, not a deep-learning model.
engine.py combines both layers into a 0-100 risk score and a verdict.
"""

from .engine import GuardEngine, GuardResult

__all__ = ["GuardEngine", "GuardResult"]
