"""The guard engine: combines Layer 1 (heuristics) and Layer 2 (statistical
scorer) into a single 0-100 risk score and an allow / flag / block verdict.

Combination rule (kept simple and explainable on purpose):
    blended = 0.6 * heuristic_score + 0.4 * statistical_score
    final   = max(heuristic_score, blended)

So a single strong heuristic match blocks on its own, while the
statistical layer can still raise a prompt with no known pattern into
the "flag" band for human review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .detectors import Finding, heuristic_score, run_detectors
from .scorer import StatisticalScorer

DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "data" / "labeled_prompts.json"


@dataclass
class GuardResult:
    score: int                 # 0-100 overall risk score
    verdict: str               # "allow" | "flag" | "block"
    heuristic_score: int       # Layer 1 sub-score, 0-100
    statistical_score: float   # Layer 2 sub-score, 0-100
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "heuristic_score": self.heuristic_score,
            "statistical_score": self.statistical_score,
            "findings": [
                {"detector": f.detector, "reason": f.reason, "points": f.points}
                for f in self.findings
            ],
        }


class GuardEngine:
    def __init__(
        self,
        scorer: StatisticalScorer | None = None,
        flag_threshold: int = 30,
        block_threshold: int = 65,
    ):
        self.scorer = scorer or StatisticalScorer.from_dataset(DEFAULT_DATASET)
        self.flag_threshold = flag_threshold
        self.block_threshold = block_threshold

    def verdict_for(self, score: int) -> str:
        if score >= self.block_threshold:
            return "block"
        if score >= self.flag_threshold:
            return "flag"
        return "allow"

    def evaluate(self, text: str) -> GuardResult:
        findings = run_detectors(text)
        h_score = heuristic_score(findings)
        s_score = self.scorer.score(text)
        blended = 0.6 * h_score + 0.4 * s_score
        final = int(round(max(h_score, blended)))
        return GuardResult(
            score=final,
            verdict=self.verdict_for(final),
            heuristic_score=h_score,
            statistical_score=s_score,
            findings=findings,
        )
