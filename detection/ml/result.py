"""Unified, channel-agnostic analysis result.

Every detector (text classifier or URL analyzer) returns this structure so the
service layer, templates and database can treat all results consistently.

The fields are deliberately explicit so we never overstate what a result means:
  * ``risk_score`` is a model probability for the text classifier but a
    heuristic (rule-weighted) score for URLs - ``score_kind`` records which.
  * ``signals`` lists the concrete evidence that produced the verdict.
  * ``source`` records which detector produced the result.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

# Classification labels used across the app.
FRAUD = "fraud"
LEGITIMATE = "legitimate"
INCONCLUSIVE = "inconclusive"


@dataclass
class AnalysisResult:
    channel: str
    classification: str          # fraud | legitimate | inconclusive
    risk_score: float            # 0.0 - 1.0 (meaning depends on score_kind)
    score_kind: str              # "probability" | "heuristic"
    signals: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    source: str = ""             # "text_model" | "url_rules" | "reputation"
    model_version: str | None = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_fraud(self) -> bool:
        return self.classification == FRAUD
