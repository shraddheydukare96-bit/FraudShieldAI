"""Service layer connecting the ML engine to the database and views.

Kept separate from views so persistence and orchestration can be tested in
isolation. It never invents results: if the text model is unavailable it returns
an honest "unavailable" outcome and saves nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .ml import engine
from .ml.classifier import ModelUnavailableError
from .ml.result import AnalysisResult
from .models import Detection


@dataclass
class AnalysisOutcome:
    ok: bool
    detection: Optional[Detection] = None
    result: Optional[AnalysisResult] = None
    message: str = ""
    errors: List[str] = None  # populated for invalid input
    report: object = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def text_model_available() -> bool:
    return engine.text_model_available()


def run_analysis(user, channel: str, content: str) -> AnalysisOutcome:
    """Analyze content, persist a Detection for ``user`` and return the outcome."""
    if not content or not content.strip():
        return AnalysisOutcome(ok=False, errors=["Content must not be empty."])

    try:
        result = engine.analyze(channel=channel, content=content)
    except ModelUnavailableError as exc:
        # Honest message, nothing saved, no fabricated prediction.
        return AnalysisOutcome(ok=False, message=str(exc))
    except ValueError as exc:
        return AnalysisOutcome(ok=False, errors=[str(exc)])

    detection = Detection.objects.create(
        user=user,
        channel=result.channel,
        content=content.strip(),
        is_fraud=result.classification == "fraud",
        confidence=result.risk_score if result.score_kind == "probability" else None,
        classification=result.classification,
        risk_score=result.risk_score,
        score_kind=result.score_kind,
        signals=result.signals,
        recommendations=result.recommendations,
        source=result.source,
        model_version=result.model_version or "",
    )

    # Create an owned Report so it appears in "My Reports" and is downloadable.
    from reports.models import Report

    report = Report.objects.create(
        user=user,
        detection=detection,
        title=f"{detection.get_channel_display()} analysis #{detection.pk} - {result.classification}",
        summary="; ".join(result.recommendations),
    )
    return AnalysisOutcome(
        ok=True, detection=detection, result=result, report=report
    )
