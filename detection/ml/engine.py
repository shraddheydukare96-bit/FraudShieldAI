"""Single entry point for running an analysis by channel.

This module stays framework-free (no Django) so it can be unit-tested in
isolation and reused by scripts. The Django service layer wraps it to persist
results and translate errors into user-facing messages.
"""
from __future__ import annotations

from .classifier import ModelUnavailableError, predict_text
from .result import AnalysisResult
from .url_analyzer import analyze_url

TEXT_CHANNELS = {"sms", "email"}
URL_CHANNELS = {"url"}


def analyze(channel: str, content: str) -> AnalysisResult:
    """Analyze ``content`` for the given ``channel``.

    Raises:
      ValueError: unsupported channel or empty content.
      ModelUnavailableError: text channel requested but no trained model exists.
    """
    if content is None or not str(content).strip():
        raise ValueError("Content to analyze must not be empty.")

    channel = (channel or "").lower()
    if channel in TEXT_CHANNELS:
        return predict_text(content, channel=channel)
    if channel in URL_CHANNELS:
        return analyze_url(content)
    raise ValueError(f"Unsupported analysis channel: {channel!r}")


def text_model_available() -> bool:
    from .classifier import model_available

    return model_available()


__all__ = [
    "analyze",
    "AnalysisResult",
    "ModelUnavailableError",
    "text_model_available",
]
