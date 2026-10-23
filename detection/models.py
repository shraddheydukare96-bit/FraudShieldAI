"""Data models for the detection app.

These models store per-user analysis records. The AI classification logic is
added in a later phase; ownership fields enable per-user access control now.
"""
from django.conf import settings
from django.db import models


class Detection(models.Model):
    """A single fraud-analysis record owned by a user."""

    class Channel(models.TextChoices):
        SMS = "sms", "SMS"
        EMAIL = "email", "Email"
        URL = "url", "URL"

    class Classification(models.TextChoices):
        FRAUD = "fraud", "Fraud"
        INCONCLUSIVE = "inconclusive", "Inconclusive"
        LEGITIMATE = "legitimate", "Legitimate"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="detections",
    )
    channel = models.CharField(max_length=5, choices=Channel.choices)
    content = models.TextField(help_text="The analyzed message, email or URL.")
    is_fraud = models.BooleanField(default=False)
    confidence = models.FloatField(null=True, blank=True)

    # Unified AI result fields (persisted per analysis for the owning user).
    classification = models.CharField(max_length=20, blank=True)
    risk_score = models.FloatField(null=True, blank=True)
    score_kind = models.CharField(max_length=20, blank=True)  # probability | heuristic
    signals = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    source = models.CharField(max_length=20, blank=True)  # text_model | url_rules
    model_version = models.CharField(max_length=60, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # ``-pk`` breaks ties when ``auto_now_add`` writes land in the same
        # microsecond, so "newest first" is deterministic.
        ordering = ["-created_at", "-pk"]

    def __str__(self):
        verdict = "Fraud" if self.is_fraud else "Legitimate"
        return f"{self.get_channel_display()} detection #{self.pk} ({verdict})"

    # ------------------------------------------------------------------ #
    # Risk presentation (derived, never invented)
    # ------------------------------------------------------------------ #
    @property
    def risk_percent(self):
        """Risk score converted to an integer 0-100 percentage.

        Returns ``None`` when no valid score exists so callers can display
        "unavailable" instead of fabricating a number. Scores stored on the
        historical 0-1 scale are converted; already-percent scores are
        accepted and clamped to the valid range.
        """
        if self.risk_score is None:
            return None
        try:
            score = float(self.risk_score)
        except (TypeError, ValueError):
            return None
        # A probability-like value (0-1) becomes a percentage; a value already
        # expressed on the 0-100 scale is used directly.
        percent = score * 100.0 if 0.0 <= score <= 1.0 else score
        if percent < 0.0 or percent > 100.0:
            # Out-of-range data -> honest failure, no invented figure.
            return None
        return max(0, min(100, int(round(percent))))

    @property
    def risk_label(self):
        """SAFE / SUSPICIOUS / HIGH RISK using the project's classification."""
        if self.classification == self.Classification.FRAUD:
            return "HIGH RISK"
        if self.classification == self.Classification.INCONCLUSIVE:
            return "SUSPICIOUS"
        if self.classification == self.Classification.LEGITIMATE:
            return "SAFE"
        # Legacy rows without an explicit classification.
        return "HIGH RISK" if self.is_fraud else "SAFE"
