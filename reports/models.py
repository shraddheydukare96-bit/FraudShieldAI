"""Data models for the reports app (per-user analysis reports)."""
from django.conf import settings
from django.db import models

from detection.models import Detection


class Report(models.Model):
    """A report generated from an analysis, owned by a user."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports",
    )
    detection = models.ForeignKey(
        Detection,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    title = models.CharField(max_length=200)
    summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Report #{self.pk}: {self.title}"


class DeliveryAttempt(models.Model):
    """One recorded attempt to email a report to its owner's registered address.

    Used for honest delivery status, rate limiting, and duplicate-send
    prevention. Only the owner's own address and a truncated error string are
    stored -- never SMTP credentials or message contents.
    """

    class Status(models.TextChoices):
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"

    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="deliveries",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="report_deliveries",
    )
    recipient = models.EmailField()
    status = models.CharField(max_length=10, choices=Status.choices)
    error_message = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]

    def __str__(self):
        return f"Delivery #{self.pk} report#{self.report_id} {self.status}"
