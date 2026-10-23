"""Account models: email verification tokens and notification preferences.

These models extend Django's built-in ``User`` without replacing it, so all
existing auth views keep working. Verification state lives here - never
inferred from ``User.email`` alone - so we never send unverified mail.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class NotificationPreferences(models.Model):
    """Per-user delivery preferences. One row per user, created at signup."""

    class Frequency(models.TextChoices):
        OFF = "off", "Never"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="preferences",
    )
    # Cached verification state. The canonical source is a successful
    # EmailVerificationToken redemption, which sets this to True.
    email_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    high_risk_alerts = models.BooleanField(
        default=True,
        help_text="Send an email when a new analysis is classified as fraud.",
    )
    report_attach_to_email = models.BooleanField(
        default=True,
        help_text="Attach the generated PDF report to the notification email.",
    )
    summary_frequency = models.CharField(
        max_length=10,
        choices=Frequency.choices,
        default=Frequency.OFF,
        help_text="How often to send a security summary email.",
    )
    last_summary_sent_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        state = "verified" if self.email_verified else "unverified"
        return f"Preferences for {self.user.username} ({state})"


class EmailVerificationToken(models.Model):
    """Opaque single-use token sent to a user's email to confirm ownership."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="verification_tokens",
    )
    key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Token for {self.user.username} (expires {self.expires_at:%Y-%m-%d %H:%M})"

    @classmethod
    def issue(cls, user, ttl: timedelta | None = None) -> "EmailVerificationToken":
        """Invalidate any outstanding tokens for ``user`` and create a new one."""
        ttl = ttl or getattr(settings, "EMAIL_VERIFICATION_TTL", timedelta(hours=24))
        cls.objects.filter(user=user, used_at__isnull=True).update(
            used_at=timezone.now()
        )
        return cls.objects.create(
            user=user, key=secrets.token_urlsafe(32), expires_at=timezone.now() + ttl
        )

    @property
    def expired(self) -> bool:
        return timezone.now() > self.expires_at

    @property
    def already_used(self) -> bool:
        return self.used_at is not None
