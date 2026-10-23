"""Service helpers for email verification and notification preferences.

Kept separate from views so the same functions can be reused by future
management commands (Group 10 alert/summary tasks) without touching HTTP code.

Nothing here fabricates delivery success: ``send_verification_email`` returns
whatever Django's email backend reports, and callers record real state.
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple
import math
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from email.utils import parseaddr

from .models import EmailVerificationToken, NotificationPreferences

User = get_user_model()


def ensure_preferences(user) -> NotificationPreferences:
    """Idempotent: guarantees every user has a preferences row."""
    prefs, _ = NotificationPreferences.objects.get_or_create(user=user)
    return prefs


def resolve_from_email() -> str:
    """Return a ``From`` value that is actually safe to send.

    Authenticated relays such as Gmail reject a message whose sender address is
    blank or differs from the logged-in account (SMTP 553). If
    ``DEFAULT_FROM_EMAIL`` already holds a valid address we use it verbatim;
    otherwise we derive a valid sender from ``EMAIL_HOST_USER`` (the account
    address, never the password). This keeps verification and report mail from
    being silently refused by the server.
    """
    from_email = (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
    address = parseaddr(from_email)[1]
    try:
        validate_email(address)
    except ValidationError:
        host_user = (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
        if host_user:
            return f"FraudShield AI <{host_user}>"
        return from_email
    return from_email


def issue_verification(user) -> EmailVerificationToken:
    """Create a fresh token, invalidating any outstanding one for this user."""
    return EmailVerificationToken.issue(user)


def verification_send_block_seconds(user):
    """Seconds the user must wait before another verification email, else None.

    Enforces BOTH a minimum spacing between sends
    (``VERIFICATION_EMAIL_COOLDOWN_SECONDS``) and a rolling hourly cap
    (``VERIFICATION_EMAIL_HOURLY_LIMIT``), measured against real
    ``EmailVerificationToken`` rows - a token is created on every (re)send. The
    caller must check this BEFORE issuing a new token, otherwise the just-
    created token would trip the cooldown. Returns the larger wait so the
    message reflects the true limit; verification itself is never disabled.
    """
    cooldown = int(getattr(settings, "VERIFICATION_EMAIL_COOLDOWN_SECONDS", 60))
    hourly_limit = int(getattr(settings, "VERIFICATION_EMAIL_HOURLY_LIMIT", 5))
    now = timezone.now()
    tokens = EmailVerificationToken.objects.filter(user=user)
    waits = []

    if cooldown > 0:
        last = tokens.order_by("-created_at").first()
        if last is not None:
            remaining = cooldown - (now - last.created_at).total_seconds()
            if remaining > 0:
                waits.append(int(math.ceil(remaining)))

    if hourly_limit > 0:
        window_start = now - timedelta(hours=1)
        recent = tokens.filter(created_at__gte=window_start)
        if recent.count() >= hourly_limit:
            oldest = recent.order_by("created_at").first()
            free_in = (oldest.created_at + timedelta(hours=1) - now).total_seconds()
            waits.append(max(1, int(math.ceil(free_in))))

    return max(waits) if waits else None


def verification_throttle_message(wait_seconds):
    """A short, honest, user-facing reason for a throttle (never a token)."""
    if not wait_seconds:
        return ""
    if wait_seconds < 60:
        unit = "second" if wait_seconds == 1 else "seconds"
        return (
            f"Please wait about {wait_seconds} {unit} before requesting "
            "another verification email."
        )
    minutes = math.ceil(wait_seconds / 60)
    unit = "minute" if minutes == 1 else "minutes"
    return (
        f"You've reached the limit for verification emails on this account. "
        f"Please try again in about {minutes} {unit}."
    )


def resolve_base_url(request=None) -> str:
    """Absolute base URL (no trailing slash) used for links inside emails.

    ``settings.SITE_URL`` is authoritative: when it is configured we use it
    verbatim and ignore the request entirely, so an arbitrary ``Host`` header
    can never poison a verification link. Only when it is unset (local
    development) do we derive the base from the request, honouring
    ``request.is_secure()``. Returns ``""`` when neither is available.
    """
    base = (getattr(settings, "SITE_URL", "") or "").strip().rstrip("/")
    if base:
        return base
    if request is None:
        return ""
    site = get_current_site(request)
    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{site.domain}"


def build_verification_url(request, token_key: str) -> str:
    """Absolute URL for the verify view.

    The base comes from ``resolve_base_url`` (``settings.SITE_URL`` when set,
    so links reach the real deployed/LAN host from any device and never trust
    a forged ``Host`` header). The path is resolved via ``reverse`` so it
    always matches the mounted URL configuration; the verification route and
    token mechanism are unchanged.
    """
    path = reverse("accounts:verify", kwargs={"key": token_key})
    base = resolve_base_url(request)
    return f"{base}{path}"


def send_verification_email(request, token: EmailVerificationToken) -> bool:
    """Queue a verification email. Returns True on ``EmailMessage.send()`` success.

    In development the default backend is ``console`` so the message is printed
    instead of delivered; in tests we use ``locmem`` and inspect ``outbox``.
    When ``EMAIL_BACKEND`` is set to SMTP the message is delivered for real.

    Guards:
      * User must have a non-empty email address (no ``to=[""]``).
      * Users whose preferences row already reports ``email_verified=True``
        are not emailed again.

    The token/key is never logged; only the boolean outcome is returned.
    """
    user = token.user
    if not (user.email or "").strip():
        # No destination -> don't fabricate a send.
        return False
    prefs = ensure_preferences(user)
    if prefs.email_verified:
        return False

    verify_url = build_verification_url(request, token.key)
    context = {
        "user": token.user,
        "verify_url": verify_url,
        "expires_in_hours": int(
            (token.expires_at - timezone.now()).total_seconds() // 3600
        ),
        "site_name": get_current_site(request).name,
    }
    subject = render_to_string("emails/verify_subject.txt", context).strip()
    body = render_to_string("emails/verify_body.txt", context)
    message = EmailMessage(
        subject=subject,
        body=body,
        from_email=resolve_from_email(),
        to=[token.user.email],
    )
    try:
        message.send(fail_silently=False)
    except Exception:
        # Any transport failure -> caller sees False, no fabricated success.
        return False
    return True


class VerifyResult:
    """Small enum so views can render precise, honest outcomes."""

    OK = "ok"
    UNKNOWN = "unknown"
    ALREADY_USED = "already_used"
    EXPIRED = "expired"
    ALREADY_VERIFIED = "already_verified"


def redeem_token(raw_key: str) -> Tuple[str, EmailVerificationToken | None]:
    """Try to consume ``raw_key``. Returns ``(status, token)``.

    On OK the linked user is marked verified in ``NotificationPreferences``.
    Expired/used/unknown tokens are never silently re-issued.
    """
    if not raw_key:
        return VerifyResult.UNKNOWN, None
    try:
        token = EmailVerificationToken.objects.select_related("user").get(key=raw_key)
    except EmailVerificationToken.DoesNotExist:
        return VerifyResult.UNKNOWN, None

    prefs = ensure_preferences(token.user)
    if prefs.email_verified:
        return VerifyResult.ALREADY_VERIFIED, token
    if token.already_used:
        return VerifyResult.ALREADY_USED, token
    if token.expired:
        return VerifyResult.EXPIRED, token

    token.used_at = timezone.now()
    token.save(update_fields=["used_at"])
    prefs.email_verified = True
    prefs.verified_at = timezone.now()
    prefs.save(update_fields=["email_verified", "verified_at", "updated_at"])
    return VerifyResult.OK, token
