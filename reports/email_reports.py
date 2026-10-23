"""Emailing generated PDF reports to the owner's registered address.

Honesty rules enforced here:
  * Success is reported ONLY when the email backend accepted the message.
    SMTP rejections, connection errors and timeouts are surfaced as failures.
  * The recipient is always ``request.user.email`` - the caller cannot choose
    an arbitrary address, so one user can never mail another user's report.
  * Sends require a valid, verified address (verification is part of signup),
    are rate limited, and every attempt is recorded for duplicate prevention.
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone

from accounts.services import resolve_from_email

from .models import DeliveryAttempt
from .pdf import build_report_pdf

# Dedicated logger - configuration lives in settings.LOGGING. Never log SMTP
# credentials or message contents; we only log ids, status and short errors.
logger = logging.getLogger("reports.email")


class SendStatus:
    OK = "ok"
    NO_EMAIL = "no_email"
    NOT_VERIFIED = "not_verified"
    COOLDOWN = "cooldown"
    REJECTED = "rejected"
    ERROR = "error"


def mask_email(address: str) -> str:
    """`manager@corp.example` -> `man****@corp.example` for safe display."""
    if not address or "@" not in address:
        return ""
    local, _, domain = address.partition("@")
    visible = local[:3] if len(local) > 3 else local[:1]
    return f"{visible}****@{domain}"


def email_state(user, report):
    """Context dict describing whether/why the user can email ``report``."""
    address = (user.email or "").strip() if user.is_authenticated else ""
    if not address:
        eligible, reason = False, SendStatus.NO_EMAIL
    else:
        try:
            validate_email(address)
        except ValidationError:
            eligible, reason = False, SendStatus.NO_EMAIL
        else:
            # Requirement: reports may ONLY go to the logged-in user's own
            # *verified* registered address. A user without a preferences row
            # is treated as unverified (default-deny) - never implicitly
            # eligible. This closes a hole where accounts created outside the
            # signup flow (e.g. via ``createsuperuser`` or fixtures) would
            # otherwise see an enabled Send button with no verification.
            prefs = getattr(user, "preferences", None)
            if prefs is None or not prefs.email_verified:
                eligible, reason = False, SendStatus.NOT_VERIFIED
            else:
                wait = cooldown_remaining(user)
                if wait is not None:
                    eligible, reason = False, SendStatus.COOLDOWN
                else:
                    eligible, reason = True, None
    return {
        "eligible": eligible,
        "reason": reason,
        "masked_email": mask_email(address),
        "cooldown_seconds": wait if reason == SendStatus.COOLDOWN else None,
        "report": report,
    }


def cooldown_remaining(user):
    """Seconds until ``user`` may send again, or ``None`` if not limited."""
    cooldown = getattr(settings, "REPORT_EMAIL_COOLDOWN_SECONDS", 60)
    if cooldown <= 0:
        return None
    last = (
        DeliveryAttempt.objects.filter(user=user, status=DeliveryAttempt.Status.SENT)
        .order_by("-created_at")
        .first()
    )
    if last is None:
        return None
    elapsed = (timezone.now() - last.created_at).total_seconds()
    remaining = cooldown - elapsed
    return int(remaining) if remaining > 0 else None


def send_report_to_registered_email(user, report) -> tuple[str, str]:
    """Generate the report PDF and email it to ``user.email``.

    Returns ``(status, message)``; the status is ``SendStatus.OK`` only after
    the backend accepted the message. Every attempt outcome is logged.
    """
    state = email_state(user, report)
    if not state["eligible"]:
        if state["reason"] == SendStatus.NO_EMAIL:
            return SendStatus.NO_EMAIL, (
                "No valid registered email address on your account, so nothing "
                "was sent. Add an email address in your profile first."
            )
        if state["reason"] == SendStatus.NOT_VERIFIED:
            return SendStatus.NOT_VERIFIED, (
                "Your email address is not verified yet. Verify it before "
                "receiving reports by email."
            )
        if state["reason"] == SendStatus.COOLDOWN:
            return SendStatus.COOLDOWN, (
                f"Please wait {state['cooldown_seconds']} seconds before "
                "sending another report."
            )

    recipient = user.email.strip()
    try:
        # Same generator as the download endpoint -> identical content/charts.
        pdf_bytes = build_report_pdf(report)
    except Exception:  # noqa: BLE001 - report honestly, keep the details in logs
        logger.exception("PDF generation failed for report %s (user %s)", report.pk, user.pk)
        _record(report, user, recipient, DeliveryAttempt.Status.FAILED, "PDF generation failed")
        return SendStatus.ERROR, "The report could not be generated. Nothing was sent."

    filename = f"fraudshield-report-{report.pk}.pdf"
    subject = f"FraudShield AI report #{report.pk}: {report.title}"
    body = (
        f"Hello {user.get_full_name() or user.username},\n\n"
        "Attached is your FraudShield AI analysis report (PDF). The risk "
        "percentage and charts in the document are computed from the results "
        "stored on your account.\n\n"
        "This message was generated by FraudShield AI and the attachment is "
        "not a guarantee - verify independently before acting on any result.\n"
    )
    message = EmailMessage(
        subject=subject,
        body=body,
        from_email=resolve_from_email(),
        to=[recipient],
    )
    message.attach(filename, pdf_bytes, "application/pdf")

    try:
        message.send(fail_silently=False)
    except Exception as exc:  # noqa: BLE001 - SMTPError, OSError, connection drops
        short = f"{type(exc).__name__}: {exc}"[:250]
        logger.warning(
            "Report email rejected (report %s, user %s): %s", report.pk, user.pk, short
        )
        _record(report, user, recipient, DeliveryAttempt.Status.FAILED, short)
        return SendStatus.REJECTED, (
            "The mail server rejected the message, so it was NOT delivered: "
            f"{short}"
        )

    logger.info("Report email accepted (report %s, user %s)", report.pk, user.pk)
    _record(report, user, recipient, DeliveryAttempt.Status.SENT, "")
    return SendStatus.OK, (
        f"Report sent to your registered address ({mask_email(recipient)})."
    )


def _record(report, user, recipient, status, error_message):
    DeliveryAttempt.objects.create(
        report=report,
        user=user,
        recipient=recipient,
        status=status,
        error_message=error_message,
    )
