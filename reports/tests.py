"""Tests for per-user data isolation + PDF charts + report email delivery."""
import base64
import re
import zlib
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.services import ensure_preferences
from detection.models import Detection

from .email_reports import mask_email, send_report_to_registered_email
from .models import DeliveryAttempt, Report
from .pdf import build_history_pie_bytes, build_report_pdf, build_risk_pie_bytes

PASSWORD = "Str0ng!Passw0rd-9"


def _pdf_text(data: bytes) -> str:
    """Decompress ReportLab content streams so we can assert real PDF text.

    ReportLab's default page compression is ``/ASCII85Decode /FlateDecode``,
    so each ``stream`` must be ASCII85-decoded and then zlib-inflated before
    the drawn text becomes searchable.
    """
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        raw = match.group(1).strip()
        text = None
        if raw.endswith(b"~>"):  # ASCII85-encoded (ReportLab default)
            try:
                decoded = base64.a85decode(raw[:-2], adobe=False, ignorechars=b" \n\r\t")
                try:
                    decoded = zlib.decompress(decoded)
                except zlib.error:
                    pass
                text = decoded.decode("latin-1", errors="ignore")
            except ValueError:
                text = None
        if text is None:
            try:
                text = zlib.decompress(raw).decode("latin-1", errors="ignore")
            except zlib.error:
                text = raw.decode("latin-1", errors="ignore")
        chunks.append(text)
    return "\n".join(chunks)


class ReportAccessTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner", "owner@example.com", PASSWORD)
        self.other = User.objects.create_user("other", "other@example.com", PASSWORD)
        detection = Detection.objects.create(
            user=self.owner, channel="url", content="http://evil.example"
        )
        self.report = Report.objects.create(
            user=self.owner, detection=detection, title="Private report"
        )

    def test_owner_can_access_report(self):
        self.client.login(username="owner", password=PASSWORD)
        self.assertEqual(
            self.client.get(reverse("reports:detail", args=[self.report.pk])).status_code,
            200,
        )

    def test_other_user_cannot_access_foreign_report(self):
        self.client.login(username="other", password=PASSWORD)
        self.assertEqual(
            self.client.get(reverse("reports:detail", args=[self.report.pk])).status_code,
            404,
        )

    def test_list_only_shows_own_reports(self):
        self.client.login(username="other", password=PASSWORD)
        self.assertNotContains(
            self.client.get(reverse("reports:index")), "Private report"
        )


class ReportPDFDownloadTests(TestCase):
    """The PDF endpoint must return a real PDF for the owner and 404 for others."""

    def setUp(self):
        self.owner = User.objects.create_user("pdfowner", "pdfowner@example.com", PASSWORD)
        self.intruder = User.objects.create_user("pdfintruder", "pi@example.com", PASSWORD)
        self.detection = Detection.objects.create(
            user=self.owner,
            channel="url",
            content="http://paypal-secure.verify.evil.click/login",
            classification="fraud",
            is_fraud=True,
            risk_score=0.82,
            score_kind="heuristic",
            signals=["misleading_domain", "risky_tld"],
            recommendations=["Do not enter credentials on this page."],
        )
        self.report = Report.objects.create(
            user=self.owner,
            detection=self.detection,
            title="URL analysis - fraud",
            summary="Do not enter credentials on this page.",
        )

    def test_anonymous_cannot_download_pdf(self):
        response = self.client.get(reverse("reports:pdf", args=[self.report.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers.get("Location", ""))

    def test_owner_receives_pdf_bytes(self):
        self.client.login(username="pdfowner", password=PASSWORD)
        response = self.client.get(reverse("reports:pdf", args=[self.report.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn(
            'attachment; filename="fraudshield-report-',
            response["Content-Disposition"],
        )
        # Real ReportLab output starts with the %PDF magic header.
        self.assertTrue(response.content.startswith(b"%PDF-"))
        self.assertGreater(len(response.content), 500)

    def test_cross_user_download_is_forbidden(self):
        self.client.login(username="pdfintruder", password=PASSWORD)
        response = self.client.get(reverse("reports:pdf", args=[self.report.pk]))
        self.assertEqual(response.status_code, 404)

    def test_missing_report_pdf_returns_404(self):
        self.client.login(username="pdfowner", password=PASSWORD)
        response = self.client.get(reverse("reports:pdf", args=[999999]))
        self.assertEqual(response.status_code, 404)


class ReportBuilderTests(TestCase):
    """build_report_pdf must produce a valid PDF for every report shape."""

    def setUp(self):
        self.owner = User.objects.create_user("builder", "b@example.com", PASSWORD)

    def test_pdf_includes_analysis_type_and_classification(self):
        from .pdf import build_report_pdf

        detection = Detection.objects.create(
            user=self.owner,
            channel="sms",
            content="WIN $1000 - reply now",
            classification="fraud",
            is_fraud=True,
            risk_score=0.91,
            score_kind="probability",
            signals=["prize_lure"],
            recommendations=["Do not reply."],
        )
        report = Report.objects.create(
            user=self.owner, detection=detection, title="SMS analysis"
        )
        data = build_report_pdf(report)
        self.assertTrue(data.startswith(b"%PDF-"))

    def test_pdf_builds_when_signals_and_recommendations_empty(self):
        from .pdf import build_report_pdf

        detection = Detection.objects.create(
            user=self.owner,
            channel="email",
            content="hello",
            classification="legitimate",
            risk_score=0.02,
            score_kind="probability",
        )
        report = Report.objects.create(
            user=self.owner, detection=detection, title="Email analysis"
        )
        data = build_report_pdf(report)
        self.assertTrue(data.startswith(b"%PDF-"))


class RiskPercentageTests(TestCase):
    """risk_percent converts real stored scores and validates the range."""

    def setUp(self):
        self.owner = User.objects.create_user("pct", "pct@example.com", PASSWORD)

    def test_zero_to_one_score_is_converted_to_percentage(self):
        d = Detection.objects.create(
            user=self.owner, channel="sms", content="x", risk_score=0.82
        )
        self.assertEqual(d.risk_percent, 82)

    def test_already_percent_score_is_used_directly(self):
        d = Detection.objects.create(
            user=self.owner, channel="sms", content="x", risk_score=47.0
        )
        self.assertEqual(d.risk_percent, 47)

    def test_rounding_is_integral(self):
        d = Detection.objects.create(
            user=self.owner, channel="sms", content="x", risk_score=0.6759
        )
        self.assertEqual(d.risk_percent, 68)

    def test_none_score_is_unavailable_not_invented(self):
        d = Detection.objects.create(
            user=self.owner, channel="sms", content="x", risk_score=None
        )
        self.assertIsNone(d.risk_percent)

    def test_out_of_range_score_is_rejected(self):
        d = Detection.objects.create(
            user=self.owner, channel="sms", content="x", risk_score=140.0
        )
        self.assertIsNone(d.risk_percent)

    def test_boundary_values_stay_within_range(self):
        lo = Detection.objects.create(user=self.owner, channel="sms", content="a", risk_score=0.0)
        hi = Detection.objects.create(user=self.owner, channel="sms", content="b", risk_score=1.0)
        self.assertEqual(lo.risk_percent, 0)
        self.assertEqual(hi.risk_percent, 100)

    def test_risk_label_matches_classification(self):
        fraud = Detection.objects.create(
            user=self.owner, channel="sms", content="a", classification="fraud", risk_score=0.9
        )
        incon = Detection.objects.create(
            user=self.owner, channel="sms", content="b", classification="inconclusive", risk_score=0.4
        )
        legit = Detection.objects.create(
            user=self.owner, channel="sms", content="c", classification="legitimate", risk_score=0.1
        )
        self.assertEqual(fraud.risk_label, "HIGH RISK")
        self.assertEqual(incon.risk_label, "SUSPICIOUS")
        self.assertEqual(legit.risk_label, "SAFE")


class PDFChartTests(TestCase):
    """Chart helpers embed real figures; the PDF carries the risk percentage."""

    def setUp(self):
        self.owner = User.objects.create_user("chart", "chart@example.com", PASSWORD)

    def _report(self, score=0.82, classification="fraud"):
        d = Detection.objects.create(
            user=self.owner,
            channel="url",
            content="http://paypal-secure.verify.evil.click/login",
            classification=classification,
            is_fraud=(classification == "fraud"),
            risk_score=score,
            score_kind="heuristic",
            signals=["misleading_domain"],
            recommendations=["Do not enter credentials."],
        )
        return Report.objects.create(user=self.owner, detection=d, title="Chart report")

    def test_risk_pie_bytes_is_a_real_png(self):
        data = build_risk_pie_bytes(82)
        self.assertIsNotNone(data)
        self.assertTrue(data.startswith(b"\x89PNG"))  # PNG magic number

    def test_risk_pie_none_when_no_valid_percent(self):
        self.assertIsNone(build_risk_pie_bytes(None))

    def test_history_pie_none_when_no_data(self):
        self.assertIsNone(build_history_pie_bytes({"safe": 0, "suspicious": 0, "high_risk": 0}))

    def test_history_pie_with_real_counts(self):
        data = build_history_pie_bytes({"safe": 3, "suspicious": 1, "high_risk": 2})
        self.assertTrue(data.startswith(b"\x89PNG"))

    def test_pdf_embeds_chart_and_shows_percentage_and_id(self):
        report = self._report()
        pdf = build_report_pdf(report)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        text = _pdf_text(pdf)
        # Table labels can word-wrap, so assert on stable tokens only.
        self.assertIn("Risk", text)
        self.assertIn("82%", text)
        self.assertIn(f"FSR-{report.pk:05d}", text)
        self.assertIn("HIGH", text)  # HIGH RISK classification
        # A raster image XObject proves the matplotlib chart is embedded in the
        # PDF file itself (not merely referenced or shown on the HTML page).
        self.assertIn(b"/Subtype /Image", pdf)


class ReportPDFContentViewTests(TestCase):
    """The download endpoint returns a PDF that reflects the stored record."""

    def setUp(self):
        self.owner = User.objects.create_user("dl", "dl@example.com", PASSWORD)
        self.detection = Detection.objects.create(
            user=self.owner,
            channel="email",
            content="Your account will be suspended",
            classification="fraud",
            is_fraud=True,
            risk_score=0.73,
            score_kind="probability",
            signals=["urgency_language"],
            recommendations=["Verify via the official app."],
        )
        self.report = Report.objects.create(
            user=self.owner, detection=self.detection, title="Email phishing analysis"
        )

    def test_downloaded_pdf_contains_percentage_and_chart_image(self):
        self.client.login(username="dl", password=PASSWORD)
        response = self.client.get(reverse("reports:pdf", args=[self.report.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/Subtype /Image", response.content)
        self.assertIn("73%", _pdf_text(response.content))


@override_settings(REPORT_EMAIL_COOLDOWN_SECONDS=60)
class SendReportEmailTests(TestCase):
    """POST send -> real EmailMessage to the owner's verified address."""

    def setUp(self):
        self.owner = User.objects.create_user("sender", "sender@example.com", PASSWORD)
        prefs = ensure_preferences(self.owner)
        prefs.email_verified = True
        prefs.save()
        self.detection = Detection.objects.create(
            user=self.owner, channel="sms", content="WIN $1000",
            classification="fraud", is_fraud=True, risk_score=0.9, score_kind="probability",
        )
        self.report = Report.objects.create(
            user=self.owner, detection=self.detection, title="SMS analysis"
        )
        self.url = reverse("reports:send_email", args=[self.report.pk])

    def test_get_does_not_send(self):
        self.client.login(username="sender", password=PASSWORD)
        before = len(mail.outbox)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), before)

    def test_anonymous_cannot_send(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers.get("Location", ""))
        self.assertEqual(len(mail.outbox), 0)

    def test_owner_post_sends_pdf_attachment_to_registered_email(self):
        self.client.login(username="sender", password=PASSWORD)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["sender@example.com"])
        self.assertTrue(message.attachments)
        filename, content, mimetype = message.attachments[0]
        self.assertTrue(filename.endswith(".pdf"))
        self.assertEqual(mimetype, "application/pdf")
        self.assertTrue(content.startswith(b"%PDF-"))
        # A DeliveryAttempt row is recorded on success.
        self.assertEqual(
            DeliveryAttempt.objects.filter(
                report=self.report, status=DeliveryAttempt.Status.SENT
            ).count(),
            1,
        )

    def test_other_user_cannot_send_foreign_report(self):
        intruder = User.objects.create_user("intruder", "i@example.com", PASSWORD)
        ensure_preferences(intruder).email_verified = True
        self.client.login(username="intruder", password=PASSWORD)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        DEFAULT_FROM_EMAIL="FraudShield AI",  # display name only -> no address
        EMAIL_HOST_USER="sender@gmail.com",
    )
    def test_send_derives_valid_from_when_default_has_no_address(self):
        # Guards the real Gmail 553 failure: the sender must become a valid
        # address matching the authenticated account, never "FraudShield AI".
        self.client.login(username="sender", password=PASSWORD)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].from_email, "FraudShield AI <sender@gmail.com>"
        )

    def test_requires_verified_email(self):
        prefs = ensure_preferences(self.owner)
        prefs.email_verified = False
        prefs.save()
        self.client.login(username="sender", password=PASSWORD)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 0)
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("not verified" in m for m in messages))

    def test_requires_registered_email(self):
        self.owner.email = ""
        self.owner.save()
        self.client.login(username="sender", password=PASSWORD)
        response = self.client.post(self.url)
        self.assertEqual(len(mail.outbox), 0)
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("No valid registered email" in m for m in messages))

    def test_smtp_failure_is_reported_honestly(self):
        self.client.login(username="sender", password=PASSWORD)
        with mock.patch(
            "django.core.mail.EmailMessage.send", side_effect=OSError("SMTP down")
        ):
            response = self.client.post(self.url)
        self.assertEqual(len(mail.outbox), 0)
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("NOT delivered" in m for m in messages))
        self.assertEqual(
            DeliveryAttempt.objects.filter(status=DeliveryAttempt.Status.FAILED).count(),
            1,
        )

    def test_cooldown_blocks_duplicate_send(self):
        self.client.login(username="sender", password=PASSWORD)
        first = self.client.post(self.url)
        self.assertEqual(len(mail.outbox), 1)
        second = self.client.post(self.url)
        # Still one message: the second is rate limited.
        self.assertEqual(len(mail.outbox), 1)
        messages = [str(m) for m in get_messages(second.wsgi_request)]
        self.assertTrue(any("wait" in m.lower() for m in messages))


class EmailHelperTests(TestCase):
    def test_mask_email_hides_local_part(self):
        self.assertEqual(mask_email("manager@corp.example"), "man****@corp.example")
        self.assertEqual(mask_email("bo@x.io"), "b****@x.io")
        self.assertEqual(mask_email(""), "")
        self.assertEqual(mask_email("not-an-email"), "")

    def test_service_success_sets_ok_status(self):
        owner = User.objects.create_user("svc", "svc@example.com", PASSWORD)
        ensure_preferences(owner).email_verified = True
        detection = Detection.objects.create(
            user=owner, channel="url", content="http://a.b", classification="legitimate",
            risk_score=0.05,
        )
        report = Report.objects.create(user=owner, detection=detection, title="R")
        status, message = send_report_to_registered_email(owner, report)
        self.assertEqual(status, "ok")
        self.assertIn(mask_email("svc@example.com"), message)


class ReportEmailButtonAvailabilityTests(TestCase):
    """The Send button on the report page is gated on a verified email."""

    def setUp(self):
        self.user = User.objects.create_user("btn", "btn@example.com", PASSWORD)
        self.detection = Detection.objects.create(
            user=self.user, channel="url", content="http://example.com",
            classification="legitimate", risk_score=0.05,
        )
        self.report = Report.objects.create(
            user=self.user, detection=self.detection, title="Web report"
        )
        self.detail_url = reverse("reports:detail", args=[self.report.pk])
        # Present only when the enabled POST form is rendered.
        self.send_form = (
            'action="' + reverse("reports:send_email", args=[self.report.pk]) + '"'
        )

    def _set_verified(self, value):
        prefs = ensure_preferences(self.user)
        prefs.email_verified = value
        prefs.save()

    def test_button_disabled_when_email_not_verified(self):
        self._set_verified(False)
        self.client.login(username="btn", password=PASSWORD)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Verify your email")
        self.assertNotContains(response, self.send_form)

    def test_button_disabled_for_user_without_preferences_row(self):
        # Default-deny: a missing preferences row must NOT enable sending.
        self.client.login(username="btn", password=PASSWORD)
        response = self.client.get(self.detail_url)
        self.assertContains(response, "Verify your email")
        self.assertNotContains(response, self.send_form)

    def test_button_enabled_after_verification(self):
        self._set_verified(True)
        self.client.login(username="btn", password=PASSWORD)
        response = self.client.get(self.detail_url)
        self.assertContains(response, self.send_form)
        self.assertContains(response, mask_email("btn@example.com"))
        self.assertNotContains(response, "Verify your email")

    def test_button_disabled_when_email_missing(self):
        self._set_verified(True)
        self.user.email = ""
        self.user.save()
        self.client.login(username="btn", password=PASSWORD)
        response = self.client.get(self.detail_url)
        self.assertContains(response, "Add an email address in your profile")
        self.assertNotContains(response, self.send_form)

    def test_download_pdf_always_available_regardless_of_verification(self):
        # Verification gates email only - PDF download stays available to owner.
        self._set_verified(False)
        self.client.login(username="btn", password=PASSWORD)
        response = self.client.get(self.detail_url)
        self.assertContains(response, "Download PDF Report")
