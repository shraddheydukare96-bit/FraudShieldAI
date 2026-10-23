"""Tests for the dashboard: real, per-user database statistics.

Every number shown on the dashboard must come from actual ``Detection`` rows.
These tests guard against (a) hardcoded/placeholder counts, (b) leaking other
users' data into your totals, and (c) charts/recent lists becoming inconsistent
with the underlying data.
"""
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from detection.models import Detection
from reports.models import Report

PASSWORD = "Str0ng!Passw0rd-9"


def _make(user, classification, channel="url", content="http://x.example"):
    return Detection.objects.create(
        user=user,
        channel=channel,
        content=content,
        classification=classification,
        is_fraud=(classification == "fraud"),
        risk_score=0.9 if classification == "fraud" else 0.1,
        score_kind="probability",
        source="text_model",
    )


class DashboardAccessTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("dash", "dash@example.com", PASSWORD)

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers.get("Location", ""))

    def test_empty_state_when_no_data(self):
        self.client.login(username="dash", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/index.html")
        self.assertFalse(response.context["has_data"])
        self.assertEqual(response.context["total_analyses"], 0)
        self.assertEqual(response.context["safe_count"], 0)
        self.assertEqual(response.context["suspicious_count"], 0)
        self.assertEqual(response.context["high_risk_count"], 0)


class DashboardCountTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("counter", "c@example.com", PASSWORD)
        self.other = User.objects.create_user("stranger", "s@example.com", PASSWORD)
        # Data for the signed-in user.
        for _ in range(2):
            _make(self.user, "legitimate")
        _make(self.user, "inconclusive")
        for _ in range(3):
            _make(self.user, "fraud")
        # Noise from another user must NOT influence our counts.
        _make(self.other, "fraud")
        _make(self.other, "legitimate")

    def test_counts_reflect_only_current_user(self):
        self.client.login(username="counter", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.context["total_analyses"], 6)
        self.assertEqual(response.context["safe_count"], 2)
        self.assertEqual(response.context["suspicious_count"], 1)
        self.assertEqual(response.context["high_risk_count"], 3)

    def test_has_data_true_when_records_exist(self):
        self.client.login(username="counter", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        self.assertTrue(response.context["has_data"])

    def test_recent_detections_capped_at_five_newest_first(self):
        self.client.login(username="counter", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        recent = list(response.context["recent_detections"])
        self.assertLessEqual(len(recent), 5)
        self.assertEqual(len(recent), 5)  # 6 exist -> top 5
        # Ordering is by -created_at, so the ids should be descending.
        ids = [d.pk for d in recent]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_report_count_uses_own_reports_only(self):
        detection = _make(self.user, "fraud")
        Report.objects.create(user=self.user, detection=detection, title="Mine")
        Report.objects.create(user=self.other, detection=None, title="Not mine")
        self.client.login(username="counter", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.context["report_count"], 1)


class DashboardChartTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("chart", "chart@example.com", PASSWORD)
        _make(self.user, "fraud", channel="sms", content="hi")
        _make(self.user, "legitimate", channel="email", content="hi")
        _make(self.user, "legitimate", channel="url", content="http://x")

    def test_channel_breakdown_matches_data(self):
        self.client.login(username="chart", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        charts = response.context["charts"]
        # Sum of channel series equals total rows.
        self.assertEqual(sum(charts["channel"]["data"]), 3)
        # Risk series matches classification counts.
        self.assertEqual(
            charts["risk"]["data"],
            [
                response.context["safe_count"],
                response.context["suspicious_count"],
                response.context["high_risk_count"],
            ],
        )
        self.assertEqual(sum(charts["risk"]["data"]), 3)

    def test_trend_series_length_is_30_days(self):
        self.client.login(username="chart", password=PASSWORD)
        response = self.client.get(reverse("dashboard:index"))
        trend = response.context["charts"]["trend"]
        self.assertEqual(len(trend["labels"]), 30)
        self.assertEqual(len(trend["data"]), 30)
        # Today's bucket should account for at least the 3 rows just created.
        self.assertGreaterEqual(trend["data"][-1], 3)
