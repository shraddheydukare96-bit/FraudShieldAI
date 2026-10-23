"""Tests for the AI detection engine, service layer, and per-user isolation.

Covers: representative examples (text + URL), invalid input, missing model file,
and user-level data isolation. Nothing here asserts real-world accuracy - only
that the deterministic pipeline behaves correctly on the project baseline.
"""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from detection import services
from detection.ml import classifier, url_analyzer
from detection.ml.result import FRAUD, LEGITIMATE
from detection.models import Detection

PASSWORD = "Str0ng!Passw0rd-9"

SPAM_TEXT = "You have been selected for a cash prize of $1000. Reply WIN to claim immediately"
HAM_TEXT = "Hey are we still on for lunch today at noon"


def _fit_on_full_corpus():
    """Fit the pipeline on the entire baseline corpus for deterministic tests."""
    corpus = classifier.load_corpus("data/fraud_text_dataset.csv")
    pipeline = classifier.build_pipeline()
    pipeline.fit(corpus.texts, corpus.labels)
    return pipeline


class MLUnitCleanupMixin:
    def tearDown(self):
        # Never leak an injected pipeline between tests.
        classifier._CACHE["pipeline"] = None
        super().tearDown()


class URLAnalyzerTests(TestCase):
    def test_domain_based_malicious_url_flags_rules(self):
        result = url_analyzer.analyze_url(
            "http://paypal-secure.verify.evil.click/login"
        )
        self.assertEqual(result.classification, FRAUD)
        self.assertGreaterEqual(result.risk_score, url_analyzer.FRAUD_THRESHOLD)
        triggered = result.detail["triggered_rules"]
        for expected in [
            "misleading_domain",
            "risky_tld",
            "credential_path_keyword",
            "insecure_http",
        ]:
            self.assertIn(expected, triggered)

    def test_ip_host_url_is_flagged(self):
        result = url_analyzer.analyze_url("http://203.0.113.9/verify-account")
        self.assertIn("ip_address_host", result.detail["triggered_rules"])

    def test_benign_url_is_legitimate(self):
        result = url_analyzer.analyze_url("https://www.example.com/blog/post")
        self.assertEqual(result.classification, LEGITIMATE)
        self.assertLess(result.risk_score, url_analyzer.SUSPICIOUS_THRESHOLD)

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            url_analyzer.analyze_url("   ")

    def test_risk_score_is_heuristic_not_probability(self):
        result = url_analyzer.analyze_url("http://suspicious-host.biz")
        self.assertEqual(result.score_kind, "heuristic")


class MissingModelTests(MLUnitCleanupMixin, TestCase):
    def test_predict_raises_when_model_artifact_absent(self):
        classifier._CACHE["pipeline"] = None
        with mock.patch.object(classifier, "MODEL_PATH", "no/such/model.joblib"):
            with self.assertRaises(classifier.ModelUnavailableError):
                classifier.predict_text(SPAM_TEXT, channel="sms")

    def test_service_returns_honest_unavailable_and_saves_nothing(self):
        user = User.objects.create_user("nobody", "nobody@example.com", PASSWORD)
        classifier._CACHE["pipeline"] = None
        with mock.patch.object(classifier, "MODEL_PATH", "no/such/model.joblib"):
            outcome = services.run_analysis(user, "sms", SPAM_TEXT)
        self.assertFalse(outcome.ok)
        self.assertIn("train_model", outcome.message)
        self.assertEqual(Detection.objects.filter(user=user).count(), 0)


class TextClassifierTests(MLUnitCleanupMixin, TestCase):
    def setUp(self):
        classifier._CACHE["pipeline"] = _fit_on_full_corpus()

    def test_spam_text_classified_as_fraud_with_probability(self):
        result = classifier.predict_text(SPAM_TEXT, channel="sms")
        self.assertEqual(result.classification, FRAUD)
        self.assertEqual(result.score_kind, "probability")
        self.assertGreater(result.risk_score, 0.5)

    def test_ham_text_classified_as_legitimate(self):
        result = classifier.predict_text(HAM_TEXT, channel="sms")
        self.assertEqual(result.classification, LEGITIMATE)
        self.assertLess(result.risk_score, 0.5)

    def test_empty_text_raises(self):
        with self.assertRaises(ValueError):
            classifier.predict_text("", channel="email")


class AnalysisServicePersistenceTests(MLUnitCleanupMixin, TestCase):
    def setUp(self):
        classifier._CACHE["pipeline"] = _fit_on_full_corpus()
        self.user = User.objects.create_user("ana", "ana@example.com", PASSWORD)

    def test_completed_text_analysis_is_saved_for_user(self):
        outcome = services.run_analysis(self.user, "sms", SPAM_TEXT)
        self.assertTrue(outcome.ok)
        detection = outcome.detection
        self.assertEqual(detection.user, self.user)
        self.assertEqual(detection.classification, FRAUD)
        self.assertTrue(detection.is_fraud)
        self.assertTrue(detection.source == "text_model")

    def test_completed_url_analysis_is_saved_for_user(self):
        outcome = services.run_analysis(
            self.user, "url", "http://10.0.0.5/login-verify.biz"
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.detection.source, "url_rules")
        self.assertEqual(outcome.detection.score_kind, "heuristic")

    def test_invalid_channel_does_not_save(self):
        outcome = services.run_analysis(self.user, "carrier-pigeon", "hello world")
        self.assertFalse(outcome.ok)
        self.assertEqual(Detection.objects.filter(user=self.user).count(), 0)


class AnalysisViewIntegrationTests(TestCase):
    def setUp(self):
        # URL channel needs no model, keeping the view test independent of
        # training artifacts.
        self.user = User.objects.create_user("view", "view@example.com", PASSWORD)
        self.other = User.objects.create_user("other", "other@example.com", PASSWORD)

    def test_anonymous_cannot_access_analysis_page(self):
        response = self.client.get(reverse("detection:analyze"))
        self.assertEqual(response.status_code, 302)

    def test_logged_in_user_can_run_url_analysis_via_view(self):
        self.client.login(username="view", password=PASSWORD)
        response = self.client.post(
            reverse("detection:analyze"),
            {"channel": "url", "content": "http://192.168.0.1/paypal-verify.click/login"},
        )
        # Redirects to the created detection's detail page.
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Detection.objects.filter(user=self.user).count(), 1)

    def test_cross_user_cannot_view_foreign_analysis(self):
        detection = Detection.objects.create(
            user=self.user, channel="url", content="http://a.biz", classification="fraud"
        )
        self.client.login(username="other", password=PASSWORD)
        detail = self.client.get(
            reverse("detection:detail", args=[detection.pk])
        )
        self.assertEqual(detail.status_code, 404)

    def test_owner_detail_page_renders_report_actions_and_percentage(self):
        from reports.models import Report

        detection = Detection.objects.create(
            user=self.user,
            channel="url",
            content="http://paypal-secure.verify.evil.click/login",
            classification="fraud",
            is_fraud=True,
            risk_score=0.82,
            score_kind="heuristic",
            signals=["misleading_domain"],
            recommendations=["Do not enter credentials."],
        )
        self.client.login(username="view", password=PASSWORD)
        response = self.client.get(reverse("detection:detail", args=[detection.pk]))
        self.assertEqual(response.status_code, 200)
        # Risk percentage from the real stored score, plus both action buttons.
        self.assertContains(response, "82%")
        self.assertContains(response, "Download PDF Report")
        self.assertContains(response, "Send Report to Registered Email")
        # The shared helper created exactly one report for this detection.
        self.assertEqual(Report.objects.filter(detection=detection).count(), 1)

    def test_url_analysis_redirects_to_renders_detail(self):
        # End-to-end: run an analysis, follow to the detail page, see the PDF
        # and email actions on the freshly created record.
        self.client.login(username="view", password=PASSWORD)
        response = self.client.post(
            reverse("detection:analyze"),
            {"channel": "url", "content": "http://paypal-verify.evil.click/login"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Download PDF Report")

    def test_history_list_excludes_foreign_records(self):
        Detection.objects.create(
            user=self.user, channel="url",
            content="secret-user-only-content", classification="fraud",
        )
        self.client.login(username="other", password=PASSWORD)
        response = self.client.get(reverse("detection:index"))
        self.assertNotContains(response, "secret-user-only-content")


class HistoryFilterTests(TestCase):
    """Search, date, channel, classification filters + pagination + ownership."""

    def setUp(self):
        self.user = User.objects.create_user("hist", "hist@example.com", PASSWORD)
        self.other = User.objects.create_user("intruder", "i@example.com", PASSWORD)
        self.client.login(username="hist", password=PASSWORD)

    def _mk(self, content, channel="url", classification="legitimate"):
        return Detection.objects.create(
            user=self.user,
            channel=channel,
            content=content,
            classification=classification,
            is_fraud=(classification == "fraud"),
        )

    def _pks_in_response(self, response):
        return {d.pk for d in response.context["detections"]}

    def test_search_q_matches_content_substring(self):
        a = self._mk("paypal secure login warning")
        b = self._mk("weekly standup moved to tuesday")
        response = self.client.get(reverse("detection:index"), {"q": "paypal"})
        self.assertEqual(self._pks_in_response(response), {a.pk})
        self.assertNotIn(b.pk, self._pks_in_response(response))

    def test_channel_filter_only_returns_that_channel(self):
        sms = self._mk("hi", channel="sms", classification="fraud")
        email = self._mk("hi", channel="email", classification="legitimate")
        response = self.client.get(reverse("detection:index"), {"channel": "sms"})
        self.assertEqual(self._pks_in_response(response), {sms.pk})
        self.assertNotIn(email.pk, self._pks_in_response(response))

    def test_classification_filter_high_risk(self):
        fraud = self._mk("a", classification="fraud")
        self._mk("b", classification="legitimate")
        self._mk("c", classification="inconclusive")
        response = self.client.get(
            reverse("detection:index"), {"classification": "fraud"}
        )
        self.assertEqual(self._pks_in_response(response), {fraud.pk})

    def test_date_range_filter(self):
        from datetime import timedelta

        import django.utils.timezone as tz

        old = self._mk("ancient", classification="fraud")
        # Backdate one record well outside the recent window.
        Detection.objects.filter(pk=old.pk).update(
            created_at=tz.now() - timedelta(days=90)
        )
        recent = self._mk("fresh", classification="fraud")
        response = self.client.get(
            reverse("detection:index"),
            {"date_from": (tz.localdate() - timedelta(days=7)).isoformat()},
        )
        pks = self._pks_in_response(response)
        self.assertIn(recent.pk, pks)
        self.assertNotIn(old.pk, pks)

    def test_combined_filters_are_anded(self):
        target = self._mk("urgent wire transfer", channel="sms", classification="fraud")
        self._mk("urgent wire transfer", channel="email", classification="fraud")
        self._mk("urgent wire transfer", channel="sms", classification="legitimate")
        response = self.client.get(
            reverse("detection:index"),
            {"q": "wire", "channel": "sms", "classification": "fraud"},
        )
        self.assertEqual(self._pks_in_response(response), {target.pk})

    def test_pagination_splits_results(self):
        for i in range(30):
            self._mk(f"record-{i}", classification="fraud")
        page1 = self.client.get(reverse("detection:index"))
        self.assertTrue(page1.context["is_paginated"])
        self.assertEqual(len(page1.context["detections"]), 25)
        page2 = self.client.get(reverse("detection:index"), {"page": 2})
        self.assertEqual(len(page2.context["detections"]), 5)
        # Pages must not overlap.
        self.assertEqual(
            self._pks_in_response(page1) & self._pks_in_response(page2), set()
        )

    def test_filters_never_leak_other_users_records(self):
        Detection.objects.create(
            user=self.other,
            channel="url",
            content="paypal other user private",
            classification="fraud",
        )
        mine = self._mk("paypal mine", classification="fraud")
        response = self.client.get(reverse("detection:index"), {"q": "paypal"})
        self.assertEqual(self._pks_in_response(response), {mine.pk})

    def test_detail_page_404_for_foreign_record(self):
        foreign = Detection.objects.create(
            user=self.other, channel="url", content="nope", classification="fraud"
        )
        response = self.client.get(reverse("detection:detail", args=[foreign.pk]))
        self.assertEqual(response.status_code, 404)

    def test_clear_link_shown_when_filters_active(self):
        self._mk("x", classification="fraud")
        response = self.client.get(reverse("detection:index"), {"q": "x"})
        self.assertTrue(response.context["has_filters"])
