"""Automated tests for the authentication + email verification system."""
import io
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core import mail
from django.core.management import call_command, CommandError
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import EmailVerificationToken, NotificationPreferences
from .services import (
    VerifyResult,
    build_verification_url,
    ensure_preferences,
    issue_verification,
    redeem_token,
    resolve_base_url,
    resolve_from_email,
    send_verification_email,
    verification_send_block_seconds,
    verification_throttle_message,
)

VALID_PASSWORD = "Str0ng!Passw0rd-9"


class SignupTests(TestCase):
    def test_successful_registration_creates_user_and_logs_in(self):
        url = reverse("accounts:signup")
        response = self.client.post(
            url,
            {
                "username": "alice",
                "email": "alice@example.com",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        # Signup now redirects to the "check your inbox" page and keeps the
        # user authenticated so they can browse while unverified.
        self.assertRedirects(response, reverse("accounts:verify_sent"))
        self.assertTrue(User.objects.filter(username="alice").exists())
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_signup_creates_preferences_and_token_and_queues_email(self):
        self.client.post(
            reverse("accounts:signup"),
            {
                "username": "viktor",
                "email": "viktor@example.com",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        user = User.objects.get(username="viktor")
        # NotificationPreferences row exists, unverified.
        prefs = NotificationPreferences.objects.get(user=user)
        self.assertFalse(prefs.email_verified)
        # One active token, and a real email is in the locmem outbox.
        token = EmailVerificationToken.objects.filter(user=user, used_at__isnull=True).get()
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("viktor@example.com", mail.outbox[0].to)
        self.assertIn(token.key, mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].subject.strip(), "FraudShield AI - verify your email address")

    def test_password_is_hashed_not_stored_in_plaintext(self):
        self.client.post(
            reverse("accounts:signup"),
            {
                "username": "bob",
                "email": "bob@example.com",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        user = User.objects.get(username="bob")
        self.assertNotEqual(user.password, VALID_PASSWORD)
        self.assertTrue(user.password.startswith("pbkdf2_"))
        self.assertTrue(user.check_password(VALID_PASSWORD))

    def test_signup_rejects_password_mismatch(self):
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "carol",
                "email": "carol@example.com",
                "password1": VALID_PASSWORD,
                "password2": "Different!Passw0rd-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="carol").exists())
        self.assertContains(response, "do not match")

    def test_signup_rejects_duplicate_username(self):
        User.objects.create_user("dave", "dave@example.com", VALID_PASSWORD)
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "dave",
                "email": "other@example.com",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already taken")

    def test_signup_rejects_duplicate_email(self):
        User.objects.create_user("erin", "erin@example.com", VALID_PASSWORD)
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "newname",
                "email": "erin@example.com",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")

    def test_signup_requires_email(self):
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "noemail",
                "email": "",
                "password1": VALID_PASSWORD,
                "password2": VALID_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="noemail").exists())

    def test_signup_page_contains_csrf_token(self):
        response = self.client.get(reverse("accounts:signup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "csrfmiddlewaretoken")


class LoginLogoutTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "frank", "frank@example.com", VALID_PASSWORD
        )

    def test_login_success(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": "frank", "password": VALID_PASSWORD},
        )
        self.assertRedirects(response, reverse("dashboard:index"))
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_wrong_password_fails(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": "frank", "password": "wrong-password"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["form"].is_valid())
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_page_contains_csrf_token(self):
        response = self.client.get(reverse("accounts:login"))
        self.assertContains(response, "csrfmiddlewaretoken")

    def test_logout_requires_post_and_redirects(self):
        self.client.login(username="frank", password=VALID_PASSWORD)
        # GET logout is not permitted (returns 405).
        self.assertEqual(self.client.get(reverse("accounts:logout")).status_code, 405)
        response = self.client.post(reverse("accounts:logout"))
        self.assertRedirects(response, reverse("accounts:login"))
        self.assertNotIn("_auth_user_id", self.client.session)


class ProfileTests(TestCase):
    def test_profile_shows_username_for_authenticated_user(self):
        User.objects.create_user("grace", "grace@example.com", VALID_PASSWORD)
        self.client.login(username="grace", password=VALID_PASSWORD)
        response = self.client.get(reverse("accounts:profile"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "grace")

    def test_profile_shows_verified_badge_after_redemption(self):
        user = User.objects.create_user("hank", "hank@example.com", VALID_PASSWORD)
        prefs = ensure_preferences(user)
        prefs.email_verified = True
        prefs.verified_at = timezone.now()
        prefs.save()
        self.client.login(username="hank", password=VALID_PASSWORD)
        response = self.client.get(reverse("accounts:profile"))
        self.assertContains(response, "Verified")


class AnonymousAccessTests(TestCase):
    protected_urls = [
        "dashboard:index",
        "detection:index",
        "reports:index",
        "accounts:profile",
        "accounts:preferences",
        "accounts:verify_sent",
    ]

    def test_anonymous_redirected_to_login(self):
        for name in self.protected_urls:
            with self.subTest(url=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 302)
                self.assertIn(
                    reverse("accounts:login"), response.headers["location"]
                )


# --------------------------------------------------------------------------- #
# Email verification tests
# --------------------------------------------------------------------------- #


class VerifyTokenModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ivy", "ivy@example.com", VALID_PASSWORD)

    def test_issue_creates_unique_key_and_sets_expiry(self):
        token = EmailVerificationToken.issue(self.user)
        self.assertEqual(len(token.key), 43)  # secrets.token_urlsafe(32) -> 43 chars
        self.assertGreater(token.expires_at, timezone.now())

    def test_issue_invalidates_previous_active_token(self):
        first = EmailVerificationToken.issue(self.user)
        second = EmailVerificationToken.issue(self.user)
        first.refresh_from_db()
        self.assertIsNotNone(first.used_at, "prior token should be marked used")
        self.assertIsNone(second.used_at)

    def test_expired_property(self):
        token = EmailVerificationToken.issue(self.user)
        token.expires_at = timezone.now() - timedelta(hours=1)
        token.save()
        self.assertTrue(token.expired)


class RedeemTokenServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("jack", "jack@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)

    def _make_token(self, **kw):
        return EmailVerificationToken.issue(self.user, **kw)

    def test_redeem_valid_token_marks_verified(self):
        token = self._make_token()
        status, t = redeem_token(token.key)
        self.assertEqual(status, VerifyResult.OK)
        prefs = NotificationPreferences.objects.get(user=self.user)
        self.assertTrue(prefs.email_verified)
        self.assertIsNotNone(prefs.verified_at)

    def test_redeem_unknown_token(self):
        status, t = redeem_token("does-not-exist")
        self.assertEqual(status, VerifyResult.UNKNOWN)
        self.assertIsNone(t)

    def test_redeem_expired_token(self):
        token = self._make_token()
        EmailVerificationToken.objects.filter(pk=token.pk).update(
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        status, t = redeem_token(token.key)
        self.assertEqual(status, VerifyResult.EXPIRED)
        self.assertFalse(NotificationPreferences.objects.get(user=self.user).email_verified)

    def test_redeem_used_token_second_time(self):
        token = self._make_token()
        first, _ = redeem_token(token.key)
        self.assertEqual(first, VerifyResult.OK)
        # Same key after user is already verified -> already_verified path.
        second, _ = redeem_token(token.key)
        self.assertEqual(second, VerifyResult.ALREADY_VERIFIED)

    def test_empty_key_returns_unknown(self):
        status, _ = redeem_token("")
        self.assertEqual(status, VerifyResult.UNKNOWN)


class VerifyEmailViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("kate", "kate@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)
        self.token = EmailVerificationToken.issue(self.user)

    def test_valid_link_shows_success_and_marks_verified(self):
        response = self.client.get(reverse("accounts:verify", args=[self.token.key]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Email verified")
        self.assertTrue(NotificationPreferences.objects.get(user=self.user).email_verified)

    def test_invalid_link_shows_honest_failure(self):
        response = self.client.get(reverse("accounts:verify", args=["bogus"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid link")
        self.assertFalse(NotificationPreferences.objects.get(user=self.user).email_verified)

    def test_expired_link_shows_honest_failure(self):
        EmailVerificationToken.objects.filter(pk=self.token.pk).update(
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        response = self.client.get(reverse("accounts:verify", args=[self.token.key]))
        self.assertContains(response, "Link expired")

    def test_verify_view_is_public(self):
        # No login needed - the token itself is the capability.
        response = self.client.get(reverse("accounts:verify", args=[self.token.key]))
        self.assertEqual(response.status_code, 200)


class ResendVerificationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("leo", "leo@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)

    def test_resend_requires_login(self):
        response = self.client.post(reverse("accounts:verify_resend"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.headers["location"])

    def test_resend_get_redirects_to_sent_page(self):
        self.client.login(username="leo", password=VALID_PASSWORD)
        response = self.client.get(reverse("accounts:verify_resend"))
        self.assertRedirects(response, reverse("accounts:verify_sent"))

    def test_resend_post_issues_new_token_and_emails(self):
        self.client.login(username="leo", password=VALID_PASSWORD)
        before = EmailVerificationToken.objects.filter(user=self.user).count()
        response = self.client.post(reverse("accounts:verify_resend"))
        self.assertRedirects(response, reverse("accounts:verify_sent"))
        after = EmailVerificationToken.objects.filter(user=self.user)
        self.assertGreater(after.count(), before)
        self.assertTrue(after.filter(used_at__isnull=True).exists())
        self.assertEqual(len(mail.outbox), 1)

    def test_resend_when_already_verified_does_not_email(self):
        prefs = NotificationPreferences.objects.get(user=self.user)
        prefs.email_verified = True
        prefs.save()
        self.client.login(username="leo", password=VALID_PASSWORD)
        self.client.post(reverse("accounts:verify_resend"))
        self.assertEqual(len(mail.outbox), 0)


class VerificationServiceTests(TestCase):
    """build_verification_url + send_verification_email honour the backend."""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user("vera", "vera@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)

    def test_build_verification_url_matches_reverse_path(self):
        request = self.factory.get("/")
        url = build_verification_url(request, "abc123")
        self.assertTrue(url.startswith("http://"))
        self.assertTrue(url.endswith(reverse("accounts:verify", args=["abc123"])))

    def test_build_verification_url_uses_https_when_secure(self):
        request = self.factory.get("/", secure=True)
        self.assertTrue(build_verification_url(request, "abc123").startswith("https://"))

    def test_send_uses_active_backend_and_embeds_working_link(self):
        request = self.factory.get("/")
        token = EmailVerificationToken.issue(self.user)
        self.assertTrue(send_verification_email(request, token))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("vera@example.com", mail.outbox[0].to)
        # The URL in the body resolves to the real verify route.
        self.assertIn(reverse("accounts:verify", args=[token.key]), mail.outbox[0].body)

    def test_send_returns_false_when_already_verified(self):
        prefs = NotificationPreferences.objects.get(user=self.user)
        prefs.email_verified = True
        prefs.save()
        token = EmailVerificationToken.issue(self.user)
        self.assertFalse(send_verification_email(self.factory.get("/"), token))
        self.assertEqual(len(mail.outbox), 0)

    def test_send_returns_false_when_user_has_no_email(self):
        self.user.email = ""
        self.user.save()
        token = EmailVerificationToken.issue(self.user)
        self.assertFalse(send_verification_email(self.factory.get("/"), token))
        self.assertEqual(len(mail.outbox), 0)

    def test_send_returns_false_on_backend_failure(self):
        # A real SMTP error must not be reported as success.
        token = EmailVerificationToken.issue(self.user)
        with mock.patch(
            "django.core.mail.EmailMessage.send", side_effect=OSError("SMTP down")
        ):
            self.assertFalse(send_verification_email(self.factory.get("/"), token))

    def test_redeemed_user_can_verify_end_to_end(self):
        # Send -> click link -> redeem -> status flips to verified.
        request = self.factory.get("/")
        token = EmailVerificationToken.issue(self.user)
        send_verification_email(request, token)
        path = reverse("accounts:verify", args=[token.key])
        response = self.client.get(path)
        self.assertContains(response, "Email verified")
        self.assertTrue(
            NotificationPreferences.objects.get(user=self.user).email_verified
        )


class SiteUrlVerificationLinkTests(TestCase):
    """Emailed links use the configured SITE_URL and never a forged Host header."""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user("siteuser", "site@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)

    def test_site_url_is_used_as_base_and_host_header_ignored(self):
        # A crafted Host header must NOT leak into the link when SITE_URL is set.
        request = self.factory.get("/", HTTP_HOST="evil.example")
        with override_settings(SITE_URL="https://fraud.example.com"):
            url = build_verification_url(request, "tok123")
        self.assertEqual(
            url, "https://fraud.example.com" + reverse("accounts:verify", args=["tok123"])
        )
        self.assertNotIn("evil.example", url)

    def test_trailing_slash_in_site_url_is_normalised(self):
        request = self.factory.get("/")
        with override_settings(SITE_URL="https://fraud.example.com/"):
            url = build_verification_url(request, "tok456")
        # Exactly one slash between host and path - no "//accounts".
        self.assertNotIn("//accounts", url)
        self.assertEqual(
            url, "https://fraud.example.com" + reverse("accounts:verify", args=["tok456"])
        )

    def test_local_network_url_is_respected(self):
        # Explicit LAN base lets a phone reach the link.
        request = self.factory.get("/", HTTP_HOST="127.0.0.1:8000")
        with override_settings(SITE_URL="http://192.168.1.50:8000"):
            url = build_verification_url(request, "lan789")
        self.assertTrue(url.startswith("http://192.168.1.50:8000/"))
        self.assertTrue(url.endswith(reverse("accounts:verify", args=["lan789"])))

    def test_resolve_base_url_returns_site_url_when_set(self):
        with override_settings(SITE_URL="https://fraud.example.com"):
            self.assertEqual(resolve_base_url(self.factory.get("/")), "https://fraud.example.com")

    def test_resolve_base_url_falls_back_to_request_when_unset(self):
        # No SITE_URL (local dev): derive from the request, honour is_secure().
        with override_settings(SITE_URL=""):
            self.assertEqual(
                resolve_base_url(self.factory.get("/", secure=True)).startswith("https://"),
                True,
            )

    def test_send_verification_email_embeds_site_url_link(self):
        token = EmailVerificationToken.issue(self.user)
        with override_settings(SITE_URL="https://fraud.example.com"):
            self.assertTrue(send_verification_email(self.factory.get("/"), token))
        self.assertEqual(len(mail.outbox), 1)
        expected = "https://fraud.example.com" + reverse("accounts:verify", args=[token.key])
        self.assertIn(expected, mail.outbox[0].body)
        self.assertNotIn("127.0.0.1", mail.outbox[0].body)

    def test_site_url_does_not_change_token_validation_or_ownership(self):
        # The link base is cosmetic; redeeming still verifies the right user and
        # a token is still single-use regardless of SITE_URL.
        token = EmailVerificationToken.issue(self.user)
        with override_settings(SITE_URL="https://fraud.example.com"):
            status, redeemed = redeem_token(token.key)
        self.assertEqual(status, VerifyResult.OK)
        self.assertEqual(redeemed.user, self.user)
        self.assertTrue(
            NotificationPreferences.objects.get(user=self.user).email_verified
        )


class ResendEdgeCaseTests(TestCase):
    """Resend must be robust for legacy accounts and missing email addresses."""

    def test_legacy_user_without_preferences_row_can_resend(self):
        legacy = User.objects.create_user("legacy", "legacy@example.com", VALID_PASSWORD)
        self.assertFalse(NotificationPreferences.objects.filter(user=legacy).exists())
        self.client.login(username="legacy", password=VALID_PASSWORD)
        # Before the fix this raised RelatedObjectDoesNotExist (HTTP 500).
        response = self.client.post(reverse("accounts:verify_resend"))
        self.assertRedirects(response, reverse("accounts:verify_sent"))
        self.assertTrue(NotificationPreferences.objects.filter(user=legacy).exists())
        self.assertEqual(len(mail.outbox), 1)

    def test_resend_with_no_email_shows_truthful_error(self):
        noemail = User.objects.create_user("noemail2", "", VALID_PASSWORD)
        ensure_preferences(noemail)
        self.client.login(username="noemail2", password=VALID_PASSWORD)
        response = self.client.post(reverse("accounts:verify_resend"))
        self.assertEqual(len(mail.outbox), 0)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("Add an email address" in m for m in msgs))

    def test_resend_surfaces_backend_failure_honestly(self):
        user = User.objects.create_user("rob", "rob@example.com", VALID_PASSWORD)
        ensure_preferences(user)
        self.client.login(username="rob", password=VALID_PASSWORD)
        with mock.patch(
            "django.core.mail.EmailMessage.send", side_effect=OSError("SMTP down")
        ):
            response = self.client.post(reverse("accounts:verify_resend"))
        self.assertEqual(len(mail.outbox), 0)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("could not send" in m for m in msgs))


@override_settings(
    VERIFICATION_EMAIL_COOLDOWN_SECONDS=60, VERIFICATION_EMAIL_HOURLY_LIMIT=5
)
class VerificationThrottleServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("thr", "thr@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)

    def test_no_prior_send_is_allowed(self):
        self.assertIsNone(verification_send_block_seconds(self.user))

    def test_send_within_cooldown_is_blocked(self):
        issue_verification(self.user)  # a send creates a token at "now"
        wait = verification_send_block_seconds(self.user)
        self.assertIsNotNone(wait)
        self.assertGreater(wait, 0)
        self.assertLessEqual(wait, 60)

    def test_send_allowed_once_cooldown_elapsed(self):
        token = issue_verification(self.user)
        EmailVerificationToken.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timedelta(seconds=120)
        )
        self.assertIsNone(verification_send_block_seconds(self.user))

    def test_hourly_cap_blocks_after_limit(self):
        # Zero the per-send cooldown so only the hourly cap can trigger.
        with self.settings(VERIFICATION_EMAIL_COOLDOWN_SECONDS=0):
            for _ in range(5):
                issue_verification(self.user)
            wait = verification_send_block_seconds(self.user)
        self.assertIsNotNone(wait)
        self.assertGreaterEqual(wait, 1)

    def test_expired_old_token_does_not_lock_user_out(self):
        # A stale (expired) token from well over an hour ago must NOT create a
        # multi-hour block - this is the fix for the perceived "24h wait".
        token = issue_verification(self.user)
        EmailVerificationToken.objects.filter(pk=token.pk).update(
            created_at=timezone.now() - timedelta(hours=2),
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertIsNone(verification_send_block_seconds(self.user))

    def test_throttle_message_wording(self):
        self.assertIn("seconds", verification_throttle_message(45))
        self.assertIn("minute", verification_throttle_message(180))
        self.assertEqual(verification_throttle_message(None), "")


@override_settings(
    VERIFICATION_EMAIL_COOLDOWN_SECONDS=60, VERIFICATION_EMAIL_HOURLY_LIMIT=5
)
class VerificationResendThrottleViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("rs", "rs@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)
        self.client.login(username="rs", password=VALID_PASSWORD)
        self.resend_url = reverse("accounts:verify_resend")
        self.sent_url = reverse("accounts:verify_sent")

    def test_first_resend_succeeds(self):
        response = self.client.post(self.resend_url)
        self.assertRedirects(response, self.sent_url)
        self.assertEqual(len(mail.outbox), 1)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("new verification link" in m for m in msgs))

    def test_immediate_second_resend_is_throttled(self):
        self.client.post(self.resend_url)          # allowed
        first_tokens = EmailVerificationToken.objects.filter(user=self.user).count()
        response = self.client.post(self.resend_url)  # within 60s -> blocked
        self.assertEqual(len(mail.outbox), 1)  # no second email sent
        self.assertEqual(
            EmailVerificationToken.objects.filter(user=self.user).count(),
            first_tokens,
        )  # no new token issued
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        # Both throttle phrasings mention "verification email"; assert that and
        # that a warning was raised, without depending on seconds-vs-minutes.
        self.assertTrue(any("verification email" in m for m in msgs))

    def test_resend_button_hidden_when_throttled(self):
        self.client.post(self.resend_url)  # consume the allowance
        page = self.client.get(self.sent_url)
        self.assertContains(page, "Resend temporarily limited")
        self.assertContains(page, "disabled")
        self.assertNotContains(page, 'action="' + self.resend_url + '"')

    def test_resend_button_available_when_not_throttled(self):
        page = self.client.get(self.sent_url)
        self.assertContains(page, 'action="' + self.resend_url + '"')
        self.assertContains(page, "Resend link")

    @override_settings(
        VERIFICATION_EMAIL_COOLDOWN_SECONDS=0, VERIFICATION_EMAIL_HOURLY_LIMIT=2
    )
    def test_abuse_prevention_hourly_limit_stops_flooding(self):
        # Two sends already this hour -> a third is refused even with no spacing.
        issue_verification(self.user)
        issue_verification(self.user)
        response = self.client.post(self.resend_url)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(EmailVerificationToken.objects.filter(user=self.user).count(), 2)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("limit" in m for m in msgs))


class ResolveFromEmailTests(TestCase):
    """A blank/invalid sender would make Gmail 553 - resolve_from_email guards it."""

    @override_settings(DEFAULT_FROM_EMAIL="FraudShield AI <good@example.com>")
    def test_keeps_valid_default_verbatim(self):
        self.assertEqual(resolve_from_email(), "FraudShield AI <good@example.com>")

    @override_settings(DEFAULT_FROM_EMAIL="FraudShield AI", EMAIL_HOST_USER="me@gmail.com")
    def test_derives_sender_from_host_user_when_default_invalid(self):
        self.assertEqual(resolve_from_email(), "FraudShield AI <me@gmail.com>")

    @override_settings(DEFAULT_FROM_EMAIL="", EMAIL_HOST_USER="")
    def test_returns_default_when_nothing_to_derive(self):
        self.assertEqual(resolve_from_email(), "")


# --------------------------------------------------------------------------- #
# Notification preferences tests
# --------------------------------------------------------------------------- #


class PreferencesViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("mia", "mia@example.com", VALID_PASSWORD)
        ensure_preferences(self.user)
        self.intruder = User.objects.create_user(
            "mallory", "mallory@example.com", VALID_PASSWORD
        )
        ensure_preferences(self.intruder)

    def test_login_required(self):
        # Covered by AnonymousAccessTests, but keep a direct check too.
        response = self.client.get(reverse("accounts:preferences"))
        self.assertEqual(response.status_code, 302)

    def test_get_returns_own_form(self):
        self.client.login(username="mia", password=VALID_PASSWORD)
        response = self.client.get(reverse("accounts:preferences"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Notification preferences")

    def test_post_updates_only_current_user_preferences(self):
        self.client.login(username="mia", password=VALID_PASSWORD)
        response = self.client.post(
            reverse("accounts:preferences"),
            {
                "high_risk_alerts": "on",
                "report_attach_to_email": "on",
                "summary_frequency": "daily",
            },
        )
        self.assertRedirects(response, reverse("accounts:preferences"))
        prefs = NotificationPreferences.objects.get(user=self.user)
        self.assertTrue(prefs.high_risk_alerts)
        self.assertTrue(prefs.report_attach_to_email)
        self.assertEqual(prefs.summary_frequency, "daily")

    def test_cannot_change_email_verified_via_form(self):
        """Users may not self-mark verified - only token redemption can do that."""
        self.client.login(username="mia", password=VALID_PASSWORD)
        self.client.post(
            reverse("accounts:preferences"),
            {
                "high_risk_alerts": "on",
                "summary_frequency": "weekly",
                # Try to inject the protected field:
                "email_verified": "on",
            },
        )
        prefs = NotificationPreferences.objects.get(user=self.user)
        self.assertFalse(prefs.email_verified)

    def test_invalid_frequency_is_rejected(self):
        self.client.login(username="mia", password=VALID_PASSWORD)
        response = self.client.post(
            reverse("accounts:preferences"),
            {"high_risk_alerts": "on", "summary_frequency": "hourly"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select a valid choice")

    def test_one_user_cannot_edit_anothers_preferences(self):
        """Preferences are OneToOne per user; there's no path to target another user."""
        self.client.login(username="mia", password=VALID_PASSWORD)
        # Even if we POST, the view uses request.user, so mallory's row is untouched.
        self.client.post(
            reverse("accounts:preferences"),
            {"high_risk_alerts": "on", "summary_frequency": "daily"},
        )
        mallory_prefs = NotificationPreferences.objects.get(user=self.intruder)
        self.assertEqual(mallory_prefs.summary_frequency, "off")


class CreateAdminCommandTests(TestCase):
    """Tests for the interactive create_admin management command.

    input() and getpass.getpass() are patched so the command can be driven
    without a TTY. The password value itself is never asserted or printed.
    """

    COMMAND = "create_admin"

    @mock.patch("accounts.management.commands.create_admin.getpass.getpass",
                side_effect=[VALID_PASSWORD, VALID_PASSWORD])
    @mock.patch("builtins.input", side_effect=["rootadmin", "root@example.com"])
    def test_creates_superuser_with_flags_and_hashed_password(self, _input, _getpass):
        out = io.StringIO()
        call_command(self.COMMAND, stdout=out)

        admin = User.objects.get(username="rootadmin")
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_active)
        self.assertEqual(admin.email, "root@example.com")
        # Password is usable and stored hashed (not in plaintext).
        self.assertTrue(admin.check_password(VALID_PASSWORD))
        self.assertNotEqual(admin.password, VALID_PASSWORD)
        self.assertTrue(admin.password.startswith("pbkdf2_"))
        # The password never leaks into the command output.
        self.assertNotIn(VALID_PASSWORD, out.getvalue())

    @mock.patch("accounts.management.commands.create_admin.getpass.getpass")
    @mock.patch("builtins.input", side_effect=["existinguser"])
    def test_existing_username_is_left_untouched(self, _input, getpass_mock):
        existing = User.objects.create_user(
            username="existinguser",
            email="old@example.com",
            password="An0ther!Valid-77",
        )
        original_hash = existing.password

        call_command(self.COMMAND)

        # Command stopped before ever prompting for a password.
        getpass_mock.assert_not_called()
        existing.refresh_from_db()
        self.assertEqual(existing.password, original_hash)  # password unchanged
        self.assertFalse(existing.is_superuser)  # flags unchanged
        self.assertEqual(User.objects.filter(username="existinguser").count(), 1)

    @mock.patch("accounts.management.commands.create_admin.getpass.getpass",
                side_effect=["short", VALID_PASSWORD, VALID_PASSWORD])
    @mock.patch("builtins.input", side_effect=["pwdadmin", ""])
    def test_weak_password_rejected_then_valid_password_accepted(
        self, _input, _getpass
    ):
        # 'short' fails the MinimumLength validator, so the loop re-prompts and
        # the subsequent valid password + matching confirmation is accepted.
        call_command(self.COMMAND)

        admin = User.objects.get(username="pwdadmin")
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.check_password(VALID_PASSWORD))

    @mock.patch("accounts.management.commands.create_admin.getpass.getpass",
                side_effect=[VALID_PASSWORD, "mismatch9!Diff-1"])
    @mock.patch("builtins.input", side_effect=["nomatch", ""])
    def test_password_confirmation_mismatch_loops_until_match(
        self, _input, getpass_mock
    ):
        # Give a mismatched confirmation, then a matching pair; the command must
        # keep looping and ultimately create using the valid (matching) entry.
        getpass_mock.side_effect = [
            VALID_PASSWORD, "different!Value-2",   # mismatch -> retry
            VALID_PASSWORD, VALID_PASSWORD,         # match -> accept
        ]
        call_command(self.COMMAND)
        self.assertTrue(User.objects.get(username="nomatch").check_password(VALID_PASSWORD))

    @mock.patch("builtins.input", side_effect=[""])
    def test_blank_username_raises(self, _input):
        with self.assertRaises(CommandError):
            call_command(self.COMMAND)
