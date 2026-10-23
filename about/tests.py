"""Tests for the about app (TeamMember model, admin and About page team grid)."""
import io
import shutil
import tempfile

from django.contrib import admin as django_admin
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .admin import ContactMessageAdmin, TeamMemberAdmin
from .models import ContactMessage, TeamMember


def _png_bytes():
    """Generate a tiny valid PNG in memory using Pillow."""
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (34, 211, 238)).save(buf, format="PNG")
    return buf.getvalue()


def _photo(name="photo.png"):
    return SimpleUploadedFile(name, _png_bytes(), content_type="image/png")


# Dedicated, throwaway media directory for uploaded-photo tests.
_MEDIA_TMP = tempfile.mkdtemp(prefix="fs-about-test-")


class TeamMemberModelTests(TestCase):
    def test_str_combines_name_and_role(self):
        member = TeamMember.objects.create(name="Test Lead", role="Project Lead")
        self.assertEqual(str(member), "Test Lead - Project Lead")

    def test_default_ordering_is_display_order_then_name(self):
        # Deliberately created out of order.
        c = TeamMember.objects.create(name="Carol", role="R", display_order=3)
        a = TeamMember.objects.create(name="Alice", role="R", display_order=1)
        b2 = TeamMember.objects.create(name="Bob", role="R", display_order=2)
        a2 = TeamMember.objects.create(name="Aaron", role="R", display_order=1)
        self.assertEqual(
            list(TeamMember.objects.all()), [a2, a, b2, c]
        )  # order 1 (Aaron, Alice), 2, 3

    def test_photo_upload_uses_team_path(self):
        member = TeamMember.objects.create(name="Photo Person", role="R", photo=_photo())
        self.assertTrue(member.photo.name.startswith("team/"))

    def test_invalid_photo_extension_fails_validation(self):
        member = TeamMember(
            name="Bad File", role="R",
            photo=SimpleUploadedFile("anim.gif", b"fake", content_type="image/gif"),
        )
        with self.assertRaises(Exception):
            member.full_clean()


class TeamMemberAdminTests(TestCase):
    def test_model_is_registered(self):
        self.assertIn(TeamMember, django_admin.site._registry)

    def test_admin_allows_reordering_and_is_active_inline(self):
        model_admin = django_admin.site._registry[TeamMember]
        self.assertIsInstance(model_admin, TeamMemberAdmin)
        self.assertIn("display_order", model_admin.list_editable)
        self.assertIn("is_active", model_admin.list_editable)


@override_settings(MEDIA_ROOT=_MEDIA_TMP)
class AboutPageTeamTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(_MEDIA_TMP, ignore_errors=True)

    def setUp(self):
        self.url = reverse("about:about")

    def _cards(self, response):
        return response.content.decode().count("fs-team-card")

    def test_about_page_public_and_ok(self):
        self.assertEqual(self.client.get(self.url).status_code, 200)

    def test_empty_state_when_no_members(self):
        response = self.client.get(self.url)
        self.assertContains(response, "Team profiles are coming soon")
        self.assertEqual(self._cards(response), 0)

    def test_only_active_members_render(self):
        TeamMember.objects.create(name="Shown", role="AI/ML Developer", is_active=True)
        TeamMember.objects.create(name="Hidden", role="R", is_active=False)
        response = self.client.get(self.url)
        self.assertContains(response, "Shown")
        self.assertNotContains(response, "Hidden")
        self.assertEqual(self._cards(response), 1)

    def test_four_cards_render_in_grid(self):
        for i in range(4):
            TeamMember.objects.create(name=f"Member {i}", role="R", display_order=i)
        response = self.client.get(self.url)
        self.assertEqual(self._cards(response), 4)
        # Responsive grid classes are present.
        self.assertIn("row-cols-xl-4", response.content.decode())
        self.assertIn("row-cols-md-2", response.content.decode())

    def test_headings_and_subtitle_present(self):
        response = self.client.get(self.url)
        self.assertContains(response, "Meet Our Team")
        self.assertContains(response, "The minds behind FraudShield AI")

    def test_placeholder_used_without_photo(self):
        TeamMember.objects.create(name="No Photo", role="R")
        response = self.client.get(self.url)
        self.assertContains(response, "img/team-placeholder.svg")

    def test_uploaded_photo_is_displayed(self):
        member = TeamMember.objects.create(name="With Photo", role="R", photo=_photo())
        response = self.client.get(self.url)
        html = response.content.decode()
        self.assertIn(member.photo.url, html)
        self.assertNotIn("img/team-placeholder.svg", html)

    def test_optional_social_links(self):
        member = TeamMember.objects.create(
            name="Linked", role="R",
            github_url="https://github.com/example-one",
            linkedin_url="https://linkedin.com/in/example-one",
        )
        html = self.client.get(self.url).content.decode()
        self.assertIn("https://github.com/example-one", html)
        self.assertIn("https://linkedin.com/in/example-one", html)
        # External links open safely.
        self.assertIn("noopener", html)

    def test_existing_about_content_preserved(self):
        response = self.client.get(self.url)
        self.assertContains(response, "About FraudShield AI")
        self.assertContains(response, "Our Mission")


# --------------------------------------------------------------------------- #
# Contact Us functionality
# --------------------------------------------------------------------------- #


class ContactMessageModelTests(TestCase):
    def test_str_shows_sender_and_subject(self):
        msg = ContactMessage.objects.create(
            name="Ada", email="ada@example.com", subject="Hi", message="There"
        )
        self.assertEqual(str(msg), "Ada <ada@example.com> - Hi")

    def test_default_status_is_new(self):
        msg = ContactMessage.objects.create(
            name="Ada", email="ada@example.com", subject="Hi", message="There"
        )
        self.assertEqual(msg.status, ContactMessage.Status.NEW)

    def test_created_at_is_set_automatically(self):
        msg = ContactMessage.objects.create(
            name="Ada", email="ada@example.com", subject="Hi", message="There"
        )
        self.assertIsNotNone(msg.created_at)


class ContactFormSubmissionTests(TestCase):
    def setUp(self):
        self.url = reverse("about:contact")
        self.data = {
            "name": "Grace",
            "email": "grace@example.com",
            "subject": "Question",
            "message": "How do I verify my email?",
        }

    def test_valid_submission_saves_and_redirects(self):
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 302)
        msg = ContactMessage.objects.get()
        self.assertEqual(msg.name, "Grace")
        self.assertEqual(msg.email, "grace@example.com")
        self.assertEqual(msg.subject, "Question")
        self.assertEqual(msg.message, "How do I verify my email?")
        self.assertEqual(msg.status, ContactMessage.Status.NEW)
        self.assertIsNone(msg.user)  # anonymous submitter
        # Following the redirect shows the success banner.
        page = self.client.get(self.url)
        self.assertContains(page, "Thanks for reaching out")

    def test_invalid_submission_does_not_save_or_claim_success(self):
        bad = dict(self.data, message="", email="not-an-email")
        response = self.client.post(self.url, bad)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ContactMessage.objects.count(), 0)
        msgs = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertFalse(any("Thanks for reaching out" in m for m in msgs))
        # Field-level validation messages are shown.
        self.assertContains(response, "Enter a valid email address")
        self.assertContains(response, "This field is required")

    def test_authenticated_submission_links_message_to_requester(self):
        user = User.objects.create_user("mem", "mem@example.com", "Str0ng!Pass-9")
        self.client.force_login(user)
        self.client.post(self.url, self.data)
        msg = ContactMessage.objects.get()
        self.assertEqual(msg.user, user)

    def test_manipulated_fields_are_ignored(self):
        victim = User.objects.create_user("victim", "v@example.com", "Str0ng!Pass-9")
        payload = dict(
            self.data, status="replied", user=victim.pk, id=999, created_at="2000-01-01"
        )
        self.client.post(self.url, payload)
        msg = ContactMessage.objects.get()
        # None of the protected attributes can be set through POST.
        self.assertEqual(msg.status, ContactMessage.Status.NEW)
        self.assertIsNone(msg.user)
        self.assertNotEqual(msg.pk, 999)


class ContactAdminTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            "root", "root@example.com", "Root!Passw0rd-9"
        )
        self.message = ContactMessage.objects.create(
            name="Ops", email="ops@example.com", subject="Billing",
            message="Full message body that must be visible to admins.",
        )

    def test_model_is_registered(self):
        self.assertIn(ContactMessage, django_admin.site._registry)
        self.assertIsInstance(
            django_admin.site._registry[ContactMessage], ContactMessageAdmin
        )

    def test_admin_configuration(self):
        model_admin = django_admin.site._registry[ContactMessage]
        for field in ("name", "email", "subject", "created_at"):
            self.assertIn(field, model_admin.list_display)
        self.assertEqual(
            set(model_admin.search_fields), {"name", "email", "subject"}
        )
        self.assertIn("status", model_admin.list_filter)
        self.assertIn("created_at", model_admin.list_filter)
        # created_at is read-only, but status remains editable.
        self.assertIn("created_at", model_admin.readonly_fields)
        self.assertNotIn("status", model_admin.readonly_fields)

    def test_submitted_message_appears_in_admin_changelist(self):
        self.client.force_login(self.superuser)
        response = self.client.get(reverse("admin:about_contactmessage_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Billing")
        self.assertContains(response, "ops@example.com")

    def test_admin_can_view_full_message_and_update_status(self):
        self.client.force_login(self.superuser)
        change_url = reverse("admin:about_contactmessage_change", args=[self.message.pk])
        # The full message body is rendered on the change page.
        page = self.client.get(change_url)
        self.assertContains(page, "Full message body that must be visible to admins.")
        # Posting a new status persists (content is read-only and unchanged).
        response = self.client.post(
            change_url, {"status": ContactMessage.Status.REPLIED}
        )
        self.assertEqual(response.status_code, 302)
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ContactMessage.Status.REPLIED)
        self.assertEqual(self.message.subject, "Billing")  # untouched

    def test_no_manual_add_from_admin(self):
        self.client.force_login(self.superuser)
        add_url = reverse("admin:about_contactmessage_add")
        self.assertEqual(self.client.get(add_url).status_code, 403)
