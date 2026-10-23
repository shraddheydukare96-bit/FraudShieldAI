"""Data models for the about app: the "Meet Our Team" section and Contact messages."""
from django.conf import settings
from django.core.validators import FileExtensionValidator
from django.db import models
from django.utils.text import slugify


def _team_upload_to(instance, filename):
    """Store team photos under ``team/`` keeping a predictable, flat layout."""
    # ``instance.pk`` may be None on first save; fall back to a slug of the name.
    identifier = instance.pk if instance.pk else (slugify(instance.name) or "member")[:40]
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "jpg"
    return f"team/{identifier}.{ext}"


class TeamMember(models.Model):
    """A single person shown in the About page "Meet Our Team" grid.

    Managed entirely through Django Admin. No records are seeded with invented
    real names/photos - the site owner adds the four members themselves.
    """

    name = models.CharField(max_length=120)
    role = models.CharField(
        max_length=120,
        help_text="Project role, e.g. AI/ML Developer.",
    )
    description = models.TextField(
        blank=True,
        help_text="Short bio shown under the name and role.",
    )
    photo = models.ImageField(
        upload_to=_team_upload_to,
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=["jpg", "jpeg", "png", "webp"])],
        help_text="Square portrait recommended. Leave empty to show a placeholder.",
    )
    github_url = models.URLField(
        "GitHub URL",
        max_length=200,
        blank=True,
        help_text="Optional. Full https link to a GitHub profile.",
    )
    linkedin_url = models.URLField(
        "LinkedIn URL",
        max_length=200,
        blank=True,
        help_text="Optional. Full https link to a LinkedIn profile.",
    )
    display_order = models.PositiveIntegerField(
        default=0,
        help_text="Lower numbers appear first. Use the list view to reorder.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Only active members are shown on the About page.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_order", "name"]
        verbose_name = "team member"
        verbose_name_plural = "team members"

    def __str__(self):
        return f"{self.name} - {self.role}"


class ContactMessage(models.Model):
    """A message submitted through the public Contact Us form.

    Persisted so administrators can read and triage enquiries in Django Admin.
    The ``user`` link is optional (contact is public) and is set ONLY from the
    authenticated request - never from submitted data - so one person cannot
    attach their message to another user's account.
    """

    class Status(models.TextChoices):
        NEW = "new", "New"
        READ = "read", "Read"
        REPLIED = "replied", "Replied"

    name = models.CharField(max_length=120)
    email = models.EmailField(max_length=254, db_index=True)
    subject = models.CharField(max_length=200)
    message = models.TextField()
    status = models.CharField(
        max_length=8,
        choices=Status.choices,
        default=Status.NEW,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="contact_messages",
        help_text="Set automatically for signed-in submitters. Never editable by the sender.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "contact message"
        verbose_name_plural = "contact messages"
        indexes = [
            models.Index(fields=["-created_at"], name="contact_created_idx"),
            models.Index(fields=["status", "-created_at"], name="contact_status_idx"),
        ]

    def __str__(self):
        return f"{self.name} <{self.email}> - {self.subject}"
