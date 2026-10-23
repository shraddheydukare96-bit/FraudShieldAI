"""Django admin registration for the about app (team members + contact messages)."""
from django.contrib import admin
from django.utils.html import format_html

from .models import ContactMessage, TeamMember


@admin.register(TeamMember)
class TeamMemberAdmin(admin.ModelAdmin):
    list_display = ("photo_thumb", "name", "role", "display_order", "is_active")
    # Editable straight from the list page so the owner can reorder members and
    # toggle visibility without opening each record.
    list_editable = ("display_order", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name", "role", "description")
    ordering = ("display_order", "name")
    empty_value_display = "—"

    fieldsets = (
        ("Identity", {"fields": ("name", "role", "description")}),
        ("Photo", {"fields": ("photo",), "description": "Square portrait recommended."}),
        (
            "Links (optional)",
            {"fields": ("github_url", "linkedin_url"), "classes": ("collapse",)},
        ),
        ("Display", {"fields": ("display_order", "is_active")}),
    )

    @admin.display(description="Photo")
    def photo_thumb(self, obj):
        """Small circular preview so the list is easy to scan."""
        if obj.photo:
            return format_html(
                '<img src="{}" alt="" '
                'style="width:36px;height:36px;border-radius:50%;object-fit:cover;">',
                obj.photo.url,
            )
        return self.empty_value_display


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "email",
        "subject",
        "status_badge",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("name", "email", "subject")
    ordering = ("-created_at",)
    # Newest first on the changelist and a compact, readable detail layout.
    date_hierarchy = "created_at"
    # The sender's content is fixed once submitted; only the status is triaged.
    readonly_fields = ("name", "email", "subject", "message", "user", "created_at")
    fields = (
        "status",
        ("name", "email"),
        "subject",
        "message",
        ("user", "created_at"),
    )

    def has_add_permission(self, request):
        # Contact messages originate from the public form only.
        return False

    @admin.display(description="Status", ordering="status")
    def status_badge(self, obj):
        colour = {
            ContactMessage.Status.NEW: "warning",
            ContactMessage.Status.READ: "info",
            ContactMessage.Status.REPLIED: "success",
        }.get(obj.status, "secondary")
        return format_html(
            '<span class="badge text-bg-{}">{}</span>', colour, obj.get_status_display()
        )
