"""Django admin registration for the reports app."""
from django.contrib import admin

from .models import DeliveryAttempt, Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "title", "detection", "created_at")
    list_filter = ("created_at",)
    search_fields = ("title", "summary", "user__username")
    readonly_fields = ("created_at",)
    autocomplete_fields = ("user",)


@admin.register(DeliveryAttempt)
class DeliveryAttemptAdmin(admin.ModelAdmin):
    """Read-only audit of report email deliveries (created by the app only)."""

    list_display = ("id", "report", "user", "recipient", "status", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("recipient", "user__username", "report__title")
    readonly_fields = tuple(
        field.name for field in DeliveryAttempt._meta.get_fields()
        if hasattr(field, "name")
    )

    def has_add_permission(self, request):
        # Attempts are written by the send view; admins must not fabricate them.
        return False
