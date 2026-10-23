"""Django admin registrations for the accounts app."""
from django.contrib import admin

from .models import EmailVerificationToken, NotificationPreferences


@admin.register(NotificationPreferences)
class NotificationPreferencesAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "email_verified",
        "high_risk_alerts",
        "summary_frequency",
        "updated_at",
    )
    list_filter = ("email_verified", "high_risk_alerts", "summary_frequency")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("created_at", "updated_at", "verified_at", "last_summary_sent_at")
    autocomplete_fields = ("user",)


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "created_at", "expires_at", "used_at")
    list_filter = ("used_at", "expires_at")
    search_fields = ("user__username", "user__email", "key")
    readonly_fields = ("key", "created_at", "expires_at", "used_at")
    autocomplete_fields = ("user",)

    def has_add_permission(self, request):
        # Tokens are issued by the app; admins should not create them by hand.
        return False
