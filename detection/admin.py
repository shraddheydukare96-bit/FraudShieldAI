"""Django admin registration for the detection app."""
from django.contrib import admin

from .models import Detection


@admin.register(Detection)
class DetectionAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "channel", "is_fraud", "confidence", "created_at")
    list_filter = ("channel", "is_fraud", "created_at")
    search_fields = ("content", "user__username")
    readonly_fields = ("created_at",)
    autocomplete_fields = ("user",)
