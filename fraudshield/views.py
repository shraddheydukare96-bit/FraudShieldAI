"""Project-level views for FraudShield AI."""
from django.views.generic import TemplateView


class HomeView(TemplateView):
    """Public landing / index page."""

    template_name = "home.html"
