"""URL configuration for the about app."""
from django.urls import path

from .views import AboutView, ContactView

app_name = "about"

urlpatterns = [
    path("", AboutView.as_view(), name="about"),
    path("contact/", ContactView.as_view(), name="contact"),
]
