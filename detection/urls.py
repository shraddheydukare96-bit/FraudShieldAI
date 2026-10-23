"""URL configuration for the detection app."""
from django.urls import path

from .views import DetectionAnalysisView, DetectionDetailView, DetectionListView

app_name = "detection"

urlpatterns = [
    path("", DetectionListView.as_view(), name="index"),
    path("analyze/", DetectionAnalysisView.as_view(), name="analyze"),
    path("<int:pk>/", DetectionDetailView.as_view(), name="detail"),
]
