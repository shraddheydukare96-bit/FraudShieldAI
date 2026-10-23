"""URL configuration for the reports app."""
from django.urls import path

from .views import ReportDetailView, ReportListView, ReportPDFView, ReportSendEmailView

app_name = "reports"

urlpatterns = [
    path("", ReportListView.as_view(), name="index"),
    path("<int:pk>/", ReportDetailView.as_view(), name="detail"),
    path("<int:pk>/pdf/", ReportPDFView.as_view(), name="pdf"),
    path("<int:pk>/email/", ReportSendEmailView.as_view(), name="send_email"),
]
