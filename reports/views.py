"""Reports views. All queries are scoped to the signed-in user."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from django.views.generic import DetailView, ListView

from . import email_reports
from .models import Report
from .pdf import build_report_pdf


class ReportListView(LoginRequiredMixin, ListView):
    template_name = "reports/list.html"
    context_object_name = "reports"
    paginate_by = 25

    def get_queryset(self):
        return Report.objects.filter(user=self.request.user).select_related("detection")


class ReportDetailView(LoginRequiredMixin, DetailView):
    template_name = "reports/detail.html"
    context_object_name = "report"

    def get_queryset(self):
        # Owner-filtered queryset -> other users' reports return HTTP 404.
        return Report.objects.filter(user=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["email_state"] = email_reports.email_state(
            self.request.user, self.object
        )
        return context


class ReportPDFView(LoginRequiredMixin, View):
    """Stream a PDF report. Only the owning user can download their report."""

    def get(self, request, pk):
        report = Report.objects.filter(user=request.user, pk=pk).first()
        if report is None:
            # Honest, permission-preserving 404 for missing/foreign reports.
            from django.http import Http404

            raise Http404("Report not found.")

        pdf_bytes = build_report_pdf(report)
        filename = f"fraudshield-report-{report.pk}.pdf"
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class ReportSendEmailView(LoginRequiredMixin, View):
    """Email the generated PDF report to the signed-in user's registered address.

    POST-only (CSRF-protected), ownership-checked, and honest: success is only
    reported when the email backend accepted the message.
    """

    def post(self, request, pk):
        # Owner-filtered lookup -> another user's report is a 404, never sent.
        report = get_object_or_404(Report, pk=pk, user=request.user)
        status, message = email_reports.send_report_to_registered_email(
            request.user, report
        )
        if status == email_reports.SendStatus.OK:
            messages.success(request, message)
        elif status in (email_reports.SendStatus.COOLDOWN,):
            messages.warning(request, message)
        else:
            messages.error(request, message)
        next_url = request.POST.get("next", "")
        # Only same-site relative paths are honoured (no open redirects).
        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect("reports:detail", pk=report.pk)

    def get(self, request, pk):
        # Sending must never happen via GET (prefetch/click bots, CSRF replay).
        return redirect("reports:detail", pk=pk)
