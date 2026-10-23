"""Detection views.

Two responsibilities are kept apart:
  * Web presentation here (forms, templates, permissions).
  * All ML + persistence logic in :mod:`detection.services` and the pure
    :mod:`detection.ml` package.

All queries are scoped to the signed-in user so each user can only see their own
analysis records.
"""
import json

from django.db.models import Q
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, ListView

from . import services
from .forms import AnalysisForm, HistoryFilterForm
from .models import Detection


class DetectionListView(LoginRequiredMixin, ListView):
    template_name = "detection/list.html"
    context_object_name = "detections"
    paginate_by = 25

    def get_queryset(self):
        # Always scoped to the signed-in user -> real data, per-user isolation.
        qs = Detection.objects.filter(user=self.request.user)
        self.filter_form = HistoryFilterForm(self.request.GET or None)
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            if data.get("q"):
                qs = qs.filter(Q(content__icontains=data["q"]) | Q(classification__icontains=data["q"]))
            if data.get("channel"):
                qs = qs.filter(channel=data["channel"])
            if data.get("classification"):
                qs = qs.filter(classification=data["classification"])
            if data.get("date_from"):
                qs = qs.filter(created_at__date__gte=data["date_from"])
            if data.get("date_to"):
                qs = qs.filter(created_at__date__lte=data["date_to"])
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Ensure the form exists even when the queryset was short-circuited.
        if not hasattr(self, "filter_form"):
            self.filter_form = HistoryFilterForm(self.request.GET or None)
        context["filter_form"] = self.filter_form
        # Echo current query params so pagination preserves filters.
        params = self.request.GET.copy()
        params.pop("page", None)
        context["query_string"] = params.urlencode()
        context["has_filters"] = bool(params)
        return context


class DetectionDetailView(LoginRequiredMixin, DetailView):
    template_name = "detection/detail.html"
    context_object_name = "detection"

    def get_queryset(self):
        # Filtering by owner makes another user's record return HTTP 404.
        return Detection.objects.filter(user=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        detection = self.object

        # Reuse the report created at analysis time (fallback: create one now)
        # so the Download/Send buttons always target the same Report record.
        from reports.pdf import get_or_create_report
        from reports import email_reports

        report = get_or_create_report(detection, self.request.user)
        context["report"] = report
        context["email_state"] = (
            email_reports.email_state(self.request.user, report) if report else None
        )

        # Data for the on-page pie charts (real stored values only; the PDF
        # renders the same figures through reports.pdf chart helpers).
        percent = detection.risk_percent
        context["risk_percent"] = percent
        context["risk_pie_json"] = json.dumps(
            [percent, 100 - percent] if percent is not None else []
        )
        own = Detection.objects.filter(user=self.request.user)
        history_counts = {
            "safe": own.filter(classification=Detection.Classification.LEGITIMATE).count(),
            "suspicious": own.filter(classification=Detection.Classification.INCONCLUSIVE).count(),
            "high_risk": own.filter(classification=Detection.Classification.FRAUD).count(),
        }
        history_counts["total"] = (
            history_counts["safe"] + history_counts["suspicious"] + history_counts["high_risk"]
        )
        context["history_counts"] = history_counts
        context["history_counts_json"] = json.dumps(history_counts)
        return context


class DetectionAnalysisView(LoginRequiredMixin, FormView):
    """Run an analysis and display the honest result on the same page."""

    template_name = "detection/analyze.html"
    form_class = AnalysisForm
    success_url = reverse_lazy("detection:analyze")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["model_available"] = services.text_model_available()
        return context

    def form_valid(self, form):
        outcome = services.run_analysis(
            user=self.request.user,
            channel=form.cleaned_data["channel"],
            content=form.cleaned_data["content"],
        )
        if outcome.ok:
            self.result = outcome.result
            self.detection_id = outcome.detection.pk
            return super().form_valid(form)

        # Model unavailable or invalid content: re-render with an honest message,
        # without fabricating a prediction.
        if outcome.message:
            form.add_error(None, outcome.message)
        for error in outcome.errors:
            form.add_error("content", error)
        return self.render_to_response(self.get_context_data(form=form))

    def get_success_url(self):
        # Show the fresh result by linking to its detail page.
        return reverse_lazy("detection:detail", args=[self.detection_id])
