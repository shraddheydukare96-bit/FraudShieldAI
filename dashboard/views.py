"""Dashboard views with real, database-backed statistics and chart data.

Every figure is derived from the signed-in user's actual Detection records.
There are no hardcoded or placeholder numbers.
"""
from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.views.generic import TemplateView

from detection.models import Detection
from reports.models import Report

TREND_DAYS = 30


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        detections = Detection.objects.filter(user=user)

        total = detections.count()
        safe = detections.filter(classification="legitimate").count()
        suspicious = detections.filter(classification="inconclusive").count()
        high_risk = detections.filter(classification="fraud").count()

        context.update(
            {
                "total_users": User.objects.count(),
                "total_analyses": total,
                "safe_count": safe,
                "suspicious_count": suspicious,
                "high_risk_count": high_risk,
                "report_count": Report.objects.filter(user=user).count(),
                "recent_detections": detections.order_by("-created_at", "-pk")[:5],
                "has_data": total > 0,
            }
        )

        # --- Chart data (all from real rows) ---
        # Analyses by channel.
        channel_counts = {label: 0 for _, label in Detection.Channel.choices}
        for row in detections.values_list("channel", flat=True):
            label = Detection.Channel(row).label if row in dict(Detection.Channel.choices) else row
            channel_counts[label] = channel_counts.get(label, 0) + 1
        context["channel_labels"] = list(channel_counts.keys())
        context["channel_data"] = list(channel_counts.values())

        # Risk distribution.
        context["risk_labels"] = ["Safe", "Suspicious", "High-risk"]
        context["risk_data"] = [safe, suspicious, high_risk]

        # Analyses over the last N days.
        since = timezone.localdate() - timezone.timedelta(days=TREND_DAYS - 1)
        daily_counts = []
        day_labels = []
        for offset in range(TREND_DAYS):
            day = since + timezone.timedelta(days=offset)
            day_labels.append(day.strftime("%b %d"))
            daily_counts.append(
                detections.filter(created_at__date=day).count()
            )
        context["trend_labels"] = day_labels
        context["trend_data"] = daily_counts

        # Single JSON payload consumed by Chart.js in the template.
        context["charts"] = {
            "channel": {"labels": context["channel_labels"], "data": context["channel_data"]},
            "risk": {
                "labels": context["risk_labels"],
                "data": context["risk_data"],
                "colors": ["#198754", "#d39e00", "#dc3545"],
            },
            "trend": {"labels": day_labels, "data": daily_counts},
        }

        return context
