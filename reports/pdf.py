"""PDF report generation using ReportLab + matplotlib.

All values come from the stored Detection/Report records - nothing is invented.
The report states whether the score is a model probability or a rule heuristic so
the reader is never misled about confidence. Charts are rendered in memory and
embedded directly in the PDF bytes (no temporary files on disk).
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

import matplotlib

matplotlib.use("Agg")  # headless rendering; must precede pyplot import
import matplotlib.pyplot as plt  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    HRFlowable,
    Image,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ACCENT = colors.HexColor("#22d3ee")
NAVY = colors.HexColor("#0f1c3f")

# Shared palette so the HTML page and the PDF show identical colours.
RISK_COLORS = {
    "safe": "#198754",
    "suspicious": "#d39e00",
    "high_risk": "#dc3545",
    "remaining": "#d5dde8",
}


def _figure_to_png_bytes(fig) -> bytes:
    """Render a matplotlib figure to PNG bytes and release the figure."""
    buf = io.BytesIO()
    try:
        fig.savefig(buf, format="png", dpi=160, bbox_inches="tight", facecolor="white")
    finally:
        plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def build_risk_pie_bytes(risk_percent) -> bytes | None:
    """Pie for ONE analysis: risk percentage vs the remaining percentage.

    Returns ``None`` when no valid percentage exists (never draws invented
    data).
    """
    if risk_percent is None:
        return None
    remaining = 100 - risk_percent
    fig, ax = plt.subplots(figsize=(3.6, 2.7))
    ax.pie(
        [risk_percent, remaining],
        colors=[RISK_COLORS["high_risk"], RISK_COLORS["remaining"]],
        startangle=90,
        counterclock=False,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 8 else "",
    )
    ax.text(
        0.0, 1.32, f"This analysis: {risk_percent}% risk vs {remaining}% remaining",
        ha="center", fontsize=8.5, color="#33465e",
    )
    ax.set_title("Risk score for this single analysis", fontsize=9.5, pad=26)
    fig.tight_layout()
    return _figure_to_png_bytes(fig)


def build_history_pie_bytes(counts: dict) -> bytes | None:
    """Pie of the owner's real safe/suspicious/high-risk detection counts.

    ``counts`` maps label -> number of stored detections. Returns ``None``
    when there is no data to show.
    """
    labels = ["SAFE", "SUSPICIOUS", "HIGH RISK"]
    keys = ["safe", "suspicious", "high_risk"]
    values = [int(counts.get(k) or 0) for k in keys]
    if sum(values) == 0:
        return None
    fig, ax = plt.subplots(figsize=(3.6, 2.7))
    ax.pie(
        values,
        labels=[f"{lbl}\n({v})" for lbl, v in zip(labels, values)],
        colors=[RISK_COLORS[k] for k in keys],
        startangle=90,
        counterclock=False,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 8 else "",
        textprops={"fontsize": 7.5, "color": "#33465e"},
    )
    ax.set_title("My detection history (all analyses)", fontsize=9.5)
    fig.tight_layout()
    return _figure_to_png_bytes(fig)


def _classification_color(classification: str) -> colors.Color:
    return {
        "fraud": colors.HexColor("#dc3545"),
        "inconclusive": colors.HexColor("#d39e00"),
        "legitimate": colors.HexColor("#198754"),
    }.get(classification, colors.HexColor("#6c757d"))


def get_or_create_report(detection, user):
    """Return the ``Report`` bound to ``detection`` (creating one if missing).

    ``detection.services.run_analysis`` already creates a report per analysis;
    this helper is the single fallback used by views so we never duplicate the
    report system. Only the detection's owner may obtain a report.
    """
    from .models import Report

    if detection.user_id != getattr(user, "id", None):
        return None
    report = Report.objects.filter(detection=detection, user=user).first()
    if report is not None:
        return report
    return Report.objects.create(
        user=user,
        detection=detection,
        title=(
            f"{detection.get_channel_display()} analysis #{detection.pk}"
            f" - {detection.risk_label}"
        ),
    )


def build_report_pdf(report) -> bytes:
    """Render a ``Report`` (and its linked ``Detection``) to PDF bytes."""
    detection = report.detection
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=report.title or "FraudShield AI Report",
        author="FraudShield AI",
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "FSTitle", parent=styles["Title"], textColor=NAVY, spaceAfter=6
    )
    subtitle = ParagraphStyle(
        "FSSub", parent=styles["Normal"], textColor=colors.HexColor("#5b6b82")
    )
    heading = ParagraphStyle(
        "FSH", parent=styles["Heading2"], textColor=NAVY, spaceBefore=10
    )

    story = []
    story.append(Paragraph("FraudShield AI - Analysis Report", title_style))
    story.append(Paragraph(report.title, subtitle))
    story.append(HRFlowable(width="100%", color=ACCENT, thickness=1.5, spaceAfter=10))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_percent = detection.risk_percent if detection else None
    if detection:
        analysis_type = detection.get_channel_display()
        timestamp = detection.created_at.strftime("%Y-%m-%d %H:%M UTC")
        classification = detection.classification or ("fraud" if detection.is_fraud else "legitimate")
        risk_score = detection.risk_score
        signals = detection.signals or []
        recommendations = detection.recommendations or []
        content = detection.content
    else:
        analysis_type = "General report"
        timestamp = report.created_at.strftime("%Y-%m-%d %H:%M UTC")
        classification = "Unknown"
        risk_score = None
        score_kind = "-"
        signals = []
        recommendations = [report.summary] if report.summary else []
        content = "-"

    # Summary table.
    score_text = (
        f"{risk_score:.3f} ({'model probability' if detection and detection.score_kind == 'probability' else 'rule-based heuristic'})"
        if risk_score is not None
        else "N/A"
    )
    percent_text = (
        f"{risk_percent}%" if risk_percent is not None
        else "Unavailable (no valid score stored)"
    )
    rows = [
        ["Report ID", f"FSR-{report.pk:05d}"],
        ["Analysis type", analysis_type],
        ["Analyzed at", timestamp],
        ["Report generated", generated],
        ["Classification", (detection.risk_label if detection else classification.capitalize())],
        ["Risk percentage", percent_text],
        ["Raw risk score", score_text],
    ]
    table = Table(rows, colWidths=[45 * mm, 115 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef4fb")),
                ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c9d5e3")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            f"Verdict: {detection.risk_label if detection else classification.upper()}",
            ParagraphStyle("FSV", parent=styles["Normal"], textColor=_classification_color(classification), fontName="Helvetica-Bold", spaceBefore=4),
        )
    )
    story.append(
        Paragraph(
            "Note: the risk percentage measures this single analysis only. It is "
            "separate from model confidence, which is shown as the raw score above.",
            subtitle,
        )
    )

    # Charts (rendered in memory, embedded in the PDF itself).
    risk_png = build_risk_pie_bytes(risk_percent)
    history_png = None
    if detection is not None:
        from detection.models import Detection

        own = Detection.objects.filter(user=report.user)
        counts = {
            "safe": own.filter(classification=Detection.Classification.LEGITIMATE).count(),
            "suspicious": own.filter(classification=Detection.Classification.INCONCLUSIVE).count(),
            "high_risk": own.filter(classification=Detection.Classification.FRAUD).count(),
        }
        history_png = build_history_pie_bytes(counts)
    if risk_png or history_png:
        story.append(Paragraph("Risk visualisation", heading))
        images = []
        if risk_png:
            images.append(Image(io.BytesIO(risk_png), width=78 * mm, height=59 * mm))
        if history_png:
            images.append(Image(io.BytesIO(history_png), width=78 * mm, height=59 * mm))
        if len(images) == 2:
            grid = Table([images], colWidths=[85 * mm, 85 * mm])
            grid.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            story.append(grid)
        else:
            story.append(images[0])
        story.append(
            Paragraph(
                "Left: risk percentage for this analysis vs the remaining percentage "
                "out of 100. Right: counts of all detections stored on your account.",
                subtitle,
            )
        )

    if content and content != "-":
        story.append(Paragraph("Analyzed content", heading))
        excerpt = content if len(content) <= 600 else content[:600] + "..."
        story.append(Paragraph(excerpt.replace("\n", "<br/>"), styles["Normal"]))

    story.append(Paragraph("Supporting signals", heading))
    if signals:
        story.append(
            ListFlowable(
                [ListItem(Paragraph(s, styles["Normal"])) for s in signals],
                bulletType="bullet",
            )
        )
    else:
        story.append(Paragraph("No specific signals were recorded.", subtitle))

    story.append(Paragraph("Safety recommendations", heading))
    if recommendations:
        story.append(
            ListFlowable(
                [ListItem(Paragraph(r, styles["Normal"])) for r in recommendations],
                bulletType="bullet",
            )
        )
    else:
        story.append(Paragraph("No recommendations were recorded.", subtitle))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c9d5e3"), thickness=0.5))
    story.append(
        Paragraph(
            "This report is produced by an automated baseline system. Scores are "
            "estimates and do not constitute a guarantee. Verify independently before "
            "acting on any result.",
            subtitle,
        )
    )

    doc.build(story)
    return buffer.getvalue()
