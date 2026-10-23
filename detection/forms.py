"""Forms for submitting content to the AI analysis engine."""
from django import forms

from .models import Detection


class AnalysisForm(forms.Form):
    channel = forms.ChoiceField(
        label="Channel",
        choices=Detection.Channel.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
        help_text="Choose the type of content you want to analyze.",
    )
    content = forms.CharField(
        label="Content",
        widget=forms.Textarea(
            attrs={
                "rows": 5,
                "class": "form-control",
                "placeholder": "Paste the SMS message, email text or URL here...",
            }
        ),
    )

    def clean_content(self):
        content = self.cleaned_data.get("content", "").strip()
        if not content:
            raise forms.ValidationError("Please enter some content to analyze.")
        return content


class HistoryFilterForm(forms.Form):
    """Optional filters for the analysis history page. All fields are optional."""

    CLASSIFICATION_CHOICES = [
        ("", "All outcomes"),
        ("fraud", "High-risk (fraud)"),
        ("inconclusive", "Suspicious (inconclusive)"),
        ("legitimate", "Safe (legitimate)"),
    ]

    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "Search content..."}
        ),
    )
    channel = forms.ChoiceField(
        required=False,
        label="Type",
        choices=[("", "All types")] + list(Detection.Channel.choices),
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    classification = forms.ChoiceField(
        required=False,
        label="Outcome",
        choices=CLASSIFICATION_CHOICES,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    date_from = forms.DateField(
        required=False,
        label="From",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
    date_to = forms.DateField(
        required=False,
        label="To",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
