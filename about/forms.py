"""Contact form for the about app (persists a ContactMessage)."""
from django import forms

from .models import ContactMessage


class ContactForm(forms.ModelForm):
    """Validated ModelForm over the four public fields.

    ``status``, ``user`` and ``created_at`` are intentionally excluded so a
    sender can never influence them through manipulated POST data.
    """

    class Meta:
        model = ContactMessage
        fields = ["name", "email", "subject", "message"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Your name"}),
            "email": forms.EmailInput(attrs={"placeholder": "you@example.com"}),
            "subject": forms.TextInput(attrs={"placeholder": "How can we help?"}),
            "message": forms.Textarea(
                attrs={"rows": 5, "placeholder": "Write your message here..."}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css = "form-select" if isinstance(field.widget, forms.Select) else "form-control"
            field.widget.attrs.setdefault("class", css)
