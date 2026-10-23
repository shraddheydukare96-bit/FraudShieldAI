"""Authentication forms for FraudShield AI accounts."""
from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User

from .models import NotificationPreferences


class FormMixin:
    """Add Bootstrap form-control classes to fields for consistent styling."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs.setdefault("class", "form-check-input")
            elif isinstance(widget, forms.Select):
                widget.attrs.setdefault("class", "form-select")
            else:
                widget.attrs.setdefault("class", "form-control")


class FraudShieldLoginForm(FormMixin, AuthenticationForm):
    username = forms.CharField(
        label="Username",
        widget=forms.TextInput(attrs={"placeholder": "Your username", "autofocus": True}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"placeholder": "Your password"}),
    )

    # Friendlier, explicit messages.
    username.error_messages["required"] = "Please enter your username."
    password.error_messages["required"] = "Please enter your password."

    def clean(self):
        try:
            return super().clean()
        except forms.ValidationError:
            # Replace Django's generic message with something clearer.
            raise forms.ValidationError(
                "We couldn't sign you in. Please check your username and password."
            )


class FraudShieldSignupForm(FormMixin, UserCreationForm):
    email = forms.EmailField(
        required=True,
        label="Email address",
        widget=forms.EmailInput(attrs={"placeholder": "you@example.com"}),
        help_text="Used for account recovery. We never share it.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Friendlier mismatch message (validators still run via the parent).
        self.error_messages["password_mismatch"] = "The two passwords do not match."
        self.fields["username"].widget.attrs["placeholder"] = "Choose a username"
        self.fields["username"].help_text = (
            "Required. Letters, digits and @/./+/-/_ only."
        )
        self.fields["password1"].widget.attrs["placeholder"] = "Create a strong password"
        self.fields["password2"].widget.attrs["placeholder"] = "Confirm your password"

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email")

    def clean_username(self):
        username = self.cleaned_data.get("username", "").strip()
        if not username:
            raise forms.ValidationError("Please choose a username.")
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("That username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip().lower()
        if not email:
            raise forms.ValidationError("Please enter a valid email address.")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "An account with this email already exists. Try logging in."
            )
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class NotificationPreferencesForm(FormMixin, forms.ModelForm):
    """Edit the signed-in user's notification preferences.

    ``email_verified`` is intentionally excluded - only token redemption can
    change that flag, so a user can never mark their address verified by hand.
    """

    class Meta:
        model = NotificationPreferences
        fields = (
            "high_risk_alerts",
            "report_attach_to_email",
            "summary_frequency",
        )
        labels = {
            "high_risk_alerts": "Email me when an analysis is classified as fraud",
            "report_attach_to_email": "Attach the PDF report to that email",
            "summary_frequency": "Security summary cadence",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Report attachment only makes sense when alerts are on.
        self.fields["report_attach_to_email"].required = False
