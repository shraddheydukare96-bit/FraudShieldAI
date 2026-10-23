"""Views for user authentication, email verification and preferences."""
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, FormView, TemplateView, UpdateView

from . import services
from .forms import (
    FraudShieldLoginForm,
    FraudShieldSignupForm,
    NotificationPreferencesForm,
)
from .models import NotificationPreferences


class FraudShieldLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = FraudShieldLoginForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        # Django's LoginView calls auth.login(), which rotates the session key
        # (cycle_key) to prevent session-fixation attacks.
        result = super().form_valid(form)
        messages.success(self.request, f"Welcome back, {form.get_user().username}.")
        return result


class FraudShieldLogoutView(LogoutView):
    """Logout is POST-only (handled by the navbar form) for CSRF safety."""


class FraudShieldSignupView(CreateView):
    form_class = FraudShieldSignupForm
    template_name = "accounts/signup.html"
    success_url = reverse_lazy("accounts:verify_sent")

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object
        # Guarantee a preferences row and a usable token exists (so the user can
        # always verify later). The throttle is checked BEFORE issuing, so the
        # first email for a brand-new account is never blocked.
        services.ensure_preferences(user)
        allowed = services.verification_send_block_seconds(user) is None
        token = services.issue_verification(user)
        # Log the new user in so the existing test suite (which asserts an
        # authenticated session after signup) keeps passing.
        login(self.request, user)
        if not allowed:
            messages.warning(
                self.request,
                services.verification_throttle_message(
                    services.verification_send_block_seconds(user)
                ),
            )
        else:
            sent = services.send_verification_email(self.request, token)
            if sent:
                messages.info(
                    self.request,
                    "We sent a verification link to your email. Please confirm "
                    "within 24 hours to unlock report delivery.",
                )
            else:
                messages.warning(
                    self.request,
                    "Account created, but we could not queue the verification "
                    "email. You can resend it from the verification page.",
                )
        return response

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("dashboard:index")
        return super().get(request, *args, **kwargs)


class ProfileView(LoginRequiredMixin, TemplateView):
    """Show the signed-in user's account details and their own resource counts."""

    template_name = "accounts/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        prefs = services.ensure_preferences(user)
        context["detection_count"] = user.detections.count()
        context["report_count"] = user.reports.count()
        context["email_verified"] = prefs.email_verified
        context["preferences"] = prefs
        return context


class VerificationSentView(LoginRequiredMixin, TemplateView):
    """Post-signup landing page telling the user to check their inbox."""

    template_name = "accounts/verify_sent.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        prefs = services.ensure_preferences(user)
        context["email_verified"] = prefs.email_verified
        context["email"] = user.email
        # Expose the live resend throttle so the template can honestly disable
        # the button (no fake countdown) instead of letting the user re-POST.
        wait = None if prefs.email_verified else services.verification_send_block_seconds(user)
        context["resend_block_seconds"] = wait
        context["can_resend"] = (not prefs.email_verified) and wait is None
        context["resend_wait_message"] = services.verification_throttle_message(wait)
        return context


class VerifyEmailView(TemplateView):
    """Redeem a verification token from the emailed link.

    Public (unauthenticated) so the user can click it from any device; the
    token itself is the capability. All outcomes are shown honestly - we never
    silently re-issue or auto-verify.
    """

    template_name = "accounts/verify_result.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        key = self.kwargs.get("key", "")
        status, token = services.redeem_token(key)
        context["status"] = status
        context["target_user"] = token.user.username if token else ""
        context["can_resend"] = status in {
            services.VerifyResult.EXPIRED,
            services.VerifyResult.ALREADY_USED,
            services.VerifyResult.UNKNOWN,
        }
        return context


class ResendVerificationView(LoginRequiredMixin, FormView):
    """POST-only resend handler (CSRF-protected)."""

    template_name = "accounts/verify_sent.html"
    form_url = None  # not a real form; we simply POST to this view.

    def get(self, request, *args, **kwargs):
        # Resend requires an explicit POST to avoid CSRF-based mail spam.
        return redirect("accounts:verify_sent")

    def form_valid(self, form):
        return self._do_send()

    def post(self, request, *args, **kwargs):
        return self._do_send()

    def _do_send(self):
        user = self.request.user
        # Use ensure_preferences so legacy accounts (no NotificationPreferences
        # row) can still resend without a RelatedObjectDoesNotExist crash.
        prefs = services.ensure_preferences(user)
        if prefs.email_verified:
            messages.info(self.request, "Your email is already verified.")
        elif not (user.email or "").strip():
            messages.error(
                self.request,
                "Add an email address to your account before verifying.",
            )
        else:
            # Check the throttle BEFORE issuing a new token (issuing first would
            # make the cooldown see the brand-new token and block forever).
            wait = services.verification_send_block_seconds(user)
            if wait is not None:
                messages.warning(
                    self.request, services.verification_throttle_message(wait)
                )
            else:
                token = services.issue_verification(user)
                sent = services.send_verification_email(self.request, token)
                if sent:
                    messages.success(
                        self.request, "A new verification link has been sent."
                    )
                else:
                    messages.error(
                        self.request,
                        "We could not send the verification email right now. "
                        "Please try again shortly.",
                    )
        return redirect("accounts:verify_sent")


class PreferencesView(LoginRequiredMixin, UpdateView):
    """Edit the signed-in user's notification preferences."""

    template_name = "accounts/preferences.html"
    form_class = NotificationPreferencesForm
    success_url = reverse_lazy("accounts:preferences")

    def get_object(self, queryset=None):
        return services.ensure_preferences(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["email_verified"] = self.object.email_verified
        context["user_email"] = self.request.user.email
        return context

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Notification preferences saved.")
        return response
