"""URL configuration for the accounts app."""
from django.urls import path

from .views import (
    FraudShieldLoginView,
    FraudShieldLogoutView,
    FraudShieldSignupView,
    PreferencesView,
    ProfileView,
    ResendVerificationView,
    VerificationSentView,
    VerifyEmailView,
)

app_name = "accounts"

urlpatterns = [
    path("login/", FraudShieldLoginView.as_view(), name="login"),
    path("logout/", FraudShieldLogoutView.as_view(), name="logout"),
    path("signup/", FraudShieldSignupView.as_view(), name="signup"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("preferences/", PreferencesView.as_view(), name="preferences"),
    path("verify/sent/", VerificationSentView.as_view(), name="verify_sent"),
    path("verify/resend/", ResendVerificationView.as_view(), name="verify_resend"),
    path("verify/<str:key>/", VerifyEmailView.as_view(), name="verify"),
]
