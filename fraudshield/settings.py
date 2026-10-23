"""
Django settings for the FraudShield AI project.

Environment-driven configuration:
  - Local development uses SQLite by default.
  - Production (e.g. Render) uses PostgreSQL when DATABASE_URL / DB_* vars are set.

Reads secrets from a local .env file via python-dotenv so that no credentials
are committed to version control.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Paths and environment
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env from the project root (safe no-op if the file does not exist).
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    """Parse a truthy/falsey environment variable into a bool."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------------- #
DEBUG = env_bool("DJANGO_DEBUG", True)

# The secret key MUST come from the environment in production. A single,
# well-known development fallback is allowed only while DEBUG is on so local
# setup stays trivial; the moment DEBUG is off a missing key is a hard
# configuration error - we never boot a deployed site on a committed secret.
_DEV_SECRET_KEY = "django-insecure-eq=w)-zd95nhro-*9z%u(o71g_$5@bmtkoy=lx7t$uuq!5il=+"
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", _DEV_SECRET_KEY if DEBUG else "")
if not SECRET_KEY:
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY must be set in the environment when DEBUG=False."
    )

# Hostnames/domains this instance may serve. Comma-separated values in
# DJANGO_ALLOWED_HOSTS are split and whitespace-stripped so a list like
# "host-a.com, host-b.com" parses correctly. We always keep the local
# development hosts AND the deployed Render hostname, so the site boots and
# serves correctly out of the box (this is the fix for the DisallowedHost error
# on fraudshieldai-e5eg.onrender.com) even when DJANGO_ALLOWED_HOSTS is unset.
# Extra/override hosts can still be supplied via DJANGO_ALLOWED_HOSTS.
_RENDER_HOST = "fraudshieldai-e5eg.onrender.com"
_BASE_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0", _RENDER_HOST]
_extra_hosts = [
    h.strip()
    for h in os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",")
    if h.strip()
]

ALLOWED_HOSTS = []
for _host in _BASE_HOSTS + _extra_hosts:
    if _host not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(_host)

# The canonical site origin is always a valid host for its own app, so add the
# SITE_URL hostname automatically (avoids a self-inflicted 400 on a custom
# domain while still refusing arbitrary Host headers when SITE_URL is unset).
_site_origin = (os.getenv("SITE_URL", "") or "").strip().rstrip("/")
_site_host = ""
if _site_origin:
    from urllib.parse import urlparse as _urlparse

    _site_host = _urlparse(_site_origin).netloc
    if _site_host and _site_host not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(_site_host)

# The Django test client and CI run against the 'testserver' host.
if DEBUG and "testserver" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("testserver")

# CSRF over HTTPS requires the full trusted origin (scheme + host). We always
# trust the deployed Render origin so HTTPS POSTs (login, verification resend,
# contact, report email) pass validation, and additionally include any origins
# from CSRF_TRUSTED_ORIGINS and the configured SITE_URL.
_extra_origins = [
    o.strip()
    for o in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
]
CSRF_TRUSTED_ORIGINS = []
for _origin in ([f"https://{_RENDER_HOST}"] + _extra_origins + ([_site_origin] if _site_origin else [])):
    if _origin not in CSRF_TRUSTED_ORIGINS:
        CSRF_TRUSTED_ORIGINS.append(_origin)

# --------------------------------------------------------------------------- #
# Applications
# --------------------------------------------------------------------------- #
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # FraudShield apps
    "accounts",
    "dashboard",
    "detection",
    "reports",
    "about",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "fraudshield.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "fraudshield.wsgi.application"

# --------------------------------------------------------------------------- #
# Database: DATABASE_URL (Render/production) -> PostgreSQL -> local SQLite
# --------------------------------------------------------------------------- #
# Render injects DATABASE_URL for its PostgreSQL instances. When present we use
# it via dj-database-url, while keeping the existing explicit POSTGRES_* and
# SQLite paths untouched so local development continues to work unchanged.
# Render recommends CONN_MAX_AGE=0 (persistent connections can be dropped by the
# proxy), so that is the default for the DATABASE_URL path.
_database_url = os.getenv("DATABASE_URL", "").strip()
if _database_url:
    import dj_database_url

    DATABASES = {
        "default": dj_database_url.parse(
            _database_url,
            conn_max_age=int(os.getenv("DB_CONN_MAX_AGE", "0")),
            ssl_require=env_bool("DB_SSL_REQUIRE", False),
        )
    }
elif env_bool("USE_POSTGRES", False) or os.getenv("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "fraudshield"),
            "USER": os.getenv("POSTGRES_USER", "postgres"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": int(os.getenv("POSTGRES_CONN_MAX_AGE", "60")),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# Guard against the silent SQLite fallback in production. Render's filesystem is
# ephemeral: a SQLite file created at build time is wiped on every restart or
# redeploy, which surfaces at runtime as "OperationalError: no such table" for
# auth_user, about_teammember, etc. If the site is deployed with DEBUG=False but
# no persistent database is attached, fail fast and loudly at boot (and during
# `manage.py migrate`) instead of serving broken pages from a throwaway SQLite.
# Local development (DEBUG=True) is unaffected and keeps using the SQLite file.
if not DEBUG and not _database_url and not (
    env_bool("USE_POSTGRES", False) or os.getenv("POSTGRES_DB")
):
    raise ImproperlyConfigured(
        "Production (DEBUG=False) needs a persistent database: set "
        "DATABASE_URL to a PostgreSQL connection string (e.g. a Render or Neon "
        "Postgres instance) before deploying. SQLite on Render's ephemeral "
        "filesystem loses all tables on restart. Local development with "
        "DEBUG=True is unaffected and continues to use SQLite."
    )

# --------------------------------------------------------------------------- #
# Password validation (secure hashing is provided by Django's default PBKDF2)
# --------------------------------------------------------------------------- #
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Default hasher chain: PBKDF2 first (Django built-in secure hashing).
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# --------------------------------------------------------------------------- #
# Authentication redirects
# --------------------------------------------------------------------------- #
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:index"
LOGOUT_REDIRECT_URL = "accounts:login"

# --------------------------------------------------------------------------- #
# Session and CSRF hardening
# --------------------------------------------------------------------------- #
SESSION_COOKIE_HTTPONLY = True          # Session cookie is not readable by JS.
CSRF_COOKIE_HTTPONLY = True             # CSRF token cookie not readable by JS.
SESSION_COOKIE_SAMESITE = "Lax"         # Mitigates cross-site request leakage.
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 60 * 60 * 12        # Sessions expire after 12 hours.
SESSION_SAVE_EVERY_REQUEST = False
SECURE_REFERRER_POLICY = "same-origin"

# --------------------------------------------------------------------------- #
# Email delivery
# --------------------------------------------------------------------------- #
# Local dev and tests use the console / locmem backends so no SMTP is required.
# Set EMAIL_BACKEND to 'django.core.mail.backends.smtp.EmailBackend' (plus the
# EMAIL_HOST_* vars) in .env for real delivery.
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.locmem.EmailBackend"
    if os.getenv("TESTING")
    else "django.core.mail.backends.console.EmailBackend",
)
EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", False)
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "FraudShield AI <no-reply@fraudshield.local>")

# Gmail (and most authenticated relays) reject any message whose "Mail from"
# envelope address is not a valid address belonging to the authenticated
# account (SMTP 553/501). If EMAIL_HOST_USER is configured but DEFAULT_FROM_EMAIL
# has no valid address (e.g. only a display name), derive a valid sender from
# the login so delivery works instead of failing opaquely. No credentials are
# involved in this step - EMAIL_HOST_USER is the account address, not a secret.
from django.core.exceptions import ValidationError as _ValidationError  # noqa: E402
from django.core.validators import validate_email as _validate_email  # noqa: E402
from email.utils import parseaddr as _parseaddr  # noqa: E402


def _from_address_is_valid(value: str) -> bool:
    try:
        _validate_email(_parseaddr(value)[1])
        return True
    except (_ValidationError, IndexError, TypeError):
        return False


_host_user = os.getenv("EMAIL_HOST_USER", "").strip()
if _host_user and not _from_address_is_valid(DEFAULT_FROM_EMAIL):
    DEFAULT_FROM_EMAIL = f"FraudShield AI <{_host_user}>"

SERVER_EMAIL = DEFAULT_FROM_EMAIL

# Verification token lifetime.
from datetime import timedelta as _timedelta  # noqa: E402
EMAIL_VERIFICATION_TTL = _timedelta(hours=int(os.getenv("EMAIL_VERIFICATION_TTL_HOURS", "24")))
EMAIL_SUBJECT_PREFIX = "[FraudShield AI] "

# Absolute base URL used to build the links we put inside outgoing emails
# (verification, and any future deep links). Configure it explicitly:
#   * local testing from another device (e.g. a phone): http://<LAN-IP>:8000
#   * production: the deployed public HTTPS origin, e.g. https://fraud.example.com
# When SITE_URL is set it is used verbatim and the incoming Host header is
# IGNORED, so a crafted Host can never poison a verification link. When it is
# left empty we fall back to the request host (convenience for local dev only
# - Django has already validated that host against ALLOWED_HOSTS); do not rely
# on the fallback in production. No trailing slash is stored.
SITE_URL = os.getenv("SITE_URL", "").strip().rstrip("/")

# Verification-email throttling (abuse protection). A verification LINK stays
# valid for EMAIL_VERIFICATION_TTL (24h by default) - that is its expiry, NOT a
# wait between sends. Re-sending is separately rate limited so one account
# cannot flood its own inbox or our SMTP provider:
#   * VERIFICATION_EMAIL_COOLDOWN_SECONDS - minimum spacing between sends.
#   * VERIFICATION_EMAIL_HOURLY_LIMIT     - max sends per rolling hour.
# Enforced against real EmailVerificationToken rows (a token is created on every
# send), so limits survive restarts and cannot be bypassed by clearing cookies.
# This NEVER disables verification itself; it only spaces out delivery requests.
VERIFICATION_EMAIL_COOLDOWN_SECONDS = int(
    os.getenv("VERIFICATION_EMAIL_COOLDOWN_SECONDS", "60")
)
VERIFICATION_EMAIL_HOURLY_LIMIT = int(os.getenv("VERIFICATION_EMAIL_HOURLY_LIMIT", "5"))

# Minimum seconds between successful "send report to my email" actions per
# user. Prevents accidental duplicates and mailbox flooding; enforced against
# real recorded DeliveryAttempt rows, not in-memory counters.
REPORT_EMAIL_COOLDOWN_SECONDS = int(os.getenv("REPORT_EMAIL_COOLDOWN_SECONDS", "60"))

# --------------------------------------------------------------------------- #
# Logging - report delivery outcomes are logged by id/status only. SMTP
# credentials and message contents never reach the logs.
# --------------------------------------------------------------------------- #
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "{levelname} {asctime} {name}: {message}", "style": "{"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
    },
    "loggers": {
        "reports.email": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# --------------------------------------------------------------------------- #
# Internationalization
# --------------------------------------------------------------------------- #
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------- #
# Static files
# --------------------------------------------------------------------------- #
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# In development and tests, use plain filesystem serving. In production, use
# WhiteNoise's manifest storage for hashed, compressed static assets.
if DEBUG:
    STATICFILES_STORAGE_BACKEND = "django.contrib.staticfiles.storage.StaticFilesStorage"
else:
    STATICFILES_STORAGE_BACKEND = "whitenoise.storage.CompressedManifestStaticFilesStorage"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": STATICFILES_STORAGE_BACKEND},
}

# --------------------------------------------------------------------------- #
# Media files (user uploads, e.g. team photos)
# --------------------------------------------------------------------------- #
# Uploaded through Django Admin and served from MEDIA_URL. In production these
# should live on a managed storage backend; locally they are written to MEDIA_ROOT.
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------- #
# Production hardening (only applied when DEBUG is off)
# --------------------------------------------------------------------------- #
if not DEBUG:
    # Render terminates TLS at its load balancer and forwards
    # X-Forwarded-Proto: https. Trusting it makes request.is_secure() correct
    # (so emailed links use https) and stops SECURE_SSL_REDIRECT from looping.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_CONTENT_TYPE_NOSNIFF = True
