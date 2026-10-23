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
_database_url = os.getenv("DATABASE_URL", "").strip().strip('"').strip("'")
if _database_url:
    import dj_database_url
    from urllib.parse import urlparse

    # Validate BEFORE handing the value to dj_database_url.parse(), which raises a
    # cryptic UnknownSchemeError on unsupported schemes (e.g. one beginning with
    # "s"). We require a complete, supported PostgreSQL URL and fail with a clear,
    # credential-safe message. Only the non-sensitive scheme token is ever echoed
    # -- never the full URL, host, user, or password.
    _ALLOWED_DB_SCHEMES = {"postgres", "postgresql", "postgis"}
    _scheme = urlparse(_database_url).scheme.split("+", 1)[0].lower()
    if "://" not in _database_url or not _scheme:
        raise ImproperlyConfigured(
            "DATABASE_URL is set but is not a full connection URL (no scheme). "
            "Expected: postgres://USER:PASSWORD@HOST:PORT/DATABASE. SQLite is "
            "not used while DATABASE_URL is present."
        )
    if _scheme not in _ALLOWED_DB_SCHEMES:
        raise ImproperlyConfigured(
            f"DATABASE_URL uses an unsupported scheme '{_scheme}://'. "
            "FraudShieldAI requires PostgreSQL: use a postgres:// or "
            "postgresql:// URL. SQLite is not used while DATABASE_URL is present."
        )
    _parsed_db = urlparse(_database_url)
    if not _parsed_db.hostname or not (_parsed_db.path or "").strip("/"):
        raise ImproperlyConfigured(
            "DATABASE_URL is an incomplete PostgreSQL URL (missing host or "
            "database name). Expected: "
            "postgres://USER:PASSWORD@HOST:PORT/DATABASE."
        )

    try:
        _database_config = dj_database_url.parse(
            _database_url,
            conn_max_age=int(os.getenv("DB_CONN_MAX_AGE", "0")),
            ssl_require=env_bool("DB_SSL_REQUIRE", False),
        )
    except Exception as _exc:
        # Turn any parse failure into a clear config error. We surface only the
        # exception type, never the URL string (which holds credentials).
        raise ImproperlyConfigured(
            "DATABASE_URL could not be parsed as a PostgreSQL connection "
            f"string ({type(_exc).__name__}). Verify it is a complete "
            "postgres://USER:PASSWORD@HOST:PORT/DATABASE URL."
        )

    # Refuse a silent downgrade: a configured DATABASE_URL MUST resolve to a
    # PostgreSQL backend, not SQLite/other (the "build succeeds but runtime shows
    # no such table" failure mode).
    _configured_engine = _database_config.get("ENGINE", "") or ""
    if "postgresql" not in _configured_engine and "postgis" not in _configured_engine:
        raise ImproperlyConfigured(
            "DATABASE_URL is set but did not resolve to a PostgreSQL backend "
            f"(got engine={_configured_engine or 'empty'}). Refusing to fall "
            "back to SQLite while DATABASE_URL is present. Use a postgres:// "
            "or postgresql:// connection URL."
        )
    DATABASES = {"default": _database_config}
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
    # No DATABASE_URL / Postgres configured. Use SQLite with a single, absolute
    # path so the BUILD process and the running WEB PROCESS open the exact same
    # file. Defaults to BASE_DIR / "db.sqlite3" (unchanged local behavior). Set
    # SQLITE_PATH to override -- e.g. to a mounted Render Disk so data can survive
    # restarts; on Render's default ephemeral filesystem the file (and all data)
    # is lost whenever the free service restarts or redeploys.
    _sqlite_override = os.getenv("SQLITE_PATH", "").strip().strip('"').strip("'")
    _sqlite_name = Path(_sqlite_override) if _sqlite_override else (BASE_DIR / "db.sqlite3")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": _sqlite_name,
        }
    }

# Database persistence policy for production (DEBUG=False):
# Render's default filesystem is EPHEMERAL. A SQLite file created and migrated
# during a build is wiped whenever the free web service restarts or redeploys,
# which later surfaces as "OperationalError: no such table: auth_user /
# about_teammember". Running SQLite with DEBUG=False is therefore permitted here
# ONLY as an explicit, temporary free demo: it serves correctly right after a
# deploy but loses data on restarts. For durable data either attach a PostgreSQL
# DATABASE_URL (recommended) or set DJANGO_REQUIRE_POSTGRES=True, which makes an
# SQLite production boot fail fast instead of silently risking data loss.
# Local development (DEBUG=True) is unaffected and always uses SQLite.
_uses_sqlite = "sqlite3" in DATABASES["default"].get("ENGINE", "")
if not DEBUG and _uses_sqlite and env_bool("DJANGO_REQUIRE_POSTGRES", False):
    raise ImproperlyConfigured(
        "DJANGO_REQUIRE_POSTGRES=True but no PostgreSQL is configured. Set "
        "DATABASE_URL to a postgres:// connection string, or unset "
        "DJANGO_REQUIRE_POSTGRES to allow an ephemeral SQLite free-tier demo."
    )

# --------------------------------------------------------------------------- #
# Startup database diagnostics (SAFE). Logged at WARNING so it always appears in
# Render's runtime log, proving which engine + file the WEB PROCESS opens. This
# is how we tell a "migrate never ran" deploy apart from a "wrong DATABASE_URL"
# one. We print only the engine and, for SQLite, the absolute file path (not a
# secret). For PostgreSQL we print only the database NAME - never host, user,
# password, or the full DATABASE_URL.
# --------------------------------------------------------------------------- #
import logging as _logging  # noqa: E402


def _safe_database_descriptor():
    db = DATABASES["default"]
    engine = (db.get("ENGINE", "") or "").rsplit(".", 1)[-1] or "unknown"
    if "sqlite" in engine:
        return engine, str(db.get("NAME"))
    if "postgresql" in engine:
        return engine, db.get("NAME", "") or "(local socket)"
    return engine, "(hidden)"


_db_engine, _db_location = _safe_database_descriptor()
_logging.getLogger("fraudshield.db").warning(
    "Django database in use: engine=%s location=%s DEBUG=%s",
    _db_engine, _db_location, DEBUG,
)
if "sqlite" in _db_engine and not DEBUG:
    _logging.getLogger("fraudshield.db").warning(
        "Production is on SQLite; data will NOT persist across restarts on an "
        "ephemeral container. Set DATABASE_URL to PostgreSQL for durable data."
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
