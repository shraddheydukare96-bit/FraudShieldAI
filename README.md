# FraudShield AI

An AI-powered cybersecurity web application for detecting fraudulent SMS
messages, phishing emails and malicious URLs. Built with **Python**, **Django**
and **scikit-learn**.

> Status: **Phase 1 complete** - project foundation, authentication, theming and
> core pages. AI analysis, model training, history and PDF reporting are
> scheduled for later phases.

## Tech Stack

- Python 3.12, Django 5.1
- Bootstrap 5 (dark navy / cyan cybersecurity theme)
- SQLite (local development), PostgreSQL (production)
- Django built-in authentication with secure PBKDF2 password hashing
- WhiteNoise (static files), python-dotenv (configuration)

## Features In This Phase

- Home, About and Contact pages
- Secure Login, Signup and Logout
- Authenticated dashboard shell with a real database statistic (user count)
- Responsive, professional dark UI with a reusable `base.html`
- Environment-driven settings (SQLite locally, PostgreSQL in production)
- Django Admin enabled at `/admin/`

## Project Structure

```
fraudshield/            # Django project (settings, urls, wsgi/asgi)
accounts/               # Login, signup, logout
dashboard/              # Authenticated dashboard
detection/              # SMS / email / URL analysis (Phase 2)
reports/                # PDF reports & history (later phase)
about/                  # About + Contact pages
templates/              # base.html and per-page templates
static/css, static/js   # Theme assets
```

## Local Setup

```powershell
# 1. Create and activate the virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment (optional - sensible defaults are built in)
copy .env.example .env

# 4. Apply migrations
python manage.py migrate

# 5. Create a superuser for the admin site
python manage.py createsuperuser

# 6. Train the baseline AI model (writes artifacts to mlartifacts/)
python manage.py train_model

# 7. Run the development server
python manage.py runserver
```

Open http://127.0.0.1:8000/ in your browser. Admin is at http://127.0.0.1:8000/admin/.

## Configuration

Settings are read from environment variables (see `.env.example`):

| Variable | Purpose | Default |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Signing key | dev fallback |
| `DJANGO_DEBUG` | Debug mode | `True` |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hosts | `localhost,127.0.0.1,0.0.0.0` |
| `SITE_URL` | Absolute base URL for emailed links | empty (falls back to request host in dev) |
| `USE_POSTGRES` | Switch to PostgreSQL | `False` (uses SQLite) |
| `POSTGRES_*` | Production DB credentials | - |

When `DJANGO_DEBUG=False`, production hardening (HTTPS redirect, HSTS, secure
cookies) is applied automatically.

## Roadmap

- **Phase 2:** scikit-learn SMS / email / URL analysis + analysis history
- **Phase 3:** Model training & evaluation with metrics
- **Phase 4:** PDF report generation
- **Phase 5:** Automated tests and Render deployment

## AI Detection (Phase 3 - complete)

- **Model:** TF-IDF + Logistic Regression pipeline (`detection/ml/classifier.py`)
  trained on the project baseline corpus. Reproducible via
  `python manage.py train_model`, which evaluates on a held-out split and prints
  precision, recall, F1 and a confusion matrix, saving `mlartifacts/evaluation_report.json`.
- **Dataset:** `data/fraud_text_dataset.csv` - a project-authored, CC0-licensed
  baseline corpus. See `data/DATASET.md` for source, license and honest
  limitations. Metrics reflect this small corpus only, not real-world accuracy.
- **URL analysis:** transparent rule-based scoring (`detection/ml/url_analyzer.py`)
  - never visits the submitted URL.
- **Optional reputation:** Google Safe Browsing Lookup via env key
  (`URL_REPUTATION_ENABLED` + `GOOGLE_SAFE_BROWSING_KEY`), disabled by default.
- **Separation:** all ML + persistence lives in `detection/ml/*` and
  `detection/services.py`, not in views. Views only present results and enforce
  per-user access control.

## PDF Reports & Email Delivery

Every completed analysis gets a `Report` that can be **downloaded as a PDF** or
**emailed to the signed-in user's own registered address**.

- **Risk percentage (0-100):** derived from the stored `Detection.risk_score`
  (0-1 scores are converted; out-of-range values display as "Score
  unavailable" - never an invented number). The raw score / model confidence
  is shown separately.
- **PDF contents:** report ID, analysis type, timestamps, classification
  (SAFE / SUSPICIOUS / HIGH RISK), risk percentage, a matplotlib pie of the
  risk vs remaining percentage for that single analysis, a second pie of the
  owner's real safe/suspicious/high-risk detection counts, supporting signals,
  and recommendations. Charts are rendered in memory and embedded in the PDF.
- **Send Report to Registered Email:** POST-only, CSRF-protected, ownership
  checked. The recipient is always `request.user.email` (shown masked), the
  address must be verified, and sends are rate limited
  (`REPORT_EMAIL_COOLDOWN_SECONDS`, default 60s). Every attempt is recorded in
  `reports.DeliveryAttempt`; the site only shows success when the mail server
  actually accepted the message.

### Emailed links and `SITE_URL`

Verification emails contain an absolute link back to your app. By default the
link's host is taken from the machine that triggered the email, so a link sent
while browsing `http://127.0.0.1:8000/` opens as `127.0.0.1` on your phone and
fails with `ERR_CONNECTION_REFUSED`. Set `SITE_URL` in `.env` to the address
your users can actually reach. When `SITE_URL` is set it is used verbatim and
the incoming `Host` header is ignored, so a forged header can never poison a
verification link (token validation, expiry and email ownership are unchanged).

- **Same-machine development** — leave `SITE_URL` empty, or set
  `SITE_URL=http://127.0.0.1:8000`.
- **Test the link from your phone** — set `SITE_URL` to your computer's LAN
  address and bind the server to all interfaces, e.g.
  ```ini
  SITE_URL=http://192.168.1.50:8000
  DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,192.168.1.50
  ```
  then run `python manage.py runserver 0:8000`, connect the phone to the same
  Wi-Fi, and use the LAN address. Find your IPv4 address with `ipconfig`
  (Windows) or `ifconfig`/`ip addr` (macOS/Linux).
- **Production** — set it to the deployed public HTTPS origin, e.g.
  `SITE_URL=https://your-domain.example`.

### Gmail SMTP setup (real delivery)

1. Enable 2-Step Verification on the Google account.
2. Create an **App Password**: Google Account -> Security -> App passwords
   (16 characters). Do **not** use your normal account password and never
   commit the value.
3. Put these in `.env` (copy from `.env.example`):

```ini
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password
DEFAULT_FROM_EMAIL=FraudShield AI <your-email@gmail.com>
```

4. Restart the server and send a report from a detection/report page. Until
   the console/locmem backend is replaced with the SMTP backend above, emails
   are **not** actually delivered (dev mode prints them to the console; tests
   use Django's in-memory backend).

## Deployment (Render)

The project is configured for a Render **Web Service** + **PostgreSQL** instance.
`build.sh`, `requirements.txt` (Gunicorn, `dj-database-url`, WhiteNoise,
`psycopg2-binary`) and `.python-version` are committed; the runtime is Gunicorn
serving `fraudshield.wsgi:application` with WhiteNoise handling static files.

**Build command**

```bash
bash ./build.sh
```

`build.sh` installs dependencies, trains the ML model (the `mlartifacts/` model
file is git-ignored and Render's disk is ephemeral, so it is regenerated on
every build from the committed `data/fraud_text_dataset.csv`), runs
`collectstatic`, and applies `migrate`.

**Start command**

```bash
gunicorn fraudshield.wsgi:application --bind 0.0.0.0:$PORT
```

**Required Render Environment Variables** (set these in the Render dashboard,
never in Git):

| Variable | Value |
| --- | --- |
| `DJANGO_SECRET_KEY` | A fresh random secret (`python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"`). Required when `DEBUG=False`. |
| `DJANGO_DEBUG` | `False` |
| `DJANGO_ALLOWED_HOSTS` | `your-app.onrender.com` plus any custom domain |
| `SITE_URL` | `https://your-app.onrender.com` (drives emailed links, `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`) |
| `DATABASE_URL` | Render's PostgreSQL **Internal** connection string (auto-injected when the DB is linked in the same Render account) |
| `EMAIL_BACKEND` | `django.core.mail.backends.smtp.EmailBackend` |
| `EMAIL_HOST` / `EMAIL_PORT` / `EMAIL_USE_TLS` | `smtp.gmail.com` / `587` / `True` |
| `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD` | Gmail address + 16-char **App Password** |
| `DEFAULT_FROM_EMAIL` | `FraudShield AI <your-email@gmail.com>` |

> `SECURE_PROXY_SSL_HEADER` is enabled automatically when `DEBUG=False`, so
> Render's HTTPS proxy is trusted (emailed links use `https://` and the SSL
> redirect does not loop).

**Persistent storage warning.** Render's filesystem is **ephemeral** — anything
written at runtime is lost on every deploy/restart:

- **Media uploads** (`MEDIA_ROOT`, e.g. team photos uploaded in Admin) do **not**
  persist. Attach a Render **Disk** to the service and point `MEDIA_ROOT` at the
  mount path, or move uploads to external object storage (S3, e.g. via
  `django-storages`). Do not rely on local `media/` files surviving a deploy.
- **Static files** are fine — they are collected at build time and served by
  WhiteNoise from the deployed image.
- The **ML model** is fine — it is rebuilt every deploy by `train_model` in
  `build.sh`.
- **Report PDFs** are generated in memory on request and never written to disk,
  so they need no storage.
- The **database** lives on Render PostgreSQL via `DATABASE_URL`, not on disk.

> This section documents the configuration only. Nothing here deploys, commits,
> or pushes the site.
