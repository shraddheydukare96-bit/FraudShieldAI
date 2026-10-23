#!/usr/bin/env bash
#
# Render build script for FraudShield AI.
#
# Render runs this as the "Build command" for a Web Service. It performs the
# four steps a Django deploy needs, in order, and fails fast (set -o errexit)
# so a broken build never goes live:
#   1. install pinned dependencies
#   2. train the ML model  -> regenerates the git-ignored mlartifacts/
#                             (Render's filesystem is ephemeral, so the model
#                             cannot be committed; training from the committed
#                             data/fraud_text_dataset.csv is reproducible)
#   3. collect static files -> WhiteNoise serves them from STATIC_ROOT
#   4. apply migrations     -> against the Render PostgreSQL DATABASE_URL
#
# Secrets (DJANGO_SECRET_KEY, DATABASE_URL, SMTP credentials, ...) are supplied
# as Render Environment Variables, never committed and never echoed here.
set -o errexit
set -o pipefail

echo "==> Installing Python dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "==> Training the ML model (regenerates git-ignored mlartifacts/)"
python manage.py train_model

echo "==> Collecting static files (WhiteNoise)"
python manage.py collectstatic --noinput

echo "==> Applying database migrations"
python manage.py migrate --noinput

echo "==> Build complete"
