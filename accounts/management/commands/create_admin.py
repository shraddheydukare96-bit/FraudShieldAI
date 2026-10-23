"""Management command: interactively create a Django superuser (admin).

Run this by hand against whichever database the deployment is configured to
use -- it operates on Django's *default* database connection, so on Render it
targets exactly the SQLite/PostgreSQL database the running app uses.

    python manage.py create_admin

Security properties (by design):
  * Username, email and password are prompted interactively; nothing is
    hardcoded and no credential is ever passed on the command line (which would
    leak into shell history / the process list).
  * The password is read with ``getpass`` so it is never echoed, and it is only
    validated + hashed -- never printed.
  * The password is hashed with the project's configured PASSWORD_HASHERS
    (PBKDF2 first) via the normal ORM path.
  * If a user with that username already exists, the account is left completely
    untouched (no password reset, no flag changes).
"""
from __future__ import annotations

import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email


class Command(BaseCommand):
    help = (
        "Interactively create a superuser in the configured default database. "
        "Prompts for username, email and password, and never overwrites an "
        "existing account."
    )

    def handle(self, *args, **options):
        user_model = get_user_model()

        username = self._prompt("Username")
        if not username:
            raise CommandError("Username is required.")

        # Preserve any existing account: never change its password or flags.
        if user_model.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(
                f"A user named '{username}' already exists. No changes were "
                "made; the existing account was left untouched."
            ))
            return

        email = self._prompt("Email (optional - press Enter to skip)")
        if email:
            try:
                validate_email(email)
            except ValidationError as exc:
                raise CommandError(
                    "Invalid email address: " + "; ".join(exc.messages)
                )

        password = self._prompt_password(user_model, username=username, email=email)

        # create_superuser() forces is_staff=True and is_superuser=True; the
        # default User model has is_active=True. Standard hashing is applied.
        user_model.objects.create_superuser(
            username=username, email=email, password=password,
        )

        self.stdout.write(self.style.SUCCESS(
            f"Superuser '{username}' created successfully "
            "(is_staff, is_superuser and is_active are all True)."
        ))

    # ------------------------------------------------------------------ #
    # Interactive helpers (kept small so tests can patch input/getpass).   #
    # ------------------------------------------------------------------ #
    def _prompt(self, label):
        return input(f"{label}: ").strip()

    def _prompt_password(self, user_model, *, username, email):
        # An unsaved instance lets the attribute-similarity validator do its job
        # without the password ever being written to the database.
        candidate = user_model(username=username, email=email)
        while True:
            password = getpass.getpass("Password (hidden): ")
            if not password:
                self.stderr.write("Password cannot be empty. Try again.")
                continue
            try:
                validate_password(password, user=candidate)
            except ValidationError as exc:
                for message in exc.messages:
                    self.stderr.write(message)
                continue
            confirm = getpass.getpass("Confirm password (hidden): ")
            if confirm != password:
                self.stderr.write("Passwords do not match. Try again.")
                continue
            return password
