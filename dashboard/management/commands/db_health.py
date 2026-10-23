"""Read-only database health check for deployment diagnosis.

Usage on Render (Shell): ``python manage.py db_health``

Prints exactly which database the running process connects to (engine + the
SQLite file path, or the PostgreSQL database name) and whether the expected
tables actually exist. It NEVER prints passwords, secret keys, or the full
DATABASE_URL. This is purely diagnostic: it runs no writes, no migrations and
no destructive operations.
"""
from __future__ import annotations

import os
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Report the live DB engine, resolved path/name, and present tables."

    # Tables that must exist for the site to function. Used by --strict.
    REQUIRED_TABLES = {
        "django_migrations",
        "auth_user",
        "accounts_notificationpreferences",
        "about_teammember",
        "detection_detection",
        "reports_report",
    }

    def add_arguments(self, parser):
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit with status 1 if any required table is missing "
            "(so a deployment build fails on an unmigrated database).",
        )

    def handle(self, *args, **options):
        db = connection.settings_dict
        engine = (db.get("ENGINE") or "").rsplit(".", 1)[-1] or "unknown"
        self.stdout.write(f"DATABASE_URL present : {bool(os.getenv('DATABASE_URL'))}")
        self.stdout.write(f"Engine             : {engine}")

        if "sqlite" in engine:
            name = str(db.get("NAME"))
            exists = Path(name).exists()
            self.stdout.write(f"SQLite file        : {name}")
            self.stdout.write(f"SQLite file exists : {exists}")
        else:
            # Name only. Deliberately omit user/password/host to avoid leaking
            # any part of the connection secret.
            self.stdout.write(f"Database name      : {db.get('NAME')}")

        # Which tables actually exist right now.
        try:
            tables = set(connection.introspection.table_names())
        except Exception as exc:  # connection failure is itself the diagnosis
            self.stderr.write(self.style.ERROR(
                f"Could not introspect tables: {type(exc).__name__}: {exc}"
            ))
            if options.get("strict"):
                raise SystemExit(1)
            return

        expected = [
            "django_migrations",
            "auth_user",
            "auth_permission",
            "django_content_type",
            "django_session",
            "accounts_notificationpreferences",
            "about_teammember",
            "about_contactmessage",
            "detection_detection",
            "reports_report",
            "reports_deliveryattempt",
        ]
        self.stdout.write(f"Total tables found : {len(tables)}")
        self.stdout.write("Key tables:")
        for table in expected:
            mark = "OK   " if table in tables else "MISSING"
            self.stdout.write(f"  [{mark}] {table}")

        if "auth_user" in tables and "about_teammember" in tables:
            self.stdout.write(self.style.SUCCESS(
                "\nSchema looks migrated for the core tables."
            ))
        else:
            self.stdout.write(self.style.WARNING(
                "\nCore tables missing -> run: python manage.py migrate --noinput"
                "\n(against the SAME database this command reports above)."
            ))

        # Strict mode: fail the calling process (e.g. a build) when required
        # tables are still absent. Reports engine/tables only - never secrets.
        missing = sorted(self.REQUIRED_TABLES - tables)
        if missing:
            self.stdout.write("Missing required tables: " + ", ".join(missing))
            if options.get("strict"):
                raise SystemExit(1)
        elif options.get("strict"):
            self.stdout.write(self.style.SUCCESS("All required tables present."))
