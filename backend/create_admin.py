#!/usr/bin/env python3
"""Create (or promote) an Admin account, from the command line only.

This is intentionally NOT an HTTP endpoint. There is no way to create an
Admin account by sending a request to the running server - the only two
ways an Admin account can come into existence are:

  1. This script, run directly on the machine/container that has access
     to the database (docker compose exec backend python create_admin.py), or
  2. seed_initial_admin() at startup, driven by ADMIN_EMAIL / ADMIN_PASSWORD
     in the environment - and only when no admin exists yet.

Usage:
    python create_admin.py --email admin@agency.gov --name "Jane Admin"
    (you'll be prompted for a password, hidden, via getpass)

    or non-interactively:
    ADMIN_EMAIL=admin@agency.gov ADMIN_PASSWORD=... python create_admin.py
"""
import argparse
import getpass
import sys

from app import create_app
from app.extensions import db, bcrypt
from app.models import User


def main():
    parser = argparse.ArgumentParser(description="Create an Admin account for Forensic Secure Storage.")
    parser.add_argument("--email", help="Admin email address")
    parser.add_argument("--name", default="System Administrator", help="Admin full name")
    parser.add_argument("--password", help="Admin password (omit to be prompted securely)")
    parser.add_argument("--force", action="store_true",
                         help="Allow creating an admin even if one already exists")
    args = parser.parse_args()

    email = (args.email or input("Admin email: ")).strip().lower()
    if not email:
        print("Email is required.", file=sys.stderr)
        sys.exit(1)

    password = args.password or getpass.getpass("Admin password (min 8 chars): ")
    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    app = create_app()
    with app.app_context():
        existing_admin = User.query.filter_by(role="admin").first()
        if existing_admin and not args.force:
            print(f"An admin account already exists ({existing_admin.email}). "
                  f"Re-run with --force if you really want to create another one.",
                  file=sys.stderr)
            sys.exit(1)

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"Promoting existing account {email} to admin.")
            existing_user.role = "admin"
            existing_user.is_active = True
            existing_user.is_email_verified = True
            existing_user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            db.session.commit()
            print("Done.")
            return

        admin = User(
            full_name=args.name.strip() or "System Administrator",
            email=email,
            password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
            role="admin",
            is_email_verified=True,
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin account created for {email}.")


if __name__ == "__main__":
    main()
