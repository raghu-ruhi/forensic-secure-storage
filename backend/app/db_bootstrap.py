"""First-admin seeding.

Schema management used to live here (``db.create_all()`` plus hand-written
``ALTER TABLE``). It has been replaced by Flask-Migrate: run
``flask db upgrade`` (see docs/MIGRATIONS.md). Nothing in this module touches
the schema any more.

``seed_initial_admin()`` optionally creates the very first Admin account from
ADMIN_EMAIL / ADMIN_PASSWORD, but ONLY if no admin exists yet. It is never
triggered by an HTTP request.
"""
import os
from app.extensions import db, bcrypt

def seed_initial_admin():
    """Create the first Admin account, but only when:
      1. ADMIN_EMAIL and ADMIN_PASSWORD are both set in the environment, and
      2. No admin account exists in the database yet.

    This never overwrites or resets an existing admin's password, and it is
    never triggered by any HTTP request - only by whoever controls the
    server's environment/.env at deploy time.
    """
    from app.models import User  # local import: avoid circulars at module load

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    admin_full_name = os.environ.get("ADMIN_FULL_NAME", "System Administrator").strip()

    if not admin_email or not admin_password:
        return  # bootstrap admin not configured - nothing to do

    if User.query.filter_by(role="admin").first():
        return  # an admin already exists - never auto-create a second one

    if User.query.filter_by(email=admin_email).first():
        print(f"[db_bootstrap] ADMIN_EMAIL '{admin_email}' is already registered as a "
              f"non-admin account; skipping admin seed. Use create_admin.py to promote it "
              f"manually if that's what you intended.")
        return

    if len(admin_password) < 8:
        print("[db_bootstrap] ADMIN_PASSWORD is too short (min 8 chars); skipping admin seed.")
        return

    admin = User(
        full_name=admin_full_name,
        email=admin_email,
        password_hash=bcrypt.generate_password_hash(admin_password).decode("utf-8"),
        role="admin",
        is_email_verified=True,
        is_active=True,
    )
    db.session.add(admin)
    db.session.commit()
    print(f"[db_bootstrap] Created initial admin account for {admin_email}.")
