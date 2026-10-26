"""One-time adoption of databases created BEFORE Flask-Migrate was introduced.

Old deployments built their schema with ``db.create_all()``. ``flask db
upgrade`` would fail on them ("relation already exists"). This helper detects
that situation and only *stamps* the matching revision in ``alembic_version``
(it never creates, alters or drops anything), after which ``flask db upgrade``
brings the schema the rest of the way:

  * no tables at all                         -> nothing to do (fresh DB)
  * tables exist, no alembic_version table:
        users.mfa_last_used_step-> stamp 0004  (DB built by create_all from the current models)
        revoked_tokens table    -> stamp 0003  (DB built by create_all from the current models)
        users.otp_hash present  -> stamp 0002  (DB from the OTP-fix release)
        otherwise               -> stamp 0001  (DB from the original release)
"""
from flask_migrate import stamp
from sqlalchemy import inspect

from app.extensions import db


def adopt_legacy_schema(directory: str = "migrations") -> str:
    """Returns one of: 'fresh', 'already-managed', 'stamped-0001', 'stamped-0002', 'stamped-0003', 'stamped-0004'."""
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    if "alembic_version" in tables:
        return "already-managed"
    if "users" not in tables:
        return "fresh"
    columns = {c["name"] for c in inspector.get_columns("users")}
    revision = "0004" if "mfa_last_used_step" in columns else "0003" if "revoked_tokens" in tables else ("0002" if "otp_hash" in columns else "0001")
    stamp(directory=directory, revision=revision)
    return f"stamped-{revision}"
