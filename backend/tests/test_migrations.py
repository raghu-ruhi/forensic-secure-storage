"""Flask-Migrate migrations against a REAL PostgreSQL (pgserver) and SQLite.

Covers: clean upgrade, schema == models (no drift), data preserved across
0001 -> 0002 on a populated database, downgrade, legacy-DB adoption.
"""
import os
import uuid

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import downgrade, upgrade
from sqlalchemy import create_engine, inspect, text

from app import create_app
from app.config import Config
from app.extensions import db
from app.migration_adopt import adopt_legacy_schema

pgserver = pytest.importorskip("pgserver")
MIGRATIONS = os.path.join(os.path.dirname(__file__), "..", "migrations")


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    server = pgserver.get_server(str(tmp_path_factory.mktemp("pg")))
    yield server
    server.cleanup()


@pytest.fixture()
def pg_app(pg, tmp_path):
    name = "m_" + uuid.uuid4().hex[:10]
    pg.psql(f"CREATE DATABASE {name};")
    uri = pg.get_uri().replace("/postgres?", f"/{name}?")
    cfg = type("C", (Config,), dict(TESTING=True, SQLALCHEMY_DATABASE_URI=uri,
                                    SECRET_KEY="k" * 32, JWT_SECRET_KEY="j" * 32,
                                    STORAGE_PATH=str(tmp_path), MASTER_KEY_PATH=str(tmp_path / "m.key")))
    app = create_app(cfg)
    with app.app_context():
        yield app
        db.session.remove()
        db.engine.dispose()


def drift():
    """Differences between the live (migrated) schema and the SQLAlchemy models."""
    with db.engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(ctx, db.metadata)


def test_clean_upgrade_creates_exactly_the_model_schema(pg_app):
    upgrade(directory=MIGRATIONS)
    tables = set(inspect(db.engine).get_table_names())
    assert {"users", "evidence", "key_records", "ledger_blocks", "audit_logs",
            "digital_signatures", "alembic_version"} <= tables
    assert drift() == [], f"models and migrations disagree: {drift()}"


def test_existing_accounts_and_evidence_survive_the_upgrade(pg_app):
    upgrade(directory=MIGRATIONS, revision="0001")  # the schema the ORIGINAL app produced
    uid, eid = str(uuid.uuid4()), str(uuid.uuid4())
    with db.engine.begin() as c:
        c.execute(text("""INSERT INTO users (id, full_name, email, password_hash, role, is_active,
                          reset_otp_attempts, reset_otp_verified)
                          VALUES (:i,'Old User','old@example.com','hash','investigator',true,0,false)"""), {"i": uid})
        c.execute(text("""INSERT INTO evidence (id, case_number, title, original_filename, encrypted_filename,
                          file_size_bytes, sha256_hash, encryption_key_id, uploader_id)
                          VALUES (:e,'CASE-1','Old evidence','a.txt','a.enc',5,:h,'k',:u)"""),
                  {"e": eid, "u": uid, "h": "a" * 64})
    upgrade(directory=MIGRATIONS)  # 0001 -> head with data present
    with db.engine.connect() as c:
        user = c.execute(text("SELECT email, otp_attempts, otp_send_count, otp_hash FROM users")).one()
        ev = c.execute(text("SELECT sha256_hash, storage_backend, mime_type FROM evidence")).one()
    assert tuple(user) == ("old@example.com", 0, 0, None)
    assert tuple(ev) == ("a" * 64, "local", None)
    assert drift() == []


def test_downgrade_to_baseline_keeps_data(pg_app):
    upgrade(directory=MIGRATIONS)
    uid = str(uuid.uuid4())
    with db.engine.begin() as c:
        c.execute(text("""INSERT INTO users (id, full_name, email, password_hash, role, is_active,
                          reset_otp_attempts, reset_otp_verified, otp_attempts, otp_send_count, reset_otp_send_count)
                          VALUES (:i,'U','u@example.com','h','investigator',true,0,false,0,0,0)"""), {"i": uid})
    downgrade(directory=MIGRATIONS, revision="0001")
    cols = {c["name"] for c in inspect(db.engine).get_columns("users")}
    assert "otp_hash" not in cols and "email" in cols
    with db.engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM users")).scalar() == 1


def test_adoption_of_database_built_by_create_all(pg_app):
    """Simulates an old deployment: tables exist, no alembic_version."""
    db.create_all()
    assert adopt_legacy_schema(MIGRATIONS) == "stamped-0004"  # current models include everything
    assert adopt_legacy_schema(MIGRATIONS) == "already-managed"
    upgrade(directory=MIGRATIONS)  # must be a no-op, not "relation already exists"
    assert drift() == []


def test_adoption_of_release_with_logout_but_without_totp_guard(pg_app):
    upgrade(directory=MIGRATIONS, revision="0003")
    with db.engine.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))
    assert adopt_legacy_schema(MIGRATIONS) == "stamped-0003"
    upgrade(directory=MIGRATIONS)
    assert "mfa_last_used_step" in {c["name"] for c in inspect(db.engine).get_columns("users")} and drift() == []


def test_adoption_of_otp_fix_release_schema_then_upgrade(pg_app):
    """A DB from the previous release: has otp_hash, lacks revoked_tokens."""
    upgrade(directory=MIGRATIONS, revision="0002")
    with db.engine.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))
    assert adopt_legacy_schema(MIGRATIONS) == "stamped-0002"
    upgrade(directory=MIGRATIONS)
    assert "revoked_tokens" in inspect(db.engine).get_table_names() and drift() == []


def test_adoption_of_original_release_schema_then_upgrade(pg_app):
    upgrade(directory=MIGRATIONS, revision="0001")
    with db.engine.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))  # as if never managed
    assert adopt_legacy_schema(MIGRATIONS) == "stamped-0001"
    upgrade(directory=MIGRATIONS)
    assert drift() == []


def test_fresh_database_is_detected(pg_app):
    assert adopt_legacy_schema(MIGRATIONS) == "fresh"


def test_app_startup_does_not_create_tables(pg_app):
    """Schema is managed only by migrations: creating the app must not touch it."""
    assert inspect(db.engine).get_table_names() == []


def test_sqlite_clean_upgrade(tmp_path):
    cfg = type("C", (Config,), dict(TESTING=True, SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path/'m.db'}",
                                    SECRET_KEY="k" * 32, JWT_SECRET_KEY="j" * 32,
                                    STORAGE_PATH=str(tmp_path), MASTER_KEY_PATH=str(tmp_path / "m.key")))
    app = create_app(cfg)
    with app.app_context():
        upgrade(directory=MIGRATIONS)
        assert drift() == []
        db.session.remove()
        db.engine.dispose()
