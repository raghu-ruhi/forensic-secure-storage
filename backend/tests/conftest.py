"""Shared fixtures. Tests run against a throw-away SQLite database and a
temporary storage directory, with outgoing mail captured in memory
(MAIL_SUPPRESS_SEND) - except tests/test_smtp_transport.py, which talks to a
real local SMTP server to exercise the actual smtplib/STARTTLS/AUTH code."""
import io
import re
import struct
import zlib

import pytest

from app import create_app
from app.config import Config
from app.extensions import db
from app.models import User
from app.services.otp_service import get_outbox
from app.utils.rate_limit import reset_rate_limits

PASSWORD = "CorrectHorse-9"


def make_config(tmp_path, **overrides):
    values = dict(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        STORAGE_PATH=str(tmp_path / "storage"),
        MASTER_KEY_PATH=str(tmp_path / "storage" / "master.key"),
        NODE_A_PATH=str(tmp_path / "storage" / "node_a"),
        NODE_B_PATH=str(tmp_path / "storage" / "node_b"),
        NODE_C_PATH=str(tmp_path / "storage" / "node_c"),
        SECRET_KEY="test-secret-key-0123456789abcdef",
        JWT_SECRET_KEY="test-jwt-secret-key-0123456789abcdef",
        MAIL_SUPPRESS_SEND=True,
        MAIL_USERNAME="sender@example.com",
        MAIL_PASSWORD="test-smtp-password-NEVER-LOG-ME",
        MAIL_DEFAULT_SENDER="sender@example.com",
        RATELIMIT_ENABLED=False,
    )
    values.update(overrides)
    return type("TestConfig", (Config,), values)


@pytest.fixture()
def app(tmp_path):
    reset_rate_limits()
    application = create_app(make_config(tmp_path))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------- helpers
def last_code(app, to=None):
    """The 6-digit code from the newest captured e-mail (to `to`, if given)."""
    messages = [m for m in get_outbox() if to is None or m["To"] == to]
    assert messages, "no email was sent"
    match = re.search(r"code is: (\d{6})", messages[-1].get_content())
    assert match, "no OTP found in the email body"
    return match.group(1)


def register(client, email="alice@example.com", name="Alice", password=PASSWORD):
    return client.post("/api/auth/register", json={"full_name": name, "email": email, "password": password})


def create_verified_user(client, app, email="alice@example.com", name="Alice", password=PASSWORD):
    assert register(client, email, name, password).status_code == 201
    r = client.post("/api/auth/verify-otp", json={"email": email, "otp_code": last_code(app, email)})
    assert r.status_code == 200, r.get_json()


def login(client, email="alice@example.com", password=PASSWORD):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_json()
    return {"Authorization": f"Bearer {r.get_json()['access_token']}"}


@pytest.fixture()
def alice(client, app):
    create_verified_user(client, app, "alice@example.com", "Alice")
    return login(client, "alice@example.com")


@pytest.fixture()
def bob(client, app):
    create_verified_user(client, app, "bob@example.com", "Bob")
    return login(client, "bob@example.com")


@pytest.fixture()
def admin(client, app):
    from app.extensions import bcrypt
    user = User(full_name="Admin", email="admin@example.com", role="admin", is_email_verified=True,
                password_hash=bcrypt.generate_password_hash(PASSWORD).decode())
    db.session.add(user)
    db.session.commit()
    return login(client, "admin@example.com")


def png_bytes(width=4, height=4):
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


PDF_BYTES = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
             b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
             b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 72 72]>>endobj\n"
             b"trailer<</Root 1 0 R>>\n%%EOF\n")


def upload(client, headers, filename="notes.txt", content=b"chain of custody notes\n",
           case="CASE-1", title="Test evidence"):
    return client.post(
        "/api/evidence/upload", headers=headers, content_type="multipart/form-data",
        data={"case_number": case, "title": title, "description": "d",
              "file": (io.BytesIO(content), filename)},
    )
