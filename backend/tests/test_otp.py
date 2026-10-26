"""Signup OTP and forgot-password OTP flows (scenarios 1-8 of the task)."""
import logging
import re
import smtplib
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import AuditLog, User
from app.services import otp_service
from app.services.otp_service import check_otp, generate_otp, get_outbox, hash_otp
from app.utils.rate_limit import reset_rate_limits
from tests.conftest import PASSWORD, create_verified_user, last_code, login, register


def get_user(email):
    return User.query.filter_by(email=email).first()


# ---------------------------------------------------------------- generation
def test_otp_is_six_digits_from_secrets_module(monkeypatch):
    codes = {generate_otp() for _ in range(2000)}
    assert all(re.fullmatch(r"\d{6}", c) for c in codes)
    assert len(codes) > 1900  # not a constant / tiny space
    assert any(c.startswith("0") for c in codes)  # leading zeros preserved

    calls = []
    real = otp_service.secrets.randbelow
    monkeypatch.setattr(otp_service.secrets, "randbelow", lambda n: calls.append(n) or real(n))
    generate_otp()
    assert calls == [10 ** 6], "OTP must come from secrets.randbelow"


def test_otp_hash_is_bound_to_purpose_and_address(app):
    h = hash_otp("123456", "signup", "a@example.com")
    assert check_otp(h, "123456", "signup", "a@example.com")
    assert not check_otp(h, "123456", "password-reset", "a@example.com")  # cross-flow replay
    assert not check_otp(h, "123456", "signup", "b@example.com")          # cross-account replay
    assert not check_otp(h, "654321", "signup", "a@example.com")


# ---------------------------------------------------------------- signup
def test_signup_emails_otp_to_the_signup_address_and_never_returns_it(client, app):
    r = register(client, "alice@example.com")
    assert r.status_code == 201
    body = r.get_json()
    assert body["email_sent"] is True

    outbox = get_outbox()
    assert len(outbox) == 1
    assert outbox[0]["To"] == "alice@example.com"
    assert "verification code" in outbox[0]["Subject"]
    code = last_code(app)

    # The OTP must not appear anywhere in the API response ...
    assert code not in r.get_data(as_text=True)
    assert "dev_otp_hint" not in body
    # ... nor in plaintext in the database.
    user = get_user("alice@example.com")
    assert user.otp_code is None
    assert user.otp_hash and code not in user.otp_hash


def test_signup_succeeds_only_after_verification(client, app):
    register(client, "alice@example.com")
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    assert r.status_code == 403 and r.get_json()["code"] == "EMAIL_NOT_VERIFIED"

    v = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": last_code(app)})
    assert v.status_code == 200
    assert get_user("alice@example.com").is_email_verified is True
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD}).status_code == 200


def test_wrong_otp_rejected_and_locks_out_after_max_attempts(client, app):
    register(client, "alice@example.com")
    good = last_code(app)
    wrong = "000000" if good != "000000" else "111111"

    first = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": wrong})
    assert first.status_code == 400 and "4 attempt" in first.get_json()["error"]
    for _ in range(3):
        client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": wrong})
    locked = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": wrong})
    assert locked.status_code == 429 and locked.get_json()["code"] == "OTP_LOCKED"

    # Even the correct code is dead after a lockout - a new one must be requested.
    r = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": good})
    assert r.status_code == 400 and not get_user("alice@example.com").is_email_verified


def test_expired_otp_rejected(client, app):
    register(client, "alice@example.com")
    code = last_code(app)
    user = get_user("alice@example.com")
    user.otp_expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.session.commit()

    r = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": code})
    assert r.status_code == 400 and r.get_json()["code"] == "OTP_EXPIRED"
    assert not get_user("alice@example.com").is_email_verified


def test_verified_otp_cannot_be_reused(client, app):
    register(client, "alice@example.com")
    code = last_code(app)
    assert client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": code}).status_code == 200
    again = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": code})
    assert again.status_code == 400 and again.get_json()["code"] == "ALREADY_VERIFIED"
    assert get_user("alice@example.com").otp_hash is None


def test_malformed_otp_input_is_rejected_cleanly(client, app):
    register(client, "alice@example.com")
    for bad in ["", "12345", "abcdef", "1234567", None, 123456, ["1"]]:
        r = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": bad})
        assert r.status_code == 400, bad
    assert client.post("/api/auth/verify-otp", data="not json", content_type="text/plain").status_code == 400
    assert client.post("/api/auth/verify-otp", json=["list"]).status_code == 400


def test_resend_cooldown_new_code_invalidates_old_one(client, app):
    register(client, "alice@example.com")
    first = last_code(app)

    r = client.post("/api/auth/resend-otp", json={"email": "alice@example.com"})
    assert r.status_code == 429 and r.get_json()["retry_after"] > 0
    assert len(get_outbox()) == 1  # nothing extra was sent

    user = get_user("alice@example.com")
    user.otp_last_sent_at = datetime.utcnow() - timedelta(seconds=61)
    db.session.commit()
    r = client.post("/api/auth/resend-otp", json={"email": "alice@example.com"})
    assert r.status_code == 200 and r.get_json()["email_sent"] is True
    second = last_code(app)

    if second != first:  # (1-in-a-million collision otherwise)
        stale = client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": first})
        assert stale.status_code == 400
    assert client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": second}).status_code == 200


def test_hourly_send_cap(client, app):
    register(client, "alice@example.com")
    user = get_user("alice@example.com")
    user.otp_last_sent_at = datetime.utcnow() - timedelta(minutes=5)
    user.otp_send_window_start = datetime.utcnow() - timedelta(minutes=30)
    user.otp_send_count = app.config["OTP_MAX_SENDS_PER_HOUR"]
    db.session.commit()
    r = client.post("/api/auth/resend-otp", json={"email": "alice@example.com"})
    assert r.status_code == 429 and "minute" in r.get_json()["error"]


def test_reregistering_an_unverified_address_is_allowed_verified_is_not(client, app):
    register(client, "alice@example.com", password="FirstPassword-1")
    user = get_user("alice@example.com")
    user.otp_last_sent_at = None  # skip the cooldown for this test
    db.session.commit()
    r = register(client, "alice@example.com", password="SecondPassword-2")
    assert r.status_code == 201
    code = last_code(app)
    client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": code})
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "SecondPassword-2"}).status_code == 200
    assert register(client, "alice@example.com").status_code == 409


def test_input_validation_on_register(client):
    assert register(client, "not-an-email").status_code == 400
    assert register(client, "a@example.com", password="short").status_code == 400
    assert register(client, "a@example.com", password="x" * 80).status_code == 400  # >72 bytes (bcrypt 5)
    assert client.post("/api/auth/register", json={"email": "a@example.com"}).status_code == 400


# ---------------------------------------------------------------- delivery failures
def _fail_with(monkeypatch, exc):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(otp_service, "send_email", boom)


def test_send_failure_is_reported_honestly_not_as_success(client, app, monkeypatch, caplog):
    _fail_with(monkeypatch, smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted"))
    with caplog.at_level(logging.INFO):
        r = register(client, "alice@example.com")
    body = r.get_json()
    assert r.status_code == 502
    assert body["email_sent"] is False and body["code"] == "EMAIL_SEND_FAILED"
    assert body["account_created"] is True
    assert "App Password" in body["mail_error"]  # actionable, categorised hint (non-production only)
    assert not re.search(r"\b\d{6}\b", r.get_data(as_text=True))  # no OTP anywhere in the response

    # The user is not stuck: no cooldown was burned and the undelivered code is void.
    user = get_user("alice@example.com")
    assert user.otp_hash is None and user.otp_last_sent_at is None
    # The server log explains the failure without secrets.
    assert "OTP email not delivered" in caplog.text and "SMTPAuthenticationError" in caplog.text
    assert "test-smtp-password" not in caplog.text


def test_resend_failure_is_not_reported_as_sent(client, app, monkeypatch):
    register(client, "alice@example.com")
    user = get_user("alice@example.com")
    user.otp_last_sent_at = None
    db.session.commit()
    _fail_with(monkeypatch, ConnectionRefusedError())
    r = client.post("/api/auth/resend-otp", json={"email": "alice@example.com"})
    assert r.status_code == 502 and r.get_json()["email_sent"] is False


def test_production_mode_hides_mail_diagnostics_from_clients(tmp_path, monkeypatch):
    from app import create_app
    from tests.conftest import make_config
    prod = create_app(make_config(tmp_path, IS_PRODUCTION=True))
    with prod.app_context():
        db.create_all()
        _fail_with(monkeypatch, ConnectionRefusedError())
        r = prod.test_client().post("/api/auth/register", json={
            "full_name": "A", "email": "a@example.com", "password": PASSWORD})
        assert r.status_code == 502 and "mail_error" not in r.get_json()


# ---------------------------------------------------------------- forgot password
def reset_flow_user(client, app):
    create_verified_user(client, app, "alice@example.com")
    get_outbox().clear()


def test_forgot_password_emails_reset_code_to_registered_address(client, app):
    reset_flow_user(client, app)
    r = client.post("/api/auth/forgot-password", json={"email": "Alice@Example.com"})
    assert r.status_code == 200 and r.get_json()["success"] is True
    msg = get_outbox()[-1]
    assert msg["To"] == "alice@example.com" and "password reset" in msg["Subject"]
    code = last_code(app)
    assert code not in r.get_data(as_text=True)
    user = get_user("alice@example.com")
    assert user.reset_otp_hash and code not in user.reset_otp_hash


def test_forgot_password_unknown_email_sends_nothing(client, app):
    r = client.post("/api/auth/forgot-password", json={"email": "ghost@example.com"})
    assert r.status_code == 404 and not get_outbox()


def test_full_password_reset_flow_and_single_use(client, app):
    reset_flow_user(client, app)
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    code = last_code(app)

    v = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": code})
    assert v.status_code == 200
    token = v.get_json()["reset_token"]

    # OTP is single use
    replay = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": code})
    assert replay.status_code == 400

    r = client.post("/api/auth/reset-password", json={
        "email": "alice@example.com", "reset_token": token, "new_password": "BrandNewPass-7"})
    assert r.status_code == 200
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "BrandNewPass-7"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD}).status_code == 401

    # reset token is single use too
    again = client.post("/api/auth/reset-password", json={
        "email": "alice@example.com", "reset_token": token, "new_password": "AnotherPass-8"})
    assert again.status_code == 400


def test_reset_requires_valid_otp_verification_first(client, app):
    reset_flow_user(client, app)
    body = {"email": "alice@example.com", "reset_token": "made-up-token", "new_password": "HackerPass-1"}

    # 1) no reset requested at all
    assert client.post("/api/auth/reset-password", json=body).status_code == 400
    # 2) reset requested but OTP not yet verified
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    assert client.post("/api/auth/reset-password", json=body).status_code == 400
    # 3) OTP verified, but a guessed/forged token is used
    code = last_code(app)
    client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": code})
    assert client.post("/api/auth/reset-password", json=body).status_code == 400
    # 4) a real token for a DIFFERENT account must not work
    create_verified_user(client, app, "mallory@example.com", "Mallory")
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "HackerPass-1"}).status_code == 401


def test_reset_otp_wrong_code_and_expiry_and_lockout(client, app):
    reset_flow_user(client, app)
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    good = last_code(app)
    wrong = "000000" if good != "000000" else "111111"
    r = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": wrong})
    assert r.status_code == 400 and r.get_json()["code"] == "OTP_INVALID"

    user = get_user("alice@example.com")
    user.reset_otp_expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.session.commit()
    r = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": good})
    assert r.status_code == 400 and r.get_json()["code"] == "OTP_EXPIRED"

    user = get_user("alice@example.com")
    user.reset_otp_last_sent_at = None
    db.session.commit()
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    good = last_code(app)
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(4):
        client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": wrong})
    r = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": wrong})
    assert r.status_code == 429
    assert client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": good}).status_code == 400


def test_signup_otp_cannot_be_used_to_reset_a_password(client, app):
    """A code issued for signup is cryptographically bound to the signup purpose:
    even if it were planted as the reset hash, it is rejected by the reset flow."""
    reset_flow_user(client, app)
    user = get_user("alice@example.com")
    user.reset_otp_hash = hash_otp("424242", "signup", "alice@example.com")  # wrong purpose
    user.reset_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    r = client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": "424242"})
    assert r.status_code == 400 and r.get_json()["code"] == "OTP_INVALID"

    user = get_user("alice@example.com")
    user.reset_otp_hash = hash_otp("424242", "password-reset", "alice@example.com")  # right purpose
    db.session.commit()
    assert client.post("/api/auth/verify-reset-otp", json={"email": "alice@example.com", "otp_code": "424242"}).status_code == 200


def test_forgot_password_cooldown_and_failure_reporting(client, app, monkeypatch):
    reset_flow_user(client, app)
    assert client.post("/api/auth/forgot-password", json={"email": "alice@example.com"}).status_code == 200
    r = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    assert r.status_code == 429 and r.get_json()["retry_after"] > 0

    user = get_user("alice@example.com")
    user.reset_otp_last_sent_at = None
    db.session.commit()
    _fail_with(monkeypatch, smtplib.SMTPServerDisconnected())
    r = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    assert r.status_code == 502 and r.get_json()["success"] is False


# ---------------------------------------------------------------- misc security
def test_secrets_never_reach_the_logs(client, app, caplog):
    with caplog.at_level(logging.DEBUG):
        register(client, "alice@example.com")
        code = last_code(app)
        client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": code})
        client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
        reset_code = last_code(app)
    assert code not in caplog.text and reset_code not in caplog.text
    assert app.config["MAIL_PASSWORD"] not in caplog.text


def test_per_ip_rate_limit_on_otp_endpoints(tmp_path):
    from app import create_app
    from tests.conftest import make_config
    reset_rate_limits()
    app = create_app(make_config(tmp_path, RATELIMIT_ENABLED=True))
    with app.app_context():
        db.create_all()
        c = app.test_client()
        codes = [c.post("/api/auth/forgot-password", json={"email": f"u{i}@example.com"}).status_code
                 for i in range(12)]
        assert codes[:10] == [404] * 10 and codes[10:] == [429, 429]
    reset_rate_limits()


def test_admin_email_diagnostics_never_leaks_credentials(client, app, admin):
    r = client.get("/api/auth/email-diagnostics", headers=admin)
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert app.config["MAIL_PASSWORD"] not in text and "sender@example.com" not in text
    assert client.get("/api/auth/email-diagnostics").status_code == 401


def test_audit_trail_records_otp_events(client, app):
    register(client, "alice@example.com")
    client.post("/api/auth/verify-otp", json={"email": "alice@example.com", "otp_code": last_code(app)})
    actions = {a.action for a in AuditLog.query.all()}
    assert {"REGISTER", "VERIFY_OTP"} <= actions
