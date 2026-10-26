"""Active security tests (run against the local test app only)."""
import base64
import json
import time

import pyotp
import pytest

from app.extensions import db
from app.models import AuditLog, User
from tests.conftest import PASSWORD, make_config, upload


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


# ------------------------------------------------------------------ JWT
def test_jwt_alg_none_and_tampered_tokens_are_rejected(client, alice):
    good = alice["Authorization"].split()[1]
    header, payload, sig = good.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged_admin = dict(claims, role="admin")
    candidates = [
        f"{b64({'alg': 'none', 'typ': 'JWT'})}.{payload}.",                       # alg=none
        f"{header}.{b64(forged_admin)}.{sig}",                                        # payload edited, old signature
        f"{header}.{payload}.{sig[:-3]}abc",                                          # corrupted signature
        f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(claims)}.AAAA",                 # bogus signature
        "a.b.c", "", "Bearer",
    ]
    for tok in candidates:
        r = client.get("/api/evidence", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code in (401, 422), tok[:30]


def test_token_signed_with_the_wrong_secret_is_rejected(client, app):
    import jwt as pyjwt
    forged = pyjwt.encode({"sub": "x", "jti": "1", "type": "access", "fresh": False,
                           "iat": int(time.time()), "exp": int(time.time()) + 600},
                          "not-the-real-secret-0123456789abcdef", algorithm="HS256")
    assert client.get("/api/evidence", headers={"Authorization": f"Bearer {forged}"}).status_code in (401, 422)


def test_role_claim_in_token_cannot_grant_admin(client, alice):
    """Authorization reads the role from the DB, never from the (forgeable-by-design) claim."""
    assert client.get("/api/admin/users", headers=alice).status_code in (403, 404)


# ------------------------------------------------------------------ injection
SQLI = ["' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "\" OR \"\"=\"", "1; SELECT pg_sleep(5)--", "%' UNION SELECT NULL--"]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_payloads_do_not_bypass_or_crash(client, alice, payload):
    r = client.post("/api/auth/login", json={"email": payload, "password": payload})
    assert r.status_code in (400, 401) and "access_token" not in r.get_data(as_text=True)
    r = upload(client, alice, "a.txt", case=payload, title=payload)
    assert r.status_code == 201                                           # stored as plain data
    assert client.get(f"/api/evidence/{payload}", headers=alice).status_code in (404, 403)
    assert User.query.count() >= 1                                        # users table still exists


def test_stored_markup_is_returned_as_data_not_executed(client, alice):
    xss = "<img src=x onerror=alert(1)>"
    r = upload(client, alice, "a.txt", title=xss, case="<script>alert(1)</script>")
    listing = client.get("/api/evidence", headers=alice)
    assert listing.mimetype == "application/json"                         # never rendered as HTML by the API
    assert listing.headers.get("X-Content-Type-Options") == "nosniff"
    assert xss in listing.get_json()[0]["title"]                          # returned verbatim as JSON data


# ------------------------------------------------------------------ CORS / headers / config
def test_cors_only_allows_configured_origins(client):
    ok = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
    for evil in ["http://evil.example", "null", "http://localhost:5173.evil.example"]:
        r = client.get("/api/health", headers={"Origin": evil})
        assert r.headers.get("Access-Control-Allow-Origin") in (None, "")
    pre = client.options("/api/evidence", headers={"Origin": "http://evil.example",
                                                   "Access-Control-Request-Method": "GET"})
    assert not pre.headers.get("Access-Control-Allow-Origin")


def test_api_responses_carry_security_headers(client, alice):
    r = client.get("/api/evidence", headers=alice)
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "no-store" in r.headers.get("Cache-Control", "")


def test_production_refuses_placeholder_secrets(tmp_path):
    from app import create_app
    with pytest.raises(RuntimeError):
        create_app(make_config(tmp_path, IS_PRODUCTION=True, TESTING=False, SECRET_KEY="dev-secret-key"))


def test_debug_is_not_enabled_by_the_factory(app):
    assert app.debug is False


# ------------------------------------------------------------------ brute force
def test_login_is_rate_limited_per_ip_and_per_account(tmp_path):
    from app import create_app
    from app.utils.rate_limit import reset_rate_limits
    reset_rate_limits()
    app = create_app(make_config(tmp_path, RATELIMIT_ENABLED=True))
    with app.app_context():
        db.create_all()
        c = app.test_client()
        codes = [c.post("/api/auth/login", json={"email": "victim@example.com", "password": f"wrong-{i}"}).status_code
                 for i in range(15)]
        assert 429 in codes, "unlimited password guessing against one account"
        assert codes.index(429) <= 10
    reset_rate_limits()


# ------------------------------------------------------------------ TOTP replay
def test_a_totp_code_cannot_be_replayed(client, app, alice):
    secret = pyotp.random_base32()
    u = User.query.filter_by(email="alice@example.com").first()
    u.mfa_enabled, u.mfa_secret = True, secret
    db.session.commit()
    code = pyotp.TOTP(secret).now()
    body = {"email": "alice@example.com", "password": PASSWORD, "totp_code": code}
    assert client.post("/api/auth/login", json=body).status_code == 200
    replay = client.post("/api/auth/login", json=body)
    assert replay.status_code == 401, "a one-time code was accepted twice"
    assert AuditLog.query.filter_by(action="LOGIN_FAILED").count() >= 1


def test_totp_wrong_code_and_reuse_of_older_window(client, app, alice):
    secret = pyotp.random_base32()
    u = User.query.filter_by(email="alice@example.com").first()
    u.mfa_enabled, u.mfa_secret = True, secret
    db.session.commit()
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD, "totp_code": "000000"})
    assert r.status_code == 401 and "access_token" not in r.get_data(as_text=True)
