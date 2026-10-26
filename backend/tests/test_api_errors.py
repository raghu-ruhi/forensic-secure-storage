"""API error handling and hardening behaviour."""
from tests.conftest import upload


def test_unknown_route_and_wrong_method_return_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.is_json
    r = client.get("/api/auth/login")
    assert r.status_code == 405 and r.is_json


def test_malformed_json_bodies_do_not_crash(client):
    for path in ["/api/auth/login", "/api/auth/register", "/api/auth/forgot-password", "/api/auth/verify-otp"]:
        for body, ctype in [("{bad json", "application/json"), ("[]", "application/json"), ("", "application/json")]:
            r = client.post(path, data=body, content_type=ctype)
            assert r.status_code in (400, 401, 404, 429), (path, body, r.status_code)
            assert r.is_json


def test_health_endpoint(client):
    assert client.get("/api/health").status_code == 200


def test_invalid_and_expired_tokens_are_rejected(client, app):
    assert client.get("/api/evidence", headers={"Authorization": "Bearer garbage"}).status_code in (401, 422)
    assert client.get("/api/evidence", headers={"Authorization": "Basic abc"}).status_code in (401, 422)
    from flask_jwt_extended import create_access_token
    from datetime import timedelta
    with app.app_context():
        expired = create_access_token(identity="x", expires_delta=timedelta(seconds=-1))
    assert client.get("/api/evidence", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_token_for_a_deleted_user_is_rejected(client, app, alice):
    from app.extensions import db
    from app.models import User
    User.query.filter_by(email="alice@example.com").delete()
    db.session.commit()
    assert client.get("/api/evidence", headers=alice).status_code == 401


def test_logout_revokes_the_token(client, alice):
    assert client.post("/api/auth/logout", headers=alice).status_code == 200
    assert client.get("/api/evidence", headers=alice).status_code == 401


def test_admin_endpoints_reject_non_admins(client, alice):
    for method, path in [("get", "/api/admin/invigilators"), ("get", "/api/admin/users"),
                         ("post", "/api/admin/invigilators")]:
        r = getattr(client, method)(path, headers=alice)
        assert r.status_code in (403, 404, 405), (path, r.status_code)


def test_registration_cannot_self_assign_admin(client, app):
    from app.models import User
    client.post("/api/auth/register", json={"full_name": "X", "email": "x@example.com",
                                            "password": "CorrectHorse-9", "role": "admin"})
    assert User.query.filter_by(email="x@example.com").one().role == "investigator"


def test_responses_never_contain_password_hashes_or_secrets(client, alice):
    body = client.get("/api/auth/me", headers=alice).get_data(as_text=True)
    for forbidden in ["password_hash", "mfa_secret", "rsa_private", "otp_hash", "reset_token_hash", "secret_key"]:
        assert forbidden not in body
