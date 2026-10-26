"""Evidence upload / view / download, integrity and access control
(scenarios 9-16 of the task)."""
import glob
import hashlib
import io
import os

from app.extensions import db
from app.models import AuditLog, Evidence, LedgerBlock
from tests.conftest import PDF_BYTES, png_bytes, upload


def actions():
    return [a.action for a in AuditLog.query.order_by(AuditLog.created_at).all()]


def storage_files(app):
    root = app.config["STORAGE_PATH"]
    return [p for p in glob.glob(os.path.join(root, "**", "*"), recursive=True) if os.path.isfile(p)]


# ---------------------------------------------------------------- upload
def test_upload_supported_file_stores_hash_and_ciphertext_only(client, app, alice):
    content = b"top secret evidence\n" * 50
    r = upload(client, alice, "notes.txt", content)
    assert r.status_code == 201, r.get_json()
    ev = r.get_json()["evidence"]
    assert ev["sha256_hash"] == hashlib.sha256(content).hexdigest()
    assert ev["file_size_bytes"] == len(content)
    assert ev["original_filename"] == "notes.txt" and ev["mime_type"] == "text/plain"
    assert ev["previewable"] is True and ev["uploader_id"]

    files = storage_files(app)
    assert files, "ciphertext should be on disk"
    for path in files:
        if path.endswith("master.key"):
            continue
        assert b"top secret evidence" not in open(path, "rb").read(), f"plaintext found in {path}"
        assert not path.endswith("_raw"), "temporary plaintext was not removed"
    # private storage: nothing is exposed under a static/public route
    assert client.get("/uploads/" + os.path.basename(files[0])).status_code == 404
    assert "UPLOAD_EVIDENCE" in actions()
    assert LedgerBlock.query.filter_by(evidence_id=ev["id"], event_type="UPLOAD").count() == 1


def test_upload_requires_authentication(client):
    assert upload(client, {}).status_code == 401


def test_upload_rejects_unsupported_type_empty_and_missing_extension(client, app, alice):
    r = upload(client, alice, "malware.exe", b"MZ\x90\x00")
    assert r.status_code == 415 and r.get_json()["code"] == "UNSUPPORTED_TYPE"
    assert upload(client, alice, "page.html", b"<script>alert(1)</script>").status_code == 415
    assert upload(client, alice, "image.svg", b"<svg onload=alert(1)>").status_code == 415
    assert upload(client, alice, "noextension", b"abc").get_json()["code"] == "MISSING_EXTENSION"
    r = upload(client, alice, "empty.txt", b"")
    assert r.status_code == 400 and r.get_json()["code"] == "EMPTY_FILE"
    assert Evidence.query.count() == 0
    assert all(p.endswith("master.key") for p in storage_files(app)), "rejected uploads must leave nothing on disk"
    assert actions().count("UPLOAD_REJECTED") >= 4


def test_upload_rejects_content_that_does_not_match_extension(client, alice):
    r = upload(client, alice, "photo.png", b"MZ this is really an executable")
    assert r.status_code == 415 and r.get_json()["code"] == "CONTENT_MISMATCH"
    assert upload(client, alice, "doc.pdf", b"not a pdf at all").status_code == 415
    assert upload(client, alice, "ok.png", png_bytes()).status_code == 201


def test_upload_rejects_oversized_files(tmp_path):
    from app import create_app
    from tests.conftest import make_config, create_verified_user, login
    app = create_app(make_config(tmp_path, MAX_UPLOAD_MB=1, MAX_CONTENT_LENGTH=2 * 1024 * 1024))
    with app.app_context():
        db.create_all()
        c = app.test_client()
        create_verified_user(c, app, "a@example.com")
        h = login(c, "a@example.com")
        r = upload(c, h, "big.bin", b"\x00" * (1024 * 1024 + 10))            # just over the app limit
        assert r.status_code == 413 and r.get_json()["code"] == "FILE_TOO_LARGE"
        r = upload(c, h, "huge.bin", b"\x00" * (3 * 1024 * 1024))            # over the request-size cap
        assert r.status_code == 413 and "maximum" in r.get_json()["error"]
        assert Evidence.query.count() == 0
        assert upload(c, h, "ok.bin", b"\x01" * 1000).status_code == 201


def test_hostile_filenames_are_neutralised_and_never_used_as_paths(client, app, alice):
    for bad in ["../../etc/passwd.txt", "..\\..\\windows\\system.txt", "/abs/path/evil.txt", "a\x00b.txt"]:
        r = upload(client, alice, bad)
        assert r.status_code in (201, 400, 415), (bad, r.status_code)
        if r.status_code == 201:
            name = r.get_json()["evidence"]["original_filename"]
            assert "/" not in name and "\\" not in name and ".." not in name and "\x00" not in name
    root = os.path.realpath(app.config["STORAGE_PATH"])
    for p in storage_files(app):
        assert os.path.realpath(p).startswith(root)


def test_validation_rules_endpoint(client, alice):
    r = client.get("/api/evidence/upload-rules", headers=alice)
    body = r.get_json()
    assert r.status_code == 200 and body["max_upload_mb"] == 50
    assert "pdf" in body["allowed_extensions"] and "exe" not in body["allowed_extensions"]
    assert client.get("/api/evidence/upload-rules").status_code == 401


# ---------------------------------------------------------------- view
def test_view_png_and_pdf_inline_with_safe_headers(client, alice):
    png = png_bytes()
    eid = upload(client, alice, "scene.png", png).get_json()["evidence"]["id"]
    r = client.get(f"/api/evidence/{eid}/view", headers=alice)
    assert r.status_code == 200 and r.data == png
    assert r.mimetype == "image/png"
    assert r.headers["Content-Disposition"].startswith("inline")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"
    assert "sandbox" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Evidence-SHA256"] == hashlib.sha256(png).hexdigest()

    pid = upload(client, alice, "report.pdf", PDF_BYTES).get_json()["evidence"]["id"]
    r = client.get(f"/api/evidence/{pid}/view", headers=alice)
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.data == PDF_BYTES
    assert actions().count("VIEW_EVIDENCE") == 2


def test_view_text_is_served_as_plain_text_never_html(client, alice):
    payload = b"<html><script>alert('xss')</script></html>"
    eid = upload(client, alice, "snippet.txt", payload).get_json()["evidence"]["id"]
    r = client.get(f"/api/evidence/{eid}/view", headers=alice)
    assert r.status_code == 200 and r.data == payload
    assert r.mimetype == "text/plain" and r.headers["X-Content-Type-Options"] == "nosniff"


def test_unsupported_preview_falls_back_to_download(client, alice):
    data = b"PK\x03\x04" + os.urandom(200)
    eid = upload(client, alice, "bundle.zip", data).get_json()["evidence"]
    assert eid["previewable"] is False
    r = client.get(f"/api/evidence/{eid['id']}/view", headers=alice)
    assert r.status_code == 415 and r.get_json()["code"] == "PREVIEW_UNSUPPORTED"
    d = client.get(f"/api/evidence/{eid['id']}/download", headers=alice)
    assert d.status_code == 200 and d.data == data


# ---------------------------------------------------------------- download
def test_download_returns_identical_bytes_and_correct_filename(client, alice):
    original = os.urandom(5000) + b"\x00\xff"
    eid = upload(client, alice, "disk dump (1).bin", original).get_json()["evidence"]["id"]
    r = client.get(f"/api/evidence/{eid}/download", headers=alice)
    assert r.status_code == 200
    assert hashlib.sha256(r.data).hexdigest() == hashlib.sha256(original).hexdigest()
    assert r.data == original
    cd = r.headers["Content-Disposition"]
    assert cd.startswith("attachment") and "disk dump (1).bin" in cd
    assert r.headers["X-Evidence-SHA256"] == hashlib.sha256(original).hexdigest()
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "DOWNLOAD_EVIDENCE" in actions()
    assert LedgerBlock.query.filter_by(evidence_id=eid, event_type="DOWNLOAD").count() == 1


def test_html_like_evidence_can_only_be_downloaded_as_attachment(client, alice):
    eid = upload(client, alice, "mail.eml", b"From: a\r\n\r\n<script>alert(1)</script>").get_json()["evidence"]["id"]
    assert client.get(f"/api/evidence/{eid}/view", headers=alice).status_code == 415
    d = client.get(f"/api/evidence/{eid}/download", headers=alice)
    assert d.headers["Content-Disposition"].startswith("attachment")


# ---------------------------------------------------------------- access control
def test_unauthenticated_users_are_denied(client, alice):
    eid = upload(client, alice, "a.txt").get_json()["evidence"]["id"]
    for path in [f"/api/evidence/{eid}/download", f"/api/evidence/{eid}/view",
                 f"/api/evidence/{eid}", "/api/evidence", f"/api/evidence/{eid}/ledger"]:
        assert client.get(path).status_code == 401, path
    assert client.get(f"/api/evidence/{eid}/download",
                      headers={"Authorization": "Bearer not.a.token"}).status_code in (401, 422)


def test_other_users_cannot_access_someone_elses_evidence(client, alice, bob):
    eid = upload(client, alice, "secret.txt", b"alice only").get_json()["evidence"]["id"]
    for method, path in [("get", f"/api/evidence/{eid}"), ("get", f"/api/evidence/{eid}/view"),
                         ("get", f"/api/evidence/{eid}/download"), ("get", f"/api/evidence/{eid}/ledger"),
                         ("get", f"/api/evidence/{eid}/nodes"), ("post", f"/api/evidence/{eid}/verify"),
                         ("post", f"/api/evidence/{eid}/rotate-key"), ("post", f"/api/signatures/{eid}/sign"),
                         ("get", f"/api/signatures/{eid}/verify"), ("get", f"/api/reports/{eid}"),
                         ("get", f"/api/audit-logs/evidence/{eid}")]:
        r = getattr(client, method)(path, headers=bob)
        assert r.status_code == 403, (path, r.status_code)
        assert r.get_json()["code"] == "ACCESS_DENIED"
        assert b"alice only" not in r.data
    assert client.get("/api/evidence", headers=bob).get_json() == []        # not even listed
    assert len(client.get("/api/evidence", headers=alice).get_json()) == 1
    denied = AuditLog.query.filter_by(action="ACCESS_DENIED").count()
    assert denied == 11


def test_admin_can_access_any_evidence(client, alice, admin):
    eid = upload(client, alice, "a.txt", b"hello").get_json()["evidence"]["id"]
    assert client.get(f"/api/evidence/{eid}/download", headers=admin).data == b"hello"
    assert len(client.get("/api/evidence", headers=admin).get_json()) == 1


def test_unknown_evidence_returns_404(client, alice):
    assert client.get("/api/evidence/does-not-exist/download", headers=alice).status_code == 404


def test_deactivated_user_loses_access_immediately(client, app, alice, admin):
    from app.models import User
    eid = upload(client, alice, "a.txt").get_json()["evidence"]["id"]
    alice_id = User.query.filter_by(email="alice@example.com").first().id
    assert client.delete(f"/api/admin/invigilators/{alice_id}", headers=admin).status_code == 200
    assert client.get(f"/api/evidence/{eid}/download", headers=alice).status_code == 401


# ---------------------------------------------------------------- integrity
def _ciphertext_path(app, eid):
    ev = db.session.get(Evidence, eid)
    return os.path.join(app.config["STORAGE_PATH"], "uploads", ev.encrypted_filename)


def test_tampered_ciphertext_blocks_download_and_flags_evidence(client, app, alice):
    eid = upload(client, alice, "a.txt", b"original evidence").get_json()["evidence"]["id"]
    path = _ciphertext_path(app, eid)
    blob = bytearray(open(path, "rb").read())
    blob[len(blob) // 2] ^= 0xFF
    open(path, "wb").write(bytes(blob))

    r = client.get(f"/api/evidence/{eid}/download", headers=alice)
    assert r.status_code == 409 and r.get_json()["code"] == "INTEGRITY_MISMATCH"
    assert b"original evidence" not in r.data
    assert db.session.get(Evidence, eid).status == "tampered"
    assert client.get(f"/api/evidence/{eid}/view", headers=alice).status_code == 409
    assert "DOWNLOAD_BLOCKED_INTEGRITY" in actions() and "VIEW_BLOCKED_INTEGRITY" in actions()
    assert LedgerBlock.query.filter_by(evidence_id=eid, event_type="TAMPER_DETECTED").count() == 2
    assert "DOWNLOAD_EVIDENCE" not in actions()


def test_hash_mismatch_with_valid_ciphertext_is_detected(client, app, alice):
    eid = upload(client, alice, "a.txt", b"original evidence").get_json()["evidence"]["id"]
    ev = db.session.get(Evidence, eid)
    ev.sha256_hash = hashlib.sha256(b"something else").hexdigest()  # recorded hash no longer matches
    db.session.commit()
    r = client.get(f"/api/evidence/{eid}/download", headers=alice)
    assert r.status_code == 409 and r.get_json()["reason"] == "INTEGRITY_HASH"


def test_missing_ciphertext_is_reported_not_served(client, app, alice):
    eid = upload(client, alice, "a.txt").get_json()["evidence"]["id"]
    os.remove(_ciphertext_path(app, eid))
    r = client.get(f"/api/evidence/{eid}/download", headers=alice)
    assert r.status_code == 500 and r.get_json()["code"] == "FILE_MISSING"


def test_path_traversal_through_a_tampered_db_row_is_blocked(client, app, alice, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_bytes(b"OUTSIDE-SECRET")
    eid = upload(client, alice, "a.txt").get_json()["evidence"]["id"]
    ev = db.session.get(Evidence, eid)
    for evil in [os.path.relpath(secret, os.path.join(app.config["STORAGE_PATH"], "uploads")), str(secret), "..", "a/../../x"]:
        ev.encrypted_filename = evil
        db.session.commit()
        r = client.get(f"/api/evidence/{eid}/download", headers=alice)
        assert r.status_code == 409, evil
        assert b"OUTSIDE-SECRET" not in r.data


def test_verify_endpoint_still_works_and_detects_tampering(client, app, alice):
    eid = upload(client, alice, "a.txt", b"payload").get_json()["evidence"]["id"]
    r = client.post(f"/api/evidence/{eid}/verify", headers=alice)
    assert r.status_code == 200 and r.get_json()["hash_match"] is True
    assert r.get_json()["peer_node_consistency"]["consistent"] is True
    path = _ciphertext_path(app, eid)
    blob = bytearray(open(path, "rb").read())
    blob[len(blob) // 2] ^= 0xFF
    open(path, "wb").write(bytes(blob))
    r = client.post(f"/api/evidence/{eid}/verify", headers=alice)
    assert r.get_json()["hash_match"] is False and r.get_json()["status"] == "tampered"


# ---------------------------------------------------------------- regressions of existing features
def test_existing_features_still_work_for_the_owner(client, alice):
    eid = upload(client, alice, "a.txt", b"payload").get_json()["evidence"]["id"]
    assert client.get(f"/api/evidence/{eid}", headers=alice).status_code == 200
    assert client.get(f"/api/evidence/{eid}/ledger", headers=alice).get_json()["blocks"]
    assert client.get(f"/api/evidence/{eid}/nodes", headers=alice).get_json()["consistent"] is True
    s = client.post(f"/api/signatures/{eid}/sign", headers=alice)
    assert s.status_code == 201
    sigs = client.get(f"/api/signatures/{eid}/verify", headers=alice).get_json()["signatures"]
    assert sigs and sigs[0]["signature_valid"] is True
    rep = client.get(f"/api/reports/{eid}", headers=alice)
    assert rep.status_code == 200 and rep.data.startswith(b"%PDF")
    assert client.post(f"/api/evidence/{eid}/rotate-key", headers=alice).status_code == 200
    # after key rotation the file must still decrypt to the original bytes
    assert client.get(f"/api/evidence/{eid}/download", headers=alice).data == b"payload"
    assert client.get(f"/api/audit-logs/evidence/{eid}", headers=alice).status_code == 200


def test_mfa_login_flow_unchanged(client, app, alice):
    import pyotp
    from app.models import User
    secret = pyotp.random_base32()
    u = User.query.filter_by(email="alice@example.com").first()
    u.mfa_enabled, u.mfa_secret = True, secret
    db.session.commit()
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "CorrectHorse-9"})
    assert r.status_code == 401 and r.get_json()["mfa_required"] is True
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "CorrectHorse-9",
                                             "totp_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
