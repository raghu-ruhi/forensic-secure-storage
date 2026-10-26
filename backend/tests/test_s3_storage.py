"""S3 storage backend, against moto's emulated AWS (no real AWS account used)."""
import hashlib

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from moto import mock_aws

from app import create_app
from app.extensions import db
from app.models import AuditLog, Evidence
from app.services.storage import (StorageIntegrityError, StorageNotFound, StoragePermissionError,
                                  StorageUnavailable, get_storage)
from app.services.storage.s3 import S3Storage
from tests.conftest import create_verified_user, login, make_config, upload

BUCKET = "forensic-evidence-test"


@pytest.fixture()
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "eu-west-1"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        s3 = boto3.client("s3", region_name="eu-west-1")
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
        yield s3


@pytest.fixture()
def s3_app(aws, tmp_path):
    app = create_app(make_config(tmp_path, STORAGE_BACKEND="s3", S3_BUCKET=BUCKET, S3_PREFIX="evidence/",
                                 AWS_REGION="eu-west-1", S3_SSE="AES256"))
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def owner(s3_app):
    c = s3_app.test_client()
    create_verified_user(c, s3_app, "o@example.com", "Owner")
    return c, login(c, "o@example.com")


def objects(aws):
    return aws.list_objects_v2(Bucket=BUCKET).get("Contents", [])


# ------------------------------------------------------------- backend unit tests
def test_put_get_roundtrip_with_server_side_encryption(s3_app, aws):
    st = get_storage()
    assert st.name == "s3"
    st.put("abc123.enc", b"ciphertext-bytes")
    assert st.get("abc123.enc") == b"ciphertext-bytes" and st.exists("abc123.enc")
    head = aws.head_object(Bucket=BUCKET, Key="evidence/abc123.enc", ChecksumMode="ENABLED")
    assert head["ServerSideEncryption"] == "AES256"
    assert head.get("ChecksumSHA256")  # a SHA-256 checksum accompanied the upload


def test_missing_object_and_exists_false(s3_app):
    st = get_storage()
    assert st.exists("nope.enc") is False
    with pytest.raises(StorageNotFound):
        st.get("nope.enc")


def test_keys_cannot_escape_the_prefix(s3_app):
    from app.services.storage import StorageKeyError
    st = get_storage()
    for bad in ["../x.enc", "a/b.enc", "", "..", "\\x", ".hidden", "x" * 300]:
        with pytest.raises(StorageKeyError):
            st.put(bad, b"x")


class _Err:
    """Minimal fake boto client that raises on chosen calls."""
    def __init__(self, exc): self.exc = exc
    def put_object(self, **k): raise self.exc
    def get_object(self, **k): raise self.exc
    def head_object(self, **k): raise self.exc
    def delete_object(self, **k): raise self.exc


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "arn:aws:iam::123456789012:role/secret-detail"}}, "op")


def test_permission_errors_are_translated_without_leaking_aws_details(s3_app):
    st = S3Storage(BUCKET, client=_Err(client_error("AccessDenied")))
    with pytest.raises(StoragePermissionError) as err:
        st.put("a.enc", b"x")
    assert "123456789012" not in str(err.value)


def test_network_failure_is_unavailable(s3_app):
    st = S3Storage(BUCKET, client=_Err(EndpointConnectionError(endpoint_url="https://s3.example")))
    with pytest.raises(StorageUnavailable):
        st.get("a.enc")


def test_incomplete_upload_is_detected_and_removed(s3_app, aws):
    class Truncating(S3Storage):
        def put(self, key, data):               # server "stores" fewer bytes than were sent
            return super().put(key, data)
    st = Truncating(BUCKET, region="eu-west-1")
    real_head = st.client.head_object
    st.client.head_object = lambda **k: {**real_head(**k), "ContentLength": 3}
    with pytest.raises(StorageIntegrityError):
        st.put("trunc.enc", b"0123456789")
    assert not [o for o in objects(aws) if o["Key"].endswith("trunc.enc")]


def test_missing_bucket_config_fails_cleanly():
    with pytest.raises(StorageUnavailable):
        S3Storage(bucket=None)


# ------------------------------------------------------------- end to end through the API
def test_upload_stores_only_ciphertext_in_s3_and_download_matches(s3_app, aws, owner):
    client, h = owner
    original = b"S3 evidence plaintext " * 100
    r = upload(client, h, "memo.txt", original)
    assert r.status_code == 201
    ev = r.get_json()["evidence"]
    assert ev["storage_backend"] == "s3" and ev["replicated_nodes"] == ["s3"]

    objs = objects(aws)
    assert len(objs) == 1 and objs[0]["Key"].startswith("evidence/") and objs[0]["Key"].endswith(".enc")
    body = aws.get_object(Bucket=BUCKET, Key=objs[0]["Key"])["Body"].read()
    assert b"S3 evidence plaintext" not in body                         # app-level encryption in the bucket
    assert aws.head_object(Bucket=BUCKET, Key=objs[0]["Key"])["ServerSideEncryption"] == "AES256"

    d = client.get(f"/api/evidence/{ev['id']}/download", headers=h)
    assert d.status_code == 200 and d.data == original
    assert hashlib.sha256(d.data).hexdigest() == ev["sha256_hash"]
    assert client.post(f"/api/evidence/{ev['id']}/verify", headers=h).get_json()["hash_match"] is True
    assert client.get(f"/api/evidence/{ev['id']}/view", headers=h).data == original


def test_tampered_s3_object_is_blocked(s3_app, aws, owner):
    client, h = owner
    ev = upload(client, h, "a.txt", b"payload").get_json()["evidence"]
    key = objects(aws)[0]["Key"]
    body = bytearray(aws.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    body[len(body) // 2] ^= 0xFF
    aws.put_object(Bucket=BUCKET, Key=key, Body=bytes(body))
    r = client.get(f"/api/evidence/{ev['id']}/download", headers=h)
    assert r.status_code == 409 and r.get_json()["code"] == "INTEGRITY_MISMATCH"


def test_deleted_s3_object_reports_missing(s3_app, aws, owner):
    client, h = owner
    ev = upload(client, h, "a.txt").get_json()["evidence"]
    aws.delete_object(Bucket=BUCKET, Key=objects(aws)[0]["Key"])
    r = client.get(f"/api/evidence/{ev['id']}/download", headers=h)
    assert r.status_code == 500 and r.get_json()["code"] == "FILE_MISSING"


def test_s3_permission_failure_on_download_is_a_safe_503(s3_app, aws, owner, monkeypatch):
    client, h = owner
    ev = upload(client, h, "a.txt").get_json()["evidence"]
    monkeypatch.setattr(get_storage().client, "get_object", lambda **k: (_ for _ in ()).throw(client_error("AccessDenied")))
    r = client.get(f"/api/evidence/{ev['id']}/download", headers=h)
    assert r.status_code == 500 or r.status_code == 503
    assert "123456789012" not in r.get_data(as_text=True) and "arn:aws" not in r.get_data(as_text=True)
    assert r.get_json()["code"] == "STORAGE_PERMISSION"


def test_upload_fails_cleanly_when_s3_is_unreachable(s3_app, aws, owner, monkeypatch):
    client, h = owner
    monkeypatch.setattr(get_storage().client, "put_object",
                        lambda **k: (_ for _ in ()).throw(EndpointConnectionError(endpoint_url="x")))
    r = upload(client, h, "a.txt")
    assert r.status_code == 503 and r.get_json()["code"] == "STORAGE_UNAVAILABLE"
    assert Evidence.query.count() == 0 and objects(aws) == []
    assert AuditLog.query.filter_by(action="UPLOAD_FAILED").count() == 1


def test_existing_local_evidence_stays_readable_after_switching_default_to_s3(tmp_path, aws, monkeypatch):
    """Rows remember their own backend, so flipping STORAGE_BACKEND never strands old evidence."""
    local = create_app(make_config(tmp_path, STORAGE_BACKEND="local"))
    with local.app_context():
        db.create_all()
        c = local.test_client()
        create_verified_user(c, local, "o@example.com")
        h = login(c, "o@example.com")
        eid = upload(c, h, "old.txt", b"written while local").get_json()["evidence"]["id"]
        db.session.remove()
        local.config.update(STORAGE_BACKEND="s3", S3_BUCKET=BUCKET, AWS_REGION="eu-west-1")
        local.extensions.pop("storage_backends", None)
        assert c.get(f"/api/evidence/{eid}/download", headers=h).data == b"written while local"
        new = upload(c, h, "new.txt", b"written while s3").get_json()["evidence"]
        assert new["storage_backend"] == "s3"
        assert c.get(f"/api/evidence/{eid}", headers=h).get_json()["storage_backend"] == "local"


def test_key_rotation_on_s3_keeps_file_readable(s3_app, aws, owner):
    client, h = owner
    ev = upload(client, h, "a.txt", b"rotate me").get_json()["evidence"]
    key = objects(aws)[0]["Key"]
    before = aws.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    assert client.post(f"/api/evidence/{ev['id']}/rotate-key", headers=h).status_code == 200
    assert aws.get_object(Bucket=BUCKET, Key=key)["Body"].read() != before
    assert client.get(f"/api/evidence/{ev['id']}/download", headers=h).data == b"rotate me"


def test_rotation_restores_old_ciphertext_if_commit_fails(s3_app, aws, owner, monkeypatch):
    client, h = owner
    ev = upload(client, h, "a.txt", b"rotate me").get_json()["evidence"]
    key = objects(aws)[0]["Key"]
    before = aws.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    real_commit = db.session.commit
    calls = {"n": 0}
    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db down")
        return real_commit()
    monkeypatch.setattr(db.session, "commit", flaky)
    with pytest.raises(RuntimeError):
        client.post(f"/api/evidence/{ev['id']}/rotate-key", headers=h)
    monkeypatch.undo()
    assert aws.get_object(Bucket=BUCKET, Key=key)["Body"].read() == before  # restored
    assert client.get(f"/api/evidence/{ev['id']}/download", headers=h).data == b"rotate me"
