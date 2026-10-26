import io
import os
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models import Evidence, User, KeyRecord
from app.services.access_service import authorize_evidence, current_user
from app.services.hashing_service import sha256_file, sha256_bytes
from app.services.key_generation_service import generate_key_with_stats
import json
from app.services.encryption_service import (
    encrypt_bytes, decrypt_bytes, wrap_key, unwrap_key, rotate_key_bytes,
)
from app.services.storage import StorageError, StorageKeyError, StorageNotFound, get_storage
from app.services.upload_validation import (
    UploadValidationError, allowed_extensions, file_extension, mime_for,
    preview_mime_for, sanitize_filename, validate_content, validate_filename,
)
from app.utils.http import text_field
from app.services.blockchain_service import add_block, verify_chain, get_last_block
from app.services.peer_storage_service import replicate_bytes_to_nodes, check_node_consistency
from app.services.audit_service import log_action

evidence_bp = Blueprint("evidence", __name__, url_prefix="/api/evidence")


def _tmp_dir() -> str:
    """Scratch space for the uploaded plaintext while it is validated/hashed.
    Deliberately NOT inside the evidence store; the file is removed immediately."""
    path = os.path.join(current_app.config["STORAGE_PATH"], "tmp")
    os.makedirs(path, exist_ok=True)
    return path


def _storage_error_response(exc: StorageError):
    """Safe, client-facing translation of a storage failure (no AWS internals)."""
    status = {"STORAGE_PERMISSION": 503, "STORAGE_UNAVAILABLE": 503, "STORAGE_NOT_FOUND": 404,
              "STORAGE_INCOMPLETE": 502, "STORAGE_BAD_KEY": 409}.get(exc.code, 500)
    messages = {
        "STORAGE_PERMISSION": "The evidence store refused access. Contact an administrator.",
        "STORAGE_UNAVAILABLE": "The evidence store is temporarily unavailable. Please retry shortly.",
        "STORAGE_INCOMPLETE": "The evidence store could not confirm a complete write. The upload was not saved.",
    }
    return jsonify({"error": messages.get(exc.code, "Evidence storage error."), "code": exc.code}), status


def _remove_quietly(*paths) -> None:
    for path in paths:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _reject_upload(user, exc: UploadValidationError, filename: str = ""):
    log_action("UPLOAD_REJECTED", actor_id=user.id, actor_email=user.email,
               resource_type="evidence", details=f"code={exc.code}; file={filename[:100]}")
    return jsonify({"error": exc.message, "code": exc.code}), exc.status


@evidence_bp.route("/upload-rules", methods=["GET"])
@jwt_required()
def upload_rules():
    """Limits the frontend uses for client-side validation (the backend
    enforces the same rules - the client check is only a convenience)."""
    return jsonify({
        "max_upload_mb": current_app.config["MAX_UPLOAD_MB"],
        "allowed_extensions": allowed_extensions(current_app.config),
    }), 200


@evidence_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_evidence():
    uploader = current_user()
    if not uploader or not uploader.is_active:
        return jsonify({"error": "User not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file part named 'file' in the request"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    case_number = text_field(request.form, "case_number", 80)
    title = text_field(request.form, "title", 200)
    description = text_field(request.form, "description", 5000)
    if not case_number or not title:
        return jsonify({"error": "case_number and title are required"}), 400

    try:
        display_name = validate_filename(file.filename, current_app.config)
    except UploadValidationError as exc:
        return _reject_upload(uploader, exc, file.filename)

    storage = get_storage()  # configured default backend for NEW uploads
    storage_id = os.urandom(8).hex()  # server-generated; no client text reaches the filesystem
    raw_path = os.path.join(_tmp_dir(), f"{storage_id}_raw")
    encrypted_filename = f"{storage_id}.enc"
    node_names = []
    stored = False

    try:
        file.save(raw_path)
        try:
            max_bytes = current_app.config["MAX_UPLOAD_MB"] * 1024 * 1024
            file_size = validate_content(raw_path, display_name, max_bytes)
        except UploadValidationError as exc:
            _remove_quietly(raw_path)  # rejected content must not stay on disk
            return _reject_upload(uploader, exc, display_name)

        # SHA-256 of the ORIGINAL bytes, taken before anything touches them.
        original_hash = sha256_file(raw_path)

        # 1. Generate an EEO-optimized AES-256 key for THIS file
        file_key, keygen_stats = generate_key_with_stats()

        # 2. Encrypt the file; plaintext is never kept at rest
        with open(raw_path, "rb") as fh:
            ciphertext = encrypt_bytes(fh.read(), file_key)
        _remove_quietly(raw_path)
        storage.put(encrypted_filename, ciphertext)   # verified write (size + SHA-256 on S3)
        stored = True

        # 3. Wrap the file key under the master key and persist it
        wrapped_key = wrap_key(file_key)

        evidence = Evidence(
            case_number=case_number,
            title=title,
            description=description,
            original_filename=display_name,
            encrypted_filename=encrypted_filename,
            file_size_bytes=file_size,
            mime_type=mime_for(display_name),
            sha256_hash=original_hash,
            storage_backend=storage.name,
            encryption_key_id="",  # set after KeyRecord is created
            uploader_id=uploader.id,
            status="stored",
        )
        db.session.add(evidence)
        db.session.flush()  # get evidence.id before commit

        key_record = KeyRecord(evidence_id=evidence.id, wrapped_key=wrapped_key, keygen_meta=json.dumps(keygen_stats))
        db.session.add(key_record)
        db.session.flush()  # populate key_record.id before we reference it
        evidence.encryption_key_id = key_record.id

        # 4. Replication. Local backend: the (simulated, same-host) peer folders.
        #    S3 backend: durability is provided by S3 itself, so no local copies are made.
        if storage.name == "local":
            node_names = replicate_bytes_to_nodes(ciphertext, encrypted_filename)
        else:
            node_names = [storage.name]
        evidence.replicated_nodes = ",".join(node_names)

        db.session.commit()
    except StorageError as exc:
        db.session.rollback()
        _remove_quietly(raw_path)
        log_action("UPLOAD_FAILED", actor_id=uploader.id, actor_email=uploader.email,
                   resource_type="evidence", details=f"storage={exc.code}")
        return _storage_error_response(exc)
    except Exception:
        # Never leave half-written evidence (plaintext or ciphertext) behind.
        db.session.rollback()
        _remove_quietly(raw_path)
        if stored:
            try:
                storage.delete(encrypted_filename)
            except StorageError:
                pass
        for node_path in (current_app.config["NODE_A_PATH"], current_app.config["NODE_B_PATH"],
                          current_app.config["NODE_C_PATH"]):
            _remove_quietly(os.path.join(node_path, encrypted_filename))
        raise

    # 5. Record the UPLOAD event on the blockchain-style ledger
    add_block(
        evidence.id, "UPLOAD", actor_id=uploader.id,
        payload={"sha256": original_hash, "filename": display_name, "size": file_size, "nodes": node_names},
    )

    log_action("UPLOAD_EVIDENCE", actor_id=uploader.id, actor_email=uploader.email,
               resource_type="evidence", resource_id=evidence.id,
               details=f"file={display_name}; size={file_size}; sha256={original_hash}")

    return jsonify({"message": "Evidence uploaded and encrypted", "evidence": evidence.to_dict()}), 201


@evidence_bp.route("", methods=["GET"])
@jwt_required()
def list_evidence():
    """Admins see every item; investigators see only the evidence they uploaded."""
    user = current_user()
    if not user or not user.is_active:
        return jsonify({"error": "User not found or disabled"}), 401
    query = Evidence.query
    if user.role != "admin":
        query = query.filter_by(uploader_id=user.id)
    items = query.order_by(Evidence.created_at.desc()).all()
    return jsonify([e.to_dict() for e in items]), 200


@evidence_bp.route("/<evidence_id>", methods=["GET"])
@jwt_required()
def get_evidence(evidence_id):
    evidence, _user, error = authorize_evidence(evidence_id, "view_details")
    if error:
        return error
    return jsonify(evidence.to_dict()), 200


# ---------------------------------------------------------------------------
# View (inline preview) and download of the decrypted original
# ---------------------------------------------------------------------------
def _load_verified_plaintext(evidence):
    """Decrypt the stored ciphertext in memory and check it against the SHA-256
    recorded at upload time.

    Returns ``(plaintext, None, None)`` on success, otherwise
    ``(None, error_code, message)``. ``INTEGRITY_*`` codes mean the stored
    evidence no longer matches what was uploaded.
    """
    key_record = KeyRecord.query.filter_by(evidence_id=evidence.id, is_active=True).first()
    if not key_record:
        return None, "KEY_MISSING", "No active encryption key found for this evidence."
    try:
        storage = get_storage(evidence.storage_backend or "local")
        ciphertext = storage.get(evidence.encrypted_filename)
    except StorageKeyError:
        return None, "INTEGRITY_PATH", "The stored file reference is invalid."
    except StorageNotFound:
        return None, "FILE_MISSING", "The encrypted evidence file is missing from storage."
    except StorageError as exc:
        return None, exc.code, "The evidence store is unavailable or refused access."
    try:
        file_key = unwrap_key(key_record.wrapped_key)
    except Exception:  # noqa: BLE001 - master key lost/changed: a config problem, not tampering
        return None, "KEY_UNAVAILABLE", "The encryption key could not be unwrapped (master key unavailable)."
    try:
        plaintext = decrypt_bytes(ciphertext, file_key)
    except Exception:  # noqa: BLE001 - Fernet authentication tag mismatch
        return None, "INTEGRITY_CIPHERTEXT", "The stored ciphertext failed authentication."
    if sha256_bytes(plaintext) != evidence.sha256_hash:
        return None, "INTEGRITY_HASH", "The SHA-256 of the decrypted file does not match the upload hash."
    return plaintext, None, None


def _node_report(evidence) -> dict:
    """Peer-folder consistency (local backend only). Not meaningful for S3."""
    if (evidence.storage_backend or "local") != "local":
        return {"consistent": None, "node_hashes": {},
                "note": f"peer-folder simulation not used with the {evidence.storage_backend} backend"}
    return check_node_consistency(evidence.encrypted_filename)


def _integrity_block(evidence, user, operation: str, code: str):
    """Deny the request, flag the evidence as compromised and leave an audit trail."""
    evidence.status = "tampered"
    evidence.last_verified_at = datetime.utcnow()
    db.session.commit()
    add_block(evidence.id, "TAMPER_DETECTED", actor_id=user.id,
              payload={"operation": operation, "reason": code})
    log_action(f"{operation.upper()}_BLOCKED_INTEGRITY", actor_id=user.id, actor_email=user.email,
               resource_type="evidence", resource_id=evidence.id, details=f"reason={code}")
    return jsonify({
        "error": "Integrity check failed: this evidence no longer matches its original SHA-256 "
                 "hash and has been flagged as compromised. The file was NOT released.",
        "code": "INTEGRITY_MISMATCH",
        "reason": code,
        "expected_sha256": evidence.sha256_hash,
        "status": evidence.status,
    }), 409


def _serve_file(evidence, data: bytes, inline: bool):
    name = sanitize_filename(evidence.original_filename) or "evidence.bin"
    mimetype = preview_mime_for(name) if inline else mime_for(name)
    response = send_file(
        io.BytesIO(data), mimetype=mimetype, as_attachment=not inline,
        download_name=name, max_age=0, etag=False, conditional=False,
    )
    # Hardening: never let a browser sniff/execute the content, never cache evidence.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response.headers["X-Evidence-SHA256"] = evidence.sha256_hash
    response.headers["X-Evidence-Status"] = evidence.status or "stored"
    return response


def _release_evidence(evidence_id: str, operation: str, inline: bool):
    evidence, user, error = authorize_evidence(evidence_id, operation)
    if error:
        return error

    if inline and not preview_mime_for(evidence.original_filename):
        ext = file_extension(evidence.original_filename)
        return jsonify({
            "error": f"Preview is not supported for '.{ext}' files. Use Download instead.",
            "code": "PREVIEW_UNSUPPORTED",
        }), 415

    plaintext, code, message = _load_verified_plaintext(evidence)
    if code and code.startswith("INTEGRITY_"):
        return _integrity_block(evidence, user, operation, code)
    if code:
        log_action(f"{operation.upper()}_FAILED", actor_id=user.id, actor_email=user.email,
                   resource_type="evidence", resource_id=evidence.id, details=f"reason={code}")
        return jsonify({"error": message, "code": code}), 500

    add_block(evidence.id, operation.upper(), actor_id=user.id,
              payload={"sha256": evidence.sha256_hash, "bytes": len(plaintext)})
    log_action(f"{operation.upper()}_EVIDENCE", actor_id=user.id, actor_email=user.email,
               resource_type="evidence", resource_id=evidence.id,
               details=f"file={evidence.original_filename}; sha256_verified=true")
    return _serve_file(evidence, plaintext, inline)


@evidence_bp.route("/<evidence_id>/view", methods=["GET"])
@jwt_required()
def view_evidence(evidence_id):
    """Integrity-checked inline preview (images, PDF, plain text only)."""
    return _release_evidence(evidence_id, "view", inline=True)


@evidence_bp.route("/<evidence_id>/download", methods=["GET"])
@jwt_required()
def download_evidence(evidence_id):
    """Integrity-checked download of the decrypted original, as an attachment."""
    return _release_evidence(evidence_id, "download", inline=False)


@evidence_bp.route("/<evidence_id>/verify", methods=["POST"])
@jwt_required()
def verify_evidence(evidence_id):
    """Decrypt the stored ciphertext, recompute SHA-256, and compare against
    the hash captured at upload time. Also checks blockchain ledger
    integrity and peer-node consistency.
    """
    evidence, _user, error = authorize_evidence(evidence_id, "verify")
    if error:
        return error
    user_id = _user.id

    key_record = KeyRecord.query.filter_by(evidence_id=evidence.id, is_active=True).first()
    if not key_record:
        return jsonify({"error": "No active encryption key found for this evidence"}), 500

    try:
        storage = get_storage(evidence.storage_backend or "local")
        ciphertext = storage.get(evidence.encrypted_filename)
    except StorageNotFound:
        return jsonify({"error": "Encrypted evidence file missing from storage"}), 500
    except StorageError as exc:
        return _storage_error_response(exc)

    file_key = unwrap_key(key_record.wrapped_key)
    decryption_failed = False
    recomputed_hash = None
    try:
        recomputed_hash = sha256_bytes(decrypt_bytes(ciphertext, file_key))
    except Exception:
        # Fernet raises InvalidToken if the ciphertext's authentication tag no
        # longer matches - the stored object was corrupted or tampered with.
        decryption_failed = True

    hash_match = (not decryption_failed) and recomputed_hash == evidence.sha256_hash
    chain_result = verify_chain(evidence.id)
    node_result = _node_report(evidence)

    evidence.status = "verified" if (hash_match and chain_result["valid"]) else "tampered"
    evidence.last_verified_at = datetime.utcnow()
    db.session.commit()

    add_block(
        evidence.id,
        "VERIFY" if hash_match else "TAMPER_DETECTED",
        actor_id=user_id,
        payload={"hash_match": hash_match, "recomputed_hash": recomputed_hash},
    )

    log_action("VERIFY_EVIDENCE", actor_id=user_id, resource_type="evidence", resource_id=evidence.id,
               details=f"hash_match={hash_match}")

    return jsonify({
        "evidence_id": evidence.id,
        "hash_match": hash_match,
        "ciphertext_corrupted": decryption_failed,
        "original_hash": evidence.sha256_hash,
        "recomputed_hash": recomputed_hash,
        "ledger_chain": chain_result,
        "peer_node_consistency": node_result,
        "status": evidence.status,
    }), 200


@evidence_bp.route("/<evidence_id>/ledger", methods=["GET"])
@jwt_required()
def get_ledger(evidence_id):
    evidence, _user, error = authorize_evidence(evidence_id, "view_ledger")
    if error:
        return error
    blocks = [b.to_dict() for b in evidence.ledger_blocks]
    blocks.sort(key=lambda b: b["timestamp"])
    return jsonify({"evidence_id": evidence_id, "blocks": blocks}), 200


@evidence_bp.route("/<evidence_id>/nodes", methods=["GET"])
@jwt_required()
def check_nodes(evidence_id):
    """Lightweight peer-storage consistency check (ciphertext hash comparison
    only) without doing a full decrypt+verify cycle."""
    evidence, _user, error = authorize_evidence(evidence_id, "check_nodes")
    if error:
        return error
    return jsonify({"evidence_id": evidence.id, **_node_report(evidence)}), 200


@evidence_bp.route("/<evidence_id>/rotate-key", methods=["POST"])
@jwt_required()
def rotate_evidence_key(evidence_id):
    evidence, _user, error = authorize_evidence(evidence_id, "rotate_key")
    if error:
        return error
    user_id = _user.id

    key_record = KeyRecord.query.filter_by(evidence_id=evidence.id, is_active=True).first()
    if not key_record:
        return jsonify({"error": "No active key to rotate"}), 500

    storage = get_storage(evidence.storage_backend or "local")
    try:
        old_ciphertext = storage.get(evidence.encrypted_filename)
    except StorageError as exc:
        return _storage_error_response(exc)
    old_key = unwrap_key(key_record.wrapped_key)
    try:
        new_key, new_ciphertext, keygen_stats = rotate_key_bytes(old_key, old_ciphertext)
    except Exception:
        return jsonify({
            "error": "Cannot rotate key: the stored ciphertext failed decryption. "
                     "It may be corrupted or tampered with. Run /verify first."
        }), 409

    # Order matters: stage the DB change, write the new ciphertext, then commit.
    # If anything fails the OLD ciphertext is restored, so the stored object and
    # the active key can never disagree.
    key_record.is_active = False
    key_record.rotated_at = datetime.utcnow()
    new_record = KeyRecord(evidence_id=evidence.id, wrapped_key=wrap_key(new_key),
                           keygen_meta=json.dumps(keygen_stats))
    db.session.add(new_record)
    db.session.flush()
    evidence.encryption_key_id = new_record.id
    try:
        storage.put(evidence.encrypted_filename, new_ciphertext)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        try:
            storage.put(evidence.encrypted_filename, old_ciphertext)
        except StorageError:
            pass
        if isinstance(exc, StorageError):
            return _storage_error_response(exc)
        raise

    if storage.name == "local":  # refresh the simulated peer copies
        evidence.replicated_nodes = ",".join(
            replicate_bytes_to_nodes(new_ciphertext, evidence.encrypted_filename))
        db.session.commit()

    add_block(evidence.id, "KEY_ROTATED", actor_id=user_id, payload={"new_key_record": new_record.id})
    log_action("ROTATE_KEY", actor_id=user_id, resource_type="evidence", resource_id=evidence.id)

    return jsonify({"message": "Encryption key rotated successfully", "evidence": evidence.to_dict()}), 200
