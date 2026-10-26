from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import User
from app.services.mfa_service import (
    generate_totp_secret, get_provisioning_qr_base64, verify_totp,
    generate_backup_codes, hash_backup_codes, consume_backup_code,
)
from app.services.audit_service import log_action

mfa_bp = Blueprint("mfa", __name__, url_prefix="/api/mfa")


@mfa_bp.route("/setup", methods=["POST"])
@jwt_required()
def setup_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.mfa_enabled:
        return jsonify({"error": "MFA is already enabled"}), 400

    secret = generate_totp_secret()
    user.mfa_secret = secret  # not yet enabled until confirmed
    db.session.commit()

    qr_data_uri = get_provisioning_qr_base64(user.email, secret)
    return jsonify({
        "secret": secret,
        "qr_code": qr_data_uri,
        "message": "Scan the QR code with an authenticator app, then confirm with /api/mfa/confirm",
    }), 200


@mfa_bp.route("/confirm", methods=["POST"])
@jwt_required()
def confirm_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json(force=True) or {}
    code = data.get("totp_code", "")

    if not user or not user.mfa_secret:
        return jsonify({"error": "Run /api/mfa/setup first"}), 400
    if not verify_totp(user.mfa_secret, code):
        return jsonify({"error": "Invalid TOTP code"}), 400

    user.mfa_enabled = True
    backup_codes = generate_backup_codes()
    user.mfa_backup_codes = hash_backup_codes(backup_codes)
    db.session.commit()

    log_action("MFA_ENABLED", actor_id=user.id, actor_email=user.email)
    return jsonify({
        "message": "MFA enabled successfully",
        "backup_codes": backup_codes,
        "backup_codes_warning": "Save these now — they will not be shown again.",
    }), 200


@mfa_bp.route("/disable", methods=["POST"])
@jwt_required()
def disable_mfa():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json(force=True) or {}
    code = data.get("totp_code", "")

    if not user or not user.mfa_enabled:
        return jsonify({"error": "MFA is not enabled"}), 400
    if not verify_totp(user.mfa_secret, code):
        return jsonify({"error": "Invalid TOTP code"}), 400

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    db.session.commit()

    log_action("MFA_DISABLED", actor_id=user.id, actor_email=user.email)
    return jsonify({"message": "MFA disabled"}), 200


@mfa_bp.route("/verify-backup-code", methods=["POST"])
@jwt_required()
def verify_backup_code():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json(force=True) or {}
    code = data.get("backup_code", "")

    if not user or not user.mfa_backup_codes:
        return jsonify({"error": "No backup codes available"}), 400

    is_valid, updated_csv = consume_backup_code(user.mfa_backup_codes, code)
    if not is_valid:
        return jsonify({"error": "Invalid or already-used backup code"}), 400

    user.mfa_backup_codes = updated_csv
    db.session.commit()
    return jsonify({"message": "Backup code accepted"}), 200
