from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import User, Evidence, DigitalSignature
from app.services.signature_service import generate_rsa_keypair, sign_hash, verify_signature
from app.services.encryption_service import wrap_key, unwrap_key
from app.services.blockchain_service import add_block
from app.services.audit_service import log_action
from app.services.access_service import authorize_evidence

signature_bp = Blueprint("signature", __name__, url_prefix="/api/signatures")


def _ensure_user_has_rsa_keys(user: User) -> str:
    """Lazily generate an RSA-2048 keypair for a user the first time they
    sign anything. Returns the private key PEM (decrypted, in-memory only).
    """
    if user.rsa_public_key and user.rsa_private_key_wrapped:
        private_pem = unwrap_key(user.rsa_private_key_wrapped).decode("utf-8")
        return private_pem

    _, public_pem, private_pem = generate_rsa_keypair()
    user.rsa_public_key = public_pem
    user.rsa_private_key_wrapped = wrap_key(private_pem.encode("utf-8"))
    db.session.commit()
    return private_pem


@signature_bp.route("/<evidence_id>/sign", methods=["POST"])
@jwt_required()
def sign_evidence(evidence_id):
    evidence, user, error = authorize_evidence(evidence_id, "sign")
    if error:
        return error

    private_pem = _ensure_user_has_rsa_keys(user)
    signature_b64 = sign_hash(private_pem, evidence.sha256_hash)

    record = DigitalSignature(
        evidence_id=evidence.id,
        signer_id=user.id,
        signature_b64=signature_b64,
        public_key_pem=user.rsa_public_key,
        signed_hash=evidence.sha256_hash,
    )
    db.session.add(record)
    db.session.commit()

    add_block(evidence.id, "SIGNED", actor_id=user.id, payload={"signature_id": record.id})
    log_action("SIGN_EVIDENCE", actor_id=user.id, resource_type="evidence", resource_id=evidence.id)

    return jsonify({"message": "Evidence signed", "signature": record.to_dict()}), 201


@signature_bp.route("/<evidence_id>/verify", methods=["GET"])
@jwt_required()
def verify_evidence_signatures(evidence_id):
    evidence, _user, error = authorize_evidence(evidence_id, "verify_signatures")
    if error:
        return error

    results = []
    for sig in evidence.signatures:
        is_valid = verify_signature(sig.public_key_pem, evidence.sha256_hash, sig.signature_b64)
        results.append({**sig.to_dict(), "signature_valid": is_valid})

    return jsonify({"evidence_id": evidence_id, "signatures": results}), 200
