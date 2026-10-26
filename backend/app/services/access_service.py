"""Evidence authorization - the single place that decides who may touch an item.

Rule: an evidence item may be read or acted upon only by the user who uploaded
it or by an Admin. Every refusal is written to the audit log as ACCESS_DENIED
so unauthorized probing is visible to administrators.

The user's *current* role/active flag is read from the database on every
request (not from the JWT claims), so a demoted or deactivated account loses
access immediately.
"""
from flask import jsonify
from flask_jwt_extended import get_jwt_identity

from app.extensions import db
from app.models import Evidence, User
from app.services.audit_service import log_action


def current_user():
    return db.session.get(User, get_jwt_identity())


def can_access(user, evidence) -> bool:
    return bool(user and user.is_active and (user.role == "admin" or evidence.uploader_id == user.id))


def authorize_evidence(evidence_id: str, action: str):
    """Return ``(evidence, user, error)``; ``error`` is a ready-to-return
    ``(response, status)`` tuple or ``None`` when access is granted."""
    user = current_user()
    if not user or not user.is_active:
        return None, None, (jsonify({"error": "User not found or disabled"}), 401)

    evidence = db.session.get(Evidence, evidence_id)
    if not evidence:
        return None, user, (jsonify({"error": "Evidence not found"}), 404)

    if not can_access(user, evidence):
        log_action("ACCESS_DENIED", actor_id=user.id, actor_email=user.email,
                   resource_type="evidence", resource_id=evidence.id, details=f"action={action}")
        return None, user, (jsonify({
            "error": "You do not have permission to access this evidence.",
            "code": "ACCESS_DENIED",
        }), 403)

    return evidence, user, None
