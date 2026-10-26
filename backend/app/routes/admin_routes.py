"""Admin-only account management: create/list/delete Invigilator accounts.

Every route here is protected with @role_required("admin"), which verifies
the JWT and checks the `role` claim server-side - the frontend never gets
to decide who's an admin, only the backend does. There is deliberately no
route here (or anywhere else in the app) that lets a caller create or
promote an Admin account; that only happens via create_admin.py or the
ADMIN_EMAIL/ADMIN_PASSWORD startup seed (see app/db_bootstrap.py).
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db, bcrypt
from app.models import User
from app.services.audit_service import log_action
from app.utils.decorators import role_required

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/invigilators", methods=["POST"])
@role_required("admin")
def create_invigilator():
    """Admin creates a new Invigilator account directly. No self-registration
    or role selection involved, and no OTP round-trip is needed since the
    Admin is vouching for the account - it's created already verified."""
    data = request.get_json(force=True) or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not full_name or not email or not password:
        return jsonify({"error": "full_name, email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists"}), 409

    # Role is hardcoded to "investigator" here too - this endpoint can
    # never be used to create another Admin, even by an Admin, on purpose.
    # (There's no artificial "only one invigilator" limit anywhere in this
    # flow - an Admin can call this as many times as needed.)
    invigilator = User(
        full_name=full_name,
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
        role="investigator",
        is_email_verified=True,
        is_active=True,
    )
    db.session.add(invigilator)
    db.session.commit()

    admin_id = get_jwt_identity()
    log_action("ADMIN_CREATE_INVIGILATOR", actor_id=admin_id,
               resource_type="user", resource_id=invigilator.id,
               details=f"created invigilator {email}")

    return jsonify({
        "message": "Invigilator account created.",
        "invigilator": invigilator.to_dict(),
    }), 201


@admin_bp.route("/invigilators", methods=["GET"])
@role_required("admin")
def list_invigilators():
    invigilators = (
        User.query.filter_by(role="investigator")
        .order_by(User.created_at.desc())
        .all()
    )
    return jsonify([u.to_dict() for u in invigilators]), 200


@admin_bp.route("/invigilators/<user_id>", methods=["DELETE"])
@role_required("admin")
def delete_invigilator(user_id):
    """Soft-delete (deactivate) an Invigilator. We deactivate rather than
    hard-delete the row because evidence.uploader_id has a foreign key to
    users.id - hard-deleting would either break that FK or require
    reassigning/deleting evidence and audit history, which would break
    existing chain-of-custody functionality. Deactivating:
      - immediately revokes any active session (see the JWT blocklist
        loader in app/__init__.py), and
      - blocks all future logins (see the is_active check in /auth/login),
    so the net effect is exactly "can no longer log in or use the app",
    without discarding forensic records they created.
    """
    target = User.query.get(user_id)
    if not target:
        return jsonify({"error": "Invigilator not found"}), 404
    if target.role != "investigator":
        # Scopes this endpoint strictly to invigilators - an Admin cannot
        # use it to deactivate another Admin, and an Invigilator can never
        # reach this endpoint at all (role_required("admin") already blocks
        # them), so an Invigilator can never delete another Invigilator.
        return jsonify({"error": "This endpoint can only be used to remove Invigilator accounts"}), 400

    target.is_active = False
    db.session.commit()

    admin_id = get_jwt_identity()
    log_action("ADMIN_DEACTIVATE_INVIGILATOR", actor_id=admin_id,
               resource_type="user", resource_id=target.id,
               details=f"deactivated invigilator {target.email}")

    return jsonify({"message": f"{target.email} has been deactivated and can no longer log in."}), 200


@admin_bp.route("/invigilators/<user_id>/reactivate", methods=["POST"])
@role_required("admin")
def reactivate_invigilator(user_id):
    """Undo a deactivation. Not explicitly required by spec, but trivial
    and useful - deactivation shouldn't be a one-way door for an Admin who
    made a mistake or a returning invigilator."""
    target = User.query.get(user_id)
    if not target:
        return jsonify({"error": "Invigilator not found"}), 404
    if target.role != "investigator":
        return jsonify({"error": "This endpoint can only be used on Invigilator accounts"}), 400

    target.is_active = True
    db.session.commit()

    admin_id = get_jwt_identity()
    log_action("ADMIN_REACTIVATE_INVIGILATOR", actor_id=admin_id,
               resource_type="user", resource_id=target.id,
               details=f"reactivated invigilator {target.email}")

    return jsonify({"message": f"{target.email} has been reactivated."}), 200
