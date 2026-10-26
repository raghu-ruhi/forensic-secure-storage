from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from app.models import AuditLog
from app.utils.decorators import role_required
from app.services.access_service import authorize_evidence

audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit-logs")


@audit_bp.route("", methods=["GET"])
@role_required("admin")
def list_audit_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs]), 200


@audit_bp.route("/evidence/<evidence_id>", methods=["GET"])
@jwt_required()
def logs_for_evidence(evidence_id):
    _evidence, _user, error = authorize_evidence(evidence_id, "view_audit_trail")
    if error:
        return error
    logs = (
        AuditLog.query.filter_by(resource_type="evidence", resource_id=evidence_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    return jsonify([log.to_dict() for log in logs]), 200
