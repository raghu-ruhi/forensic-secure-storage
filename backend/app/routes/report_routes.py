import os
from flask import Blueprint, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Evidence, User
from app.services.report_service import generate_evidence_report
from app.services.blockchain_service import verify_chain
from app.services.audit_service import log_action
from app.services.access_service import authorize_evidence

report_bp = Blueprint("report", __name__, url_prefix="/api/reports")


@report_bp.route("/<evidence_id>", methods=["GET"])
@jwt_required()
def download_report(evidence_id):
    evidence, _user, error = authorize_evidence(evidence_id, "report")
    if error:
        return error
    user_id = _user.id
    uploader = User.query.get(evidence.uploader_id)

    chain_result = verify_chain(evidence.id)
    ledger_blocks = sorted(evidence.ledger_blocks, key=lambda b: b.timestamp)

    reports_dir = os.path.join(current_app.config["STORAGE_PATH"], "reports")
    output_path = os.path.join(reports_dir, f"{evidence.id}_report.pdf")

    generate_evidence_report(
        evidence=evidence,
        uploader=uploader,
        ledger_blocks=ledger_blocks,
        signatures=evidence.signatures,
        chain_valid=chain_result,
        output_path=output_path,
    )

    log_action("GENERATE_REPORT", actor_id=user_id, resource_type="evidence", resource_id=evidence.id)

    return send_file(
        output_path,
        as_attachment=True,
        download_name=f"forensic_report_{evidence.case_number}.pdf",
        mimetype="application/pdf",
    )
