from flask import request
from app.extensions import db
from app.models import AuditLog


def log_action(action: str, actor_id: str = None, actor_email: str = None,
                resource_type: str = None, resource_id: str = None, details: str = None) -> None:
    entry = AuditLog(
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr if request else None,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()
