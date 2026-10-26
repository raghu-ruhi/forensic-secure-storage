import uuid
from datetime import datetime
from app.extensions import db
from app.services.upload_validation import file_extension, mime_for, is_previewable


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = db.Column(db.String(80), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)  # server-determined from the extension allowlist

    sha256_hash = db.Column(db.String(64), nullable=False)  # hash of original file at upload time
    encryption_key_id = db.Column(db.String(36), nullable=False)  # references KeyRecord-style key id

    uploader_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)

    status = db.Column(db.String(20), default="stored")  # stored | verified | tampered
    storage_backend = db.Column(db.String(20), nullable=False, default="local")  # local | s3
    replicated_nodes = db.Column(db.String(100), default="")  # e.g. "node_a,node_b,node_c"

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_verified_at = db.Column(db.DateTime, nullable=True)

    signatures = db.relationship("DigitalSignature", backref="evidence", lazy=True)
    ledger_blocks = db.relationship("LedgerBlock", backref="evidence", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "description": self.description,
            "original_filename": self.original_filename,
            "file_size_bytes": self.file_size_bytes,
            "file_extension": file_extension(self.original_filename),
            "mime_type": self.mime_type or mime_for(self.original_filename),
            "previewable": is_previewable(self.original_filename),
            "sha256_hash": self.sha256_hash,
            "uploader_id": self.uploader_id,
            "status": self.status,
            "storage_backend": self.storage_backend or "local",
            "replicated_nodes": self.replicated_nodes.split(",") if self.replicated_nodes else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_verified_at": self.last_verified_at.isoformat() if self.last_verified_at else None,
        }
