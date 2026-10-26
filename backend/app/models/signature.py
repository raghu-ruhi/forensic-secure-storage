import uuid
from datetime import datetime
from app.extensions import db


class DigitalSignature(db.Model):
    __tablename__ = "digital_signatures"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = db.Column(db.String(36), db.ForeignKey("evidence.id"), nullable=False)
    signer_id = db.Column(db.String(36), nullable=False)
    signature_b64 = db.Column(db.Text, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    signed_hash = db.Column(db.String(64), nullable=False)  # the sha256 hash that was signed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "evidence_id": self.evidence_id,
            "signer_id": self.signer_id,
            "signed_hash": self.signed_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
