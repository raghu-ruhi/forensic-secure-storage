import uuid
from datetime import datetime
from app.extensions import db


class LedgerBlock(db.Model):
    """Lightweight blockchain-style evidence ledger.
    Each block cryptographically chains to the previous block's hash,
    giving tamper-evidence to the ordered history of evidence events.
    """

    __tablename__ = "ledger_blocks"

    block_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = db.Column(db.String(36), db.ForeignKey("evidence.id"), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)  # UPLOAD | VERIFY | ACCESS | TAMPER_DETECTED
    previous_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=False)
    actor_id = db.Column(db.String(36), nullable=True)  # user who triggered the event
    payload = db.Column(db.Text, nullable=True)  # JSON string of event-specific data
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "block_id": self.block_id,
            "evidence_id": self.evidence_id,
            "event_type": self.event_type,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "actor_id": self.actor_id,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
