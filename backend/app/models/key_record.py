import uuid
from datetime import datetime
from app.extensions import db


class KeyRecord(db.Model):
    """Stores each evidence file's EEO-generated Fernet key, itself encrypted
    ('wrapped') under a master key so the database never holds a raw usable key.
    """

    __tablename__ = "key_records"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = db.Column(db.String(36), db.ForeignKey("evidence.id"), nullable=False)
    wrapped_key = db.Column(db.Text, nullable=False)  # base64 ciphertext of the file key
    # JSON of NON-secret key-generation statistics (algorithm, iterations,
    # duration, fitness). Never contains key material.
    keygen_meta = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # False after rotation
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rotated_at = db.Column(db.DateTime, nullable=True)
