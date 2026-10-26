from datetime import datetime

from app.extensions import db


class RevokedToken(db.Model):
    """JWT IDs (``jti``) revoked by logout. Rows are only needed until the token's
    natural expiry, after which they are purged."""
    __tablename__ = "revoked_tokens"

    jti = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.String(36), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
