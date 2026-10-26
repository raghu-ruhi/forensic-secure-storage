import uuid
from datetime import datetime
from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="investigator")  # admin | investigator

    # Secure Block Verification Mechanism (SBVM) fields - paper Section III-C
    origin_x = db.Column(db.Float, nullable=True)
    origin_y = db.Column(db.Float, nullable=True)
    secret_code = db.Column(db.String(255), nullable=True)  # SC, rotates each auth cycle
    secret_key = db.Column(db.String(255), nullable=True)  # SK from EEO key generation

    is_email_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # Legacy plaintext column from the original implementation. It is no
    # longer written to (always NULL) - signup OTPs are stored hashed in
    # otp_hash below. Kept only so existing databases keep loading.
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)

    # --- Signup / email-verification OTP (hashed, expiring, rate limited) ---
    otp_hash = db.Column(db.String(255), nullable=True)
    otp_attempts = db.Column(db.Integer, nullable=False, default=0)
    otp_last_sent_at = db.Column(db.DateTime, nullable=True)
    otp_send_count = db.Column(db.Integer, nullable=False, default=0)
    otp_send_window_start = db.Column(db.DateTime, nullable=True)

    # --- Forgot / Reset password fields ---
    # The OTP itself is never stored in plaintext - only a keyed HMAC of it,
    # so it can't leak via a DB dump or an accidental log line.
    reset_otp_hash = db.Column(db.String(255), nullable=True)
    reset_otp_expires_at = db.Column(db.DateTime, nullable=True)
    reset_otp_attempts = db.Column(db.Integer, nullable=False, default=0)
    reset_otp_verified = db.Column(db.Boolean, nullable=False, default=False)
    reset_otp_last_sent_at = db.Column(db.DateTime, nullable=True)
    reset_otp_send_count = db.Column(db.Integer, nullable=False, default=0)
    reset_otp_send_window_start = db.Column(db.DateTime, nullable=True)
    # Short-lived, single-use bearer token issued only after the OTP has
    # been verified. The actual reset-password call requires this token
    # instead of the OTP again, so a verified-but-not-yet-used OTP can't be
    # replayed against /reset-password.
    reset_token_hash = db.Column(db.String(255), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    mfa_last_used_step = db.Column(db.BigInteger, nullable=True)  # last accepted TOTP time-step (replay guard)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True)
    mfa_backup_codes = db.Column(db.Text, nullable=True)  # comma-separated hashed codes

    # RSA keypair for digital signatures (Section: Digital Signatures).
    # Private key is stored wrapped (encrypted) under the master key, same
    # pattern as evidence file keys - never stored in plaintext.
    rsa_public_key = db.Column(db.Text, nullable=True)
    rsa_private_key_wrapped = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    evidences = db.relationship("Evidence", backref="uploader", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "role": self.role,
            "is_email_verified": self.is_email_verified,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
