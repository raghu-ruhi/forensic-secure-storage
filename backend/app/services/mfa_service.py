import io
import base64
import secrets
import pyotp
import qrcode
from app.extensions import bcrypt


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_qr_base64(email: str, secret: str, issuer: str = "ForensicSecureStorage") -> str:
    """Return a base64 PNG data URI of the TOTP QR code for authenticator apps."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(count: int = 8) -> list[str]:
    """Return plaintext backup codes to show the user once."""
    return [secrets.token_hex(4) for _ in range(count)]


def hash_backup_codes(codes: list[str]) -> str:
    """Store only bcrypt hashes, comma-separated, never the plaintext codes."""
    return ",".join(bcrypt.generate_password_hash(c).decode("utf-8") for c in codes)


def consume_backup_code(stored_hashes_csv: str, submitted_code: str) -> tuple[bool, str]:
    """Check a submitted backup code against stored hashes. Returns
    (is_valid, updated_csv_with_that_code_removed) so each code works once.
    """
    if not stored_hashes_csv:
        return False, stored_hashes_csv
    hashes = stored_hashes_csv.split(",")
    for h in hashes:
        if bcrypt.check_password_hash(h, submitted_code):
            hashes.remove(h)
            return True, ",".join(hashes)
    return False, stored_hashes_csv
