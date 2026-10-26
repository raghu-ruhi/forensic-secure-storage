import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_rsa_keypair():
    """Generate a fresh RSA-2048 key pair. Returns (private_key_obj, public_pem, private_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_key, public_pem, private_pem


def sign_hash(private_pem: str, sha256_hex: str) -> str:
    """Sign a SHA-256 hex digest (of the evidence file) with an RSA private key.
    Returns the signature as a base64 string.
    """
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    signature = private_key.sign(
        bytes.fromhex(sha256_hex),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_pem: str, sha256_hex: str, signature_b64: str) -> bool:
    """Verify a signature against the current hash of the evidence file.
    Returns False (not an exception) on any mismatch so callers can report
    a clean "verification failed" result.
    """
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            bytes.fromhex(sha256_hex),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
