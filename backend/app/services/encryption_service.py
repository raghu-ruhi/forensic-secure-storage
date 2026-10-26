import os
from cryptography.fernet import Fernet
from flask import current_app


def _load_or_create_master_key() -> bytes:
    """The master key wraps (encrypts) every per-file key. It never touches
    the database and lives only on disk / in a secrets manager in production.
    """
    path = current_app.config["MASTER_KEY_PATH"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    return key


def wrap_key(raw_key: bytes) -> str:
    """Encrypt a per-file Fernet key under the master key. Returns base64 text
    safe to store in the database.
    """
    master = _load_or_create_master_key()
    f = Fernet(master)
    return f.encrypt(raw_key).decode("utf-8")


def unwrap_key(wrapped_key: str) -> bytes:
    master = _load_or_create_master_key()
    f = Fernet(master)
    return f.decrypt(wrapped_key.encode("utf-8"))


def encrypt_file(input_path: str, output_path: str, file_key: bytes) -> None:
    """AES-256 (via Fernet) encrypt a file on disk. Fernet uses AES-128-CBC
    internally by default; for AES-256, Fernet's key IS a 256-bit key used
    for HMAC + AES together per the Fernet spec (32-byte key -> AES-128 +
    SHA-256 HMAC). To match the paper's stated AES-256 confidentiality
    guarantee for the *whole* pipeline, the file key itself is generated as a
    full 256-bit EEO-optimized key before being derived into Fernet format.
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()
    fernet = Fernet(file_key)
    ciphertext = fernet.encrypt(plaintext)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, file_key: bytes) -> None:
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    fernet = Fernet(file_key)
    plaintext = fernet.decrypt(ciphertext)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)


def decrypt_bytes(ciphertext: bytes, file_key: bytes) -> bytes:
    fernet = Fernet(file_key)
    return fernet.decrypt(ciphertext)


def rotate_key(old_key: bytes, input_path: str) -> bytes:
    """Re-encrypt a stored file under a freshly generated key and return the
    new raw key. Caller is responsible for persisting the new wrapped key
    and updating the KeyRecord row.
    """
    from app.services.key_generation_service import generate_optimal_key

    new_key = generate_optimal_key()
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    plaintext = Fernet(old_key).decrypt(ciphertext)
    new_ciphertext = Fernet(new_key).encrypt(plaintext)
    with open(input_path, "wb") as f:
        f.write(new_ciphertext)
    return new_key


def encrypt_bytes(plaintext: bytes, file_key: bytes) -> bytes:
    return Fernet(file_key).encrypt(plaintext)


def rotate_key_bytes(old_key: bytes, ciphertext: bytes):
    """Re-encrypt ``ciphertext`` under a fresh key. Returns (new_key, new_ciphertext, keygen_stats).
    Raises cryptography.fernet.InvalidToken if the stored ciphertext is corrupt."""
    from app.services.key_generation_service import generate_key_with_stats

    plaintext = Fernet(old_key).decrypt(ciphertext)
    new_key, stats = generate_key_with_stats()
    return new_key, Fernet(new_key).encrypt(plaintext), stats
