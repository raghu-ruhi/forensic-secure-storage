import hashlib


def sha256_bytes(data: bytes) -> str:
    """Return the hex-digest SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: str, chunk_size: int = 8192) -> str:
    """Stream a file from disk and return its SHA-256 hex digest.
    Streaming avoids loading large evidence files fully into memory.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_hash(file_path: str, expected_hash: str) -> bool:
    """Recompute the hash of a file and compare against a stored hash."""
    return sha256_file(file_path) == expected_hash
