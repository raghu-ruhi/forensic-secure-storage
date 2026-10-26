"""Validation rules for uploaded evidence files.

Design notes
------------
* Allowlist, not blocklist: only extensions listed in ``EXTENSION_MIME`` are
  accepted. Executables, scripts, HTML and SVG are deliberately NOT on the
  list - evidence is stored encrypted and never executed, but keeping active
  content out also removes any chance of it being rendered by a browser.
  Operators can narrow or widen the list with ALLOWED_UPLOAD_EXTENSIONS.
* The MIME type is derived from the extension *by the server*. The
  Content-Type header sent by the client is never trusted or reused.
* For formats with a well-known signature (PDF, PNG, JPEG, ...) the first
  bytes of the file must match the extension, so ``malware.exe`` renamed to
  ``photo.png`` is rejected.
* Only the sanitized *display* name is kept from the client. Files on disk
  are named with server-generated random identifiers, so no client-supplied
  string is ever used to build a filesystem path.
"""
import os
import unicodedata

# extension -> MIME type (served only as an attachment unless previewable)
EXTENSION_MIME = {
    # images
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
    "webp": "image/webp", "bmp": "image/bmp", "tif": "image/tiff", "tiff": "image/tiff",
    # documents
    "pdf": "application/pdf", "txt": "text/plain", "log": "text/plain", "csv": "text/csv",
    "json": "application/json", "xml": "application/xml",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "eml": "message/rfc822", "msg": "application/vnd.ms-outlook",
    # archives
    "zip": "application/zip", "gz": "application/gzip", "tar": "application/x-tar",
    "7z": "application/x-7z-compressed", "rar": "application/vnd.rar",
    # audio / video
    "mp3": "audio/mpeg", "wav": "audio/wav", "mp4": "video/mp4", "avi": "video/x-msvideo",
    "mov": "video/quicktime", "mkv": "video/x-matroska",
    # forensic artefacts: disk images, memory dumps, captures, logs, databases
    "e01": "application/octet-stream", "dd": "application/octet-stream",
    "img": "application/octet-stream", "raw": "application/octet-stream",
    "mem": "application/octet-stream", "vmem": "application/octet-stream",
    "dmp": "application/octet-stream", "bin": "application/octet-stream",
    "pcap": "application/vnd.tcpdump.pcap", "pcapng": "application/octet-stream",
    "evtx": "application/octet-stream", "sqlite": "application/vnd.sqlite3",
    "db": "application/octet-stream",
}

# Formats the browser may render inline, and the exact Content-Type the
# server will declare for them. Everything else is download-only.
PREVIEW_MIME = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
    "webp": "image/webp", "bmp": "image/bmp",
    "pdf": "application/pdf",
    "txt": "text/plain; charset=utf-8", "log": "text/plain; charset=utf-8",
    "csv": "text/plain; charset=utf-8", "json": "text/plain; charset=utf-8",
}

# Leading-bytes signatures. A tuple of alternatives per extension.
_SIGNATURES = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "pdf": (b"%PDF-",),
    "gz": (b"\x1f\x8b",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06"),
    "docx": (b"PK\x03\x04",), "xlsx": (b"PK\x03\x04",), "pptx": (b"PK\x03\x04",),
    "7z": (b"7z\xbc\xaf\x27\x1c",),
    "sqlite": (b"SQLite format 3\x00",),
}

MAX_DISPLAY_NAME_LENGTH = 200


class UploadValidationError(Exception):
    """Raised with a user-safe message when an upload is rejected."""

    def __init__(self, message: str, code: str = "INVALID_UPLOAD", status: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def file_extension(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lstrip(".").lower()


def mime_for(filename: str) -> str:
    return EXTENSION_MIME.get(file_extension(filename), "application/octet-stream")


def is_previewable(filename: str) -> bool:
    return file_extension(filename) in PREVIEW_MIME


def preview_mime_for(filename: str):
    return PREVIEW_MIME.get(file_extension(filename))


def allowed_extensions(config=None) -> list:
    """Effective allowlist: the built-in set, optionally narrowed/overridden by
    ALLOWED_UPLOAD_EXTENSIONS (extensions not in EXTENSION_MIME are ignored, so
    the override can never enable something this module has no MIME rule for).
    """
    override = (config or {}).get("ALLOWED_UPLOAD_EXTENSIONS_OVERRIDE")
    if override:
        wanted = {e.strip().lower().lstrip(".") for e in override.split(",") if e.strip()}
        return sorted(e for e in EXTENSION_MIME if e in wanted)
    return sorted(EXTENSION_MIME)


def sanitize_filename(raw_name: str) -> str:
    """Return a safe display name: no directories, no control characters."""
    name = (raw_name or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip().strip(".").strip()
    if len(name) > MAX_DISPLAY_NAME_LENGTH:
        stem, ext = os.path.splitext(name)
        name = stem[: MAX_DISPLAY_NAME_LENGTH - len(ext)] + ext
    return name


def validate_filename(raw_name: str, config=None) -> str:
    """Validate the client-supplied name and return its sanitized form."""
    name = sanitize_filename(raw_name)
    if not name:
        raise UploadValidationError("The file name is empty or invalid.", "INVALID_FILENAME")
    ext = file_extension(name)
    if not ext:
        raise UploadValidationError(
            "The file has no extension, so its type cannot be validated.", "MISSING_EXTENSION")
    if ext not in allowed_extensions(config):
        raise UploadValidationError(
            f"Files of type '.{ext}' are not accepted. Allowed types: "
            f"{', '.join('.' + e for e in allowed_extensions(config))}.",
            "UNSUPPORTED_TYPE", 415)
    return name


def validate_content(path: str, filename: str, max_bytes: int) -> int:
    """Validate the saved temp file (size, non-empty, signature). Returns size."""
    size = os.path.getsize(path)
    if size == 0:
        raise UploadValidationError("The file is empty.", "EMPTY_FILE")
    if size > max_bytes:
        raise UploadValidationError(
            f"The file is {size / (1024 * 1024):.1f} MB; the maximum allowed size is "
            f"{max_bytes // (1024 * 1024)} MB.", "FILE_TOO_LARGE", 413)

    ext = file_extension(filename)
    with open(path, "rb") as f:
        head = f.read(1024)
    if ext == "webp":
        ok = head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    elif ext == "pdf":
        ok = b"%PDF-" in head  # PDFs may carry a few junk bytes before the header
    elif ext in _SIGNATURES:
        ok = any(head.startswith(sig) for sig in _SIGNATURES[ext])
    else:
        ok = True  # no reliable signature (text, logs, raw dumps, ...)
    if not ok:
        raise UploadValidationError(
            f"The file content does not match its '.{ext}' extension.", "CONTENT_MISMATCH", 415)
    return size
