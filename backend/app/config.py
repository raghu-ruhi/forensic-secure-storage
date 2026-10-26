import os
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# ---------------------------------------------------------------------------
# .env loading
#
# Real environment variables always win (load_dotenv never overrides them), so
# under Docker Compose - which injects the variables itself - these calls are
# harmless no-ops. For a local `python run.py` they let you keep the settings
# in either file:
#   1. backend/.env     (legacy location, loaded first so it takes priority)
#   2. <project>/.env   (the single canonical file documented in the README)
# ---------------------------------------------------------------------------
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# Values copied straight from the *.env.example files. If one of these is
# still present, the operator never filled the setting in.
PLACEHOLDER_VALUES = {
    "your_email@gmail.com",
    "your_gmail_address@gmail.com",
    "your_app_password",
    "your_google_app_password",
    "change_this_to_a_long_random_string",
    "change_this_to_a_different_long_random_string",
    "dev-secret-key",
    "dev-jwt-secret-key",
}


def _clean(value):
    """Strip whitespace and one pair of surrounding quotes.

    Docker Compose's env_file keeps quotes literally in some versions, and
    people paste values with a trailing space/newline - both silently break
    SMTP authentication, so normalise them here.
    """
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def _env(*names, default=None):
    """First non-empty value among the given variable names (aliases)."""
    for name in names:
        value = _clean(os.environ.get(name))
        if value:
            return value
    return default


def _env_bool(*names, default=False):
    raw = _env(*names)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    raw = _env(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


def is_placeholder(value) -> bool:
    return value is None or value == "" or value.lower() in PLACEHOLDER_VALUES


def _mail_password():
    password = _env("MAIL_PASSWORD", "SMTP_PASSWORD")
    server = (_env("MAIL_SERVER", "SMTP_HOST", default="smtp.gmail.com") or "").lower()
    if password and server.endswith("gmail.com"):
        # Google displays App Passwords as four space-separated groups
        # ("abcd efgh ijkl mnop"); the real password has no spaces.
        password = "".join(password.split())
    return password


def _mail_security():
    """Return (use_tls, use_ssl) and make them consistent with the port.

    A very common misconfiguration is port 465 with STARTTLS (or 587 with
    implicit SSL), which fails with "SMTP server disconnected" / timeouts.
    """
    port = _mail_port()
    use_ssl = _env_bool("MAIL_USE_SSL", default=False)
    use_tls = _env_bool("MAIL_USE_TLS", default=True)
    if port == 465:
        return False, True
    if port == 587 and use_ssl:
        return True, False
    if use_ssl:
        return False, True
    return use_tls, False


def _mail_port():
    raw = _env("MAIL_PORT", "SMTP_PORT")
    try:
        return int(raw) if raw else 587
    except ValueError:
        return 587


_MAIL_USE_TLS, _MAIL_USE_SSL = _mail_security()
_MAIL_USERNAME = _env("MAIL_USERNAME", "SMTP_USERNAME")

IS_PRODUCTION = (_env("FLASK_ENV", "APP_ENV", default="development") or "").lower() == "production"


class Config:
    SECRET_KEY = _env("SECRET_KEY", default="dev-secret-key")
    JWT_SECRET_KEY = _env("JWT_SECRET_KEY", default="dev-jwt-secret-key")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    IS_PRODUCTION = IS_PRODUCTION

    SQLALCHEMY_DATABASE_URI = _env(
        "DATABASE_URL",
        default="postgresql://forensic_user:StrongPass123!@localhost:5432/forensic_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Mail / SMTP -------------------------------------------------------
    # Canonical names are MAIL_*; the SMTP_* names are accepted as aliases so
    # a .env written with either convention works.
    MAIL_SERVER = _env("MAIL_SERVER", "SMTP_HOST", default="smtp.gmail.com")
    MAIL_PORT = _mail_port()
    MAIL_USE_TLS = _MAIL_USE_TLS
    MAIL_USE_SSL = _MAIL_USE_SSL
    MAIL_USERNAME = _MAIL_USERNAME
    MAIL_PASSWORD = _mail_password()
    MAIL_DEFAULT_SENDER = _env("MAIL_FROM", "SMTP_FROM_EMAIL", default=_MAIL_USERNAME)
    MAIL_TIMEOUT_SECONDS = _env_int("MAIL_TIMEOUT_SECONDS", 15)
    # Set MAIL_REQUIRE_AUTH=false only for an unauthenticated relay / local test sink.
    MAIL_REQUIRE_AUTH = _env_bool("MAIL_REQUIRE_AUTH", default=True)
    MAIL_SUPPRESS_SEND = False  # tests only: capture messages instead of sending

    # --- OTP policy --------------------------------------------------------
    OTP_TTL_MINUTES = _env_int("OTP_TTL_MINUTES", 10)
    OTP_RESEND_COOLDOWN_SECONDS = _env_int("OTP_RESEND_COOLDOWN_SECONDS", 60)
    OTP_MAX_ATTEMPTS = _env_int("OTP_MAX_ATTEMPTS", 5)
    OTP_MAX_SENDS_PER_HOUR = _env_int("OTP_MAX_SENDS_PER_HOUR", 5)
    RATELIMIT_ENABLED = True  # per-IP limiter on unauthenticated auth endpoints

    # --- Storage -----------------------------------------------------------
    STORAGE_PATH = os.path.abspath(_env("STORAGE_PATH", default=os.path.join(BASE_DIR, "storage")))
    MASTER_KEY_PATH = os.path.abspath(_env(
        "MASTER_KEY_PATH", default=os.path.join(BASE_DIR, "storage", "master.key")
    ))

    NODE_A_PATH = os.path.abspath(_env("NODE_A_PATH", default=os.path.join(BASE_DIR, "storage", "node_a")))
    NODE_B_PATH = os.path.abspath(_env("NODE_B_PATH", default=os.path.join(BASE_DIR, "storage", "node_b")))
    NODE_C_PATH = os.path.abspath(_env("NODE_C_PATH", default=os.path.join(BASE_DIR, "storage", "node_c")))

    # --- Key generation (Equilibrium Optimizer parameters) ----------------
    EEO_POPULATION = _env_int("EEO_POPULATION", 20)
    EEO_MAX_ITER = _env_int("EEO_MAX_ITER", 50)

    # --- Evidence object storage ------------------------------------------
    # local = <STORAGE_PATH>/uploads ; s3 = private S3 bucket (see docs/AWS_S3_EC2.md).
    # On EC2 leave AWS credentials UNSET: boto3 uses the instance role.
    STORAGE_BACKEND = _env("STORAGE_BACKEND", default="local")
    S3_BUCKET = _env("S3_BUCKET")
    S3_PREFIX = _env("S3_PREFIX", default="evidence/")
    AWS_REGION = _env("AWS_REGION", "AWS_DEFAULT_REGION")
    S3_SSE = _env("S3_SSE", default="AES256")              # AES256 | aws:kms
    S3_KMS_KEY_ID = _env("S3_KMS_KEY_ID")
    S3_CONNECT_TIMEOUT = _env_int("S3_CONNECT_TIMEOUT", 5)
    S3_READ_TIMEOUT = _env_int("S3_READ_TIMEOUT", 30)
    S3_MAX_RETRIES = _env_int("S3_MAX_RETRIES", 3)
    S3_ENDPOINT_URL = _env("S3_ENDPOINT_URL")              # tests / MinIO only

    # --- Evidence upload limits -------------------------------------------
    # Evidence is encrypted in memory (Fernet), so keep this modest. Raise it
    # only if the backend container has the RAM to match.
    MAX_UPLOAD_MB = _env_int("MAX_UPLOAD_MB", 50)
    # Flask rejects bigger request bodies with HTTP 413 before reading them.
    # +1 MB of slack covers the multipart form fields around the file.
    MAX_CONTENT_LENGTH = (MAX_UPLOAD_MB + 1) * 1024 * 1024
    # Optional override: comma-separated list, e.g. "pdf,png,jpg,txt"
    ALLOWED_UPLOAD_EXTENSIONS_OVERRIDE = _env("ALLOWED_UPLOAD_EXTENSIONS")

    # Comma-separated list of allowed browser origins (CORS).
    FRONTEND_ORIGIN = _env("FRONTEND_ORIGIN", default="http://localhost:5173,http://127.0.0.1:5173")
    FRONTEND_ORIGINS = [o.strip() for o in FRONTEND_ORIGIN.split(",") if o.strip()]
