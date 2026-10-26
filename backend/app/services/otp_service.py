"""OTP generation / hashing / throttling and e-mail delivery.

Why SMTP is sent with ``smtplib`` directly instead of ``Flask-Mail``'s send:
  * Flask-Mail 0.10 calls ``smtplib.SMTP(host, port)`` with no timeout (an
    unreachable host hangs until gunicorn kills the worker with no response -
    "the OTP never arrives" with no error), and
  * its STARTTLS call uses Python's *unverified* default TLS context, so a
    man-in-the-middle could read the OTP and the SMTP password.
Here every connection has a hard timeout and TLS certificates are verified
(``ssl.create_default_context()``). The ``mail`` extension from Flask-Mail is
still initialised in app/extensions.py so nothing else in the project changes.

Nothing in this module ever logs or returns an OTP, the SMTP password, or a
reset token.
"""
import hashlib
import hmac
import logging
import math
import secrets
import smtplib
import socket
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from flask import current_app

from app.config import is_placeholder

logger = logging.getLogger("forensic.otp")

PURPOSE_SIGNUP = "signup"
PURPOSE_RESET = "password-reset"
HOUR_SECONDS = 3600


class MailConfigError(Exception):
    """The mail settings are missing/placeholder - nothing was attempted."""


# --------------------------------------------------------------------------
# OTP / token primitives
# --------------------------------------------------------------------------
def generate_otp() -> str:
    """Uniformly random 6-digit code from the OS CSPRNG (``secrets``)."""
    return f"{secrets.randbelow(10 ** 6):06d}"


def otp_expiry(minutes: int = None) -> datetime:
    minutes = minutes if minutes is not None else current_app.config["OTP_TTL_MINUTES"]
    return datetime.utcnow() + timedelta(minutes=minutes)


def _hmac(message: str) -> str:
    key = current_app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_otp(otp_code: str, purpose: str, email: str) -> str:
    """Keyed HMAC of ``purpose:email:code``.

    Binding the purpose and address means a code issued for signup can never
    be replayed against the password-reset endpoint (or another account), and
    the plaintext code is never stored. HMAC rather than bcrypt on purpose: a
    6-digit code is protected by expiry + an attempt limit, not by hash cost.
    """
    return _hmac(f"otp:{purpose}:{email.lower()}:{otp_code}")


def check_otp(otp_hash: str, otp_code: str, purpose: str, email: str) -> bool:
    if not otp_hash or not otp_code:
        return False
    return hmac.compare_digest(otp_hash, hash_otp(otp_code, purpose, email))


def hash_token(token: str) -> str:
    """HMAC for the single-use password-reset bearer token (256-bit random)."""
    return _hmac(f"token:{token}")


def check_token(token_hash: str, token: str) -> bool:
    if not token_hash or not token:
        return False
    return hmac.compare_digest(token_hash, hash_token(token))


# --------------------------------------------------------------------------
# Resend cooldown + hourly cap (stored per account, so they are exact even
# with several gunicorn workers)
# --------------------------------------------------------------------------
def check_send_allowed(user, prefix: str, now: datetime = None):
    """Return ``(retry_after_seconds, kind)``; ``(0, None)`` means a send is allowed.

    ``prefix`` selects the column family: ``"otp"`` for signup or
    ``"reset_otp"`` for password reset.
    """
    cfg = current_app.config
    now = now or datetime.utcnow()

    last_sent = getattr(user, f"{prefix}_last_sent_at")
    if last_sent:
        remaining = cfg["OTP_RESEND_COOLDOWN_SECONDS"] - (now - last_sent).total_seconds()
        if remaining > 0:
            return math.ceil(remaining), "cooldown"

    window_start = getattr(user, f"{prefix}_send_window_start")
    count = getattr(user, f"{prefix}_send_count") or 0
    if window_start and (now - window_start).total_seconds() < HOUR_SECONDS \
            and count >= cfg["OTP_MAX_SENDS_PER_HOUR"]:
        return math.ceil(HOUR_SECONDS - (now - window_start).total_seconds()), "hourly"
    return 0, None


def record_send(user, prefix: str, now: datetime = None) -> None:
    now = now or datetime.utcnow()
    window_start = getattr(user, f"{prefix}_send_window_start")
    if not window_start or (now - window_start).total_seconds() >= HOUR_SECONDS:
        setattr(user, f"{prefix}_send_window_start", now)
        setattr(user, f"{prefix}_send_count", 0)
    setattr(user, f"{prefix}_send_count", (getattr(user, f"{prefix}_send_count") or 0) + 1)
    setattr(user, f"{prefix}_last_sent_at", now)


def release_cooldown(user, prefix: str) -> None:
    """After a *failed* delivery let the user retry immediately (the attempt
    still counts toward the hourly cap, so this cannot be used to hammer SMTP)."""
    setattr(user, f"{prefix}_last_sent_at", None)


def throttle_message(retry_after: int, kind: str) -> str:
    if kind == "hourly":
        return (f"Too many codes were requested for this account. "
                f"Please try again in {math.ceil(retry_after / 60)} minute(s).")
    return f"A code was already sent recently. Please wait {retry_after}s before requesting another."


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------
def _mask_email(email: str) -> str:
    local, _, domain = (email or "").partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


def get_outbox() -> list:
    """Messages captured while MAIL_SUPPRESS_SEND is on (used by the tests)."""
    return current_app.extensions.setdefault("mail_outbox", [])


def _build_message(to_email: str, subject: str, body: str) -> EmailMessage:
    cfg = current_app.config
    sender = cfg.get("MAIL_DEFAULT_SENDER")
    if not sender:
        raise MailConfigError("No sender address: set MAIL_USERNAME (or MAIL_FROM).")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("Forensic Secure Storage", sender))
    msg["To"] = to_email
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
    msg.set_content(body)
    return msg


def _check_credentials() -> None:
    cfg = current_app.config
    if not cfg.get("MAIL_REQUIRE_AUTH", True):
        return
    username, password = cfg.get("MAIL_USERNAME"), cfg.get("MAIL_PASSWORD")
    if is_placeholder(username) or is_placeholder(password):
        raise MailConfigError(
            "MAIL_USERNAME / MAIL_PASSWORD are missing or still contain the .env.example "
            "placeholder values. Set them in .env (Gmail: use a 16-character App Password) "
            "and recreate the backend container.")


def _open_smtp():
    """Open, secure and authenticate an SMTP connection (caller must close it)."""
    cfg = current_app.config
    host, port = cfg["MAIL_SERVER"], cfg["MAIL_PORT"]
    timeout = cfg.get("MAIL_TIMEOUT_SECONDS", 15)
    context = ssl.create_default_context()  # verifies certificate chain + hostname

    if cfg.get("MAIL_USE_SSL"):
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if cfg.get("MAIL_USE_TLS") and not cfg.get("MAIL_USE_SSL"):
            server.starttls(context=context)
            server.ehlo()
        if cfg.get("MAIL_REQUIRE_AUTH", True):
            server.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
    except Exception:
        try:
            server.close()
        except Exception:  # noqa: BLE001
            pass
        raise
    return server


def send_email(to_email: str, subject: str, body: str) -> None:
    """Deliver one message or raise. Never swallows errors."""
    msg = _build_message(to_email, subject, body)
    if current_app.config.get("MAIL_SUPPRESS_SEND"):
        get_outbox().append(msg)
        return
    _check_credentials()
    server = _open_smtp()
    try:
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001 - connection already gone; message result stands
            pass


def send_otp_email(to_email: str, otp_code: str) -> None:
    """Email-verification OTP (registration / resend-otp)."""
    ttl = current_app.config["OTP_TTL_MINUTES"]
    send_email(
        to_email,
        "Your Forensic Secure Storage verification code",
        f"Your one-time verification code is: {otp_code}\n"
        f"This code expires in {ttl} minutes and can only be used once.\n\n"
        f"If you did not request this, you can ignore this email.",
    )


def send_password_reset_email(to_email: str, otp_code: str) -> None:
    """Password-reset OTP - a distinct subject/body from the signup OTP."""
    ttl = current_app.config["OTP_TTL_MINUTES"]
    send_email(
        to_email,
        "Your Forensic Secure Storage password reset code",
        f"We received a request to reset the password for your Forensic "
        f"Secure Storage account ({to_email}).\n\n"
        f"Your password reset code is: {otp_code}\n"
        f"This code expires in {ttl} minutes and can only be used once.\n\n"
        f"If you did not request a password reset, you can safely ignore "
        f"this email - your password will not be changed.",
    )


# --------------------------------------------------------------------------
# Error reporting (no secrets, ever)
# --------------------------------------------------------------------------
def describe_mail_error(exc: Exception) -> str:
    """Categorised, actionable explanation of an SMTP/network failure."""
    if isinstance(exc, MailConfigError):
        return str(exc)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        detail = (exc.smtp_error or b"")
        detail = detail.decode("utf-8", "ignore") if isinstance(detail, bytes) else str(detail)
        if exc.smtp_code == 534 or "5.7.9" in detail or "application-specific" in detail.lower():
            return ("Gmail rejected the login: an App Password is required. Enable Google 2-Step "
                    "Verification, create an App Password and use it as MAIL_PASSWORD.")
        return (f"SMTP authentication failed (code {exc.smtp_code}). The username/password was "
                "rejected. For Gmail use a 16-character App Password, not your account password, "
                "and make sure MAIL_USERNAME is the full Gmail address.")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ("TLS certificate verification failed - the mail server's certificate is not "
                "trusted. Check MAIL_SERVER, or whether a proxy/antivirus is intercepting TLS.")
    if isinstance(exc, ssl.SSLError):
        return ("TLS handshake with the mail server failed. Check that MAIL_PORT matches the "
                "security mode (587 + STARTTLS, or 465 + SSL).")
    if isinstance(exc, socket.gaierror):
        return "Could not resolve the SMTP server name - check MAIL_SERVER and the container's DNS/internet access."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ("Connection to the SMTP server timed out - check MAIL_SERVER/MAIL_PORT and that "
                "outbound SMTP is not blocked by a firewall.")
    if isinstance(exc, ConnectionRefusedError):
        return "Connection to the SMTP server was refused - check MAIL_SERVER and MAIL_PORT."
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return ("The SMTP server closed the connection unexpectedly - check that MAIL_PORT matches "
                "MAIL_USE_TLS / MAIL_USE_SSL.")
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "The SMTP server does not support the requested feature (STARTTLS/AUTH) on this port."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "The mail server rejected the recipient address."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "The mail server rejected the sender address - MAIL_FROM must be the authenticated account."
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP error: {exc.__class__.__name__}."
    if isinstance(exc, OSError):
        return f"Network error while contacting the SMTP server ({exc.__class__.__name__})."
    return f"Unexpected error sending email: {exc.__class__.__name__}."


def log_mail_failure(purpose: str, to_email: str, exc: Exception) -> None:
    """Server-side diagnostic: purpose, masked recipient, exception *class* and
    the categorised explanation. No OTP, no password, no traceback locals."""
    logger.error("OTP email not delivered (purpose=%s, to=%s, error=%s): %s",
                 purpose, _mask_email(to_email), exc.__class__.__name__, describe_mail_error(exc))


def mail_config_status() -> dict:
    """Which mail settings are present (never their values) plus the result of
    a live connect + STARTTLS + login. Sends no message."""
    cfg = current_app.config
    username, password = cfg.get("MAIL_USERNAME"), cfg.get("MAIL_PASSWORD")
    status = {
        "mail_server": cfg.get("MAIL_SERVER"),
        "mail_port": cfg.get("MAIL_PORT"),
        "mail_use_tls": bool(cfg.get("MAIL_USE_TLS")),
        "mail_use_ssl": bool(cfg.get("MAIL_USE_SSL")),
        "mail_username_configured": not is_placeholder(username),
        "mail_password_configured": not is_placeholder(password),
        "mail_sender_configured": bool(cfg.get("MAIL_DEFAULT_SENDER")),
        "connection_ok": False,
        "error": None,
    }
    try:
        _check_credentials()
        _build_message("diagnostic@example.invalid", "x", "x")  # validates the sender
        server = _open_smtp()
        try:
            server.noop()
        finally:
            try:
                server.quit()
            except Exception:  # noqa: BLE001
                pass
        status["connection_ok"] = True
    except Exception as exc:  # noqa: BLE001 - report any failure category
        status["error"] = describe_mail_error(exc)
    return status
