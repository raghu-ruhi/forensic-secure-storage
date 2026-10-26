import re
import secrets
import time
from datetime import datetime, timedelta

import pyotp
from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, current_app, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, get_jwt_identity
from sqlalchemy.exc import IntegrityError

from app.extensions import db, bcrypt
from app.models import RevokedToken, User
from app.services.otp_service import (
    PURPOSE_RESET,
    PURPOSE_SIGNUP,
    check_otp,
    check_send_allowed,
    check_token,
    describe_mail_error,
    generate_otp,
    hash_otp,
    hash_token,
    log_mail_failure,
    mail_config_status,
    otp_expiry,
    record_send,
    release_cooldown,
    send_otp_email,
    send_password_reset_email,
    throttle_message,
)
from app.services.audit_service import log_action
from app.utils.decorators import role_required
from app.utils.http import json_body, text_field
from app.utils.rate_limit import hit_limit, ip_rate_limit

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

VALID_ROLES = {"admin", "investigator"}
# Roles a person can self-assign via the public /register endpoint. Admin is
# deliberately excluded - see register() below. Admin accounts can only be
# created via create_admin.py, the ADMIN_EMAIL/ADMIN_PASSWORD startup seed,
# or an existing Admin using the authenticated /api/admin endpoints.
SELF_REGISTERABLE_ROLES = {"investigator"}

OTP_FORMAT = re.compile(r"^\d{6}$")
MAX_PASSWORD_BYTES = 72  # bcrypt limit; bcrypt>=5 raises instead of truncating


def _password_error(password: str):
    if not isinstance(password, str) or len(password) < 8:
        return "password must be at least 8 characters"
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"password must be at most {MAX_PASSWORD_BYTES} bytes"
    return None


def _normalise_email(raw: str):
    """Return the normalised address, or None if it is not a valid e-mail."""
    if not raw:
        return None
    try:
        return validate_email(raw, check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None


def _throttled(retry_after: int, kind: str):
    resp = jsonify({
        "error": throttle_message(retry_after, kind),
        "code": "OTP_THROTTLED",
        "retry_after": retry_after,
    })
    resp.status_code = 429
    resp.headers["Retry-After"] = str(retry_after)
    return resp


def _delivery_failed(exc: Exception, purpose_label: str, user_created: bool = False):
    """Honest failure response: the e-mail was NOT sent, say so (HTTP 502)."""
    body = {
        "success": False,
        "email_sent": False,
        "code": "EMAIL_SEND_FAILED",
        "error": ("We could not send the verification email. Please try again in a minute, "
                  "or contact an administrator if this keeps happening."),
    }
    if user_created:
        body["account_created"] = True
    if not current_app.config.get("IS_PRODUCTION"):
        # Categorised hint only (never credentials / the OTP) to speed up setup.
        body["mail_error"] = describe_mail_error(exc)
    return jsonify(body), 502


def _issue_signup_otp(user):
    """Throttle -> generate -> store hash -> e-mail. Returns an error response
    tuple, or None when the e-mail was handed to the SMTP server."""
    retry_after, kind = check_send_allowed(user, "otp")
    if retry_after:
        return _throttled(retry_after, kind), 429

    code = generate_otp()
    user.otp_code = None  # legacy plaintext column is never used any more
    user.otp_hash = hash_otp(code, PURPOSE_SIGNUP, user.email)
    user.otp_expires_at = otp_expiry()
    user.otp_attempts = 0
    record_send(user, "otp")
    db.session.commit()

    try:
        send_otp_email(user.email, code)
    except Exception as exc:  # noqa: BLE001 - any SMTP/network failure
        log_mail_failure("signup", user.email, exc)
        # The code never reached the user: invalidate it and let them retry now.
        user.otp_hash = None
        user.otp_expires_at = None
        release_cooldown(user, "otp")
        db.session.commit()
        log_action("OTP_EMAIL_FAILED", actor_id=user.id, actor_email=user.email,
                   resource_type="user", resource_id=user.id, details="purpose=signup")
        return _delivery_failed(exc, "signup", user_created=True)
    return None


def _issue_reset_otp(user):
    retry_after, kind = check_send_allowed(user, "reset_otp")
    if retry_after:
        return _throttled(retry_after, kind), 429

    code = generate_otp()
    user.reset_otp_hash = hash_otp(code, PURPOSE_RESET, user.email)
    user.reset_otp_expires_at = otp_expiry()
    user.reset_otp_attempts = 0
    user.reset_otp_verified = False
    # Invalidate any reset token left over from an earlier, abandoned attempt.
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    record_send(user, "reset_otp")
    db.session.commit()

    try:
        send_password_reset_email(user.email, code)
    except Exception as exc:  # noqa: BLE001
        log_mail_failure("password-reset", user.email, exc)
        user.reset_otp_hash = None
        user.reset_otp_expires_at = None
        release_cooldown(user, "reset_otp")
        db.session.commit()
        log_action("OTP_EMAIL_FAILED", actor_id=user.id, actor_email=user.email,
                   resource_type="user", resource_id=user.id, details="purpose=password-reset")
        return _delivery_failed(exc, "password-reset")
    return None


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Revoke the presented access token so a stolen copy stops working immediately."""
    claims = get_jwt()
    now = datetime.utcnow()
    expires = datetime.utcfromtimestamp(claims["exp"])
    if not db.session.get(RevokedToken, claims["jti"]):
        db.session.add(RevokedToken(jti=claims["jti"], user_id=claims.get("sub"), expires_at=expires))
    RevokedToken.query.filter(RevokedToken.expires_at < now).delete()   # purge rows that can no longer matter
    db.session.commit()
    log_action("LOGOUT", actor_id=claims.get("sub"), resource_type="user", resource_id=claims.get("sub"))
    return jsonify({"message": "Logged out"}), 200


@auth_bp.route("/register", methods=["POST"])
@ip_rate_limit("register", 10, 900)
def register():
    data = json_body()
    full_name = text_field(data, "full_name", 120)
    email = _normalise_email(text_field(data, "email", 254))
    password = data.get("password", "")

    # SECURITY: the role is never taken from the client here. Public
    # self-registration can only ever create an Investigator account; Admin
    # accounts are provisioned separately (create_admin.py / ADMIN_EMAIL seed
    # / the /api/admin endpoints).
    role = "investigator"

    if not full_name or not data.get("email") or not password:
        return jsonify({"error": "full_name, email and password are required"}), 400
    if not email:
        return jsonify({"error": "Please enter a valid email address"}), 400
    pw_error = _password_error(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    user = User.query.filter_by(email=email).first()
    if user and user.is_email_verified:
        return jsonify({"error": "An account with this email already exists"}), 409

    if user:
        # An earlier signup for this address was never verified (e.g. the
        # e-mail never arrived). Let the person start over instead of being
        # locked out by a half-created account. Nobody can log in to it until
        # the OTP sent to this mailbox is entered, so re-using the row is safe.
        user.full_name = full_name
        user.password_hash = password_hash
    else:
        # SBVM circular-theorem credentials (paper Section III-C): a random
        # origin point (Ox, Oy). Drawn from the OS CSPRNG, not `random`.
        rng = secrets.SystemRandom()
        user = User(
            full_name=full_name,
            email=email,
            password_hash=password_hash,
            role=role,
            origin_x=round(rng.uniform(-100, 100), 4),
            origin_y=round(rng.uniform(-100, 100), 4),
            is_email_verified=False,
        )
        db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:  # two signups for the same address raced
        db.session.rollback()
        return jsonify({"error": "An account with this email already exists"}), 409

    failure = _issue_signup_otp(user)
    if failure:
        return failure

    log_action("REGISTER", actor_id=user.id, actor_email=email, resource_type="user", resource_id=user.id)
    return jsonify({
        "message": "Account created. Check your email for the verification code.",
        "email_sent": True,
        "user_id": user.id,
        "expires_in_minutes": current_app.config["OTP_TTL_MINUTES"],
        "resend_available_in": current_app.config["OTP_RESEND_COOLDOWN_SECONDS"],
    }), 201


@auth_bp.route("/verify-otp", methods=["POST"])
@ip_rate_limit("otp-verify", 30, 900)
def verify_otp():
    data = json_body()
    email = _normalise_email(text_field(data, "email", 254)) or ""
    otp_code = text_field(data, "otp_code", 12)

    if not email or not OTP_FORMAT.match(otp_code):
        return jsonify({"error": "Enter the 6-digit code from your email"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid or expired code"}), 400

    if user.is_email_verified:
        # Deliberately NOT a success: a verified account has no live OTP, so a
        # replayed code is refused rather than "verified again".
        return jsonify({"error": "This email is already verified. Please log in.",
                        "code": "ALREADY_VERIFIED"}), 400

    max_attempts = current_app.config["OTP_MAX_ATTEMPTS"]
    if not user.otp_hash or not user.otp_expires_at:
        return jsonify({"error": "No active code for this account. Please request a new one.",
                        "code": "OTP_NOT_REQUESTED"}), 400

    if user.otp_expires_at < datetime.utcnow():
        user.otp_hash = None
        user.otp_expires_at = None
        user.otp_attempts = 0
        db.session.commit()
        return jsonify({"error": "This code has expired. Please request a new one.",
                        "code": "OTP_EXPIRED"}), 400

    if (user.otp_attempts or 0) >= max_attempts:
        user.otp_hash = None
        user.otp_expires_at = None
        user.otp_attempts = 0
        db.session.commit()
        return jsonify({"error": "Too many incorrect attempts. Please request a new code.",
                        "code": "OTP_LOCKED"}), 429

    if not check_otp(user.otp_hash, otp_code, PURPOSE_SIGNUP, email):
        user.otp_attempts = (user.otp_attempts or 0) + 1
        if user.otp_attempts >= max_attempts:
            user.otp_hash = None  # burn the code; the attacker needs a fresh e-mail
            user.otp_expires_at = None
            user.otp_attempts = 0
            db.session.commit()
            log_action("OTP_LOCKOUT", actor_id=user.id, actor_email=email,
                       resource_type="user", resource_id=user.id, details="purpose=signup")
            return jsonify({"error": "Too many incorrect attempts. Please request a new code.",
                            "code": "OTP_LOCKED"}), 429
        db.session.commit()
        remaining = max_attempts - user.otp_attempts
        return jsonify({"error": f"Invalid code. {remaining} attempt(s) remaining.",
                        "code": "OTP_INVALID"}), 400

    # Correct and unexpired: consume it so it can never be used again.
    user.is_email_verified = True
    user.otp_hash = None
    user.otp_code = None
    user.otp_expires_at = None
    user.otp_attempts = 0
    db.session.commit()

    log_action("VERIFY_OTP", actor_id=user.id, actor_email=email, resource_type="user", resource_id=user.id)
    return jsonify({"message": "Email verified successfully. You can now log in."}), 200


@auth_bp.route("/resend-otp", methods=["POST"])
@ip_rate_limit("otp-send", 10, 900)
def resend_otp():
    data = json_body()
    email = _normalise_email(text_field(data, "email", 254)) or ""
    user = User.query.filter_by(email=email).first() if email else None
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.is_email_verified:
        return jsonify({"error": "This email is already verified. Please log in.",
                        "code": "ALREADY_VERIFIED"}), 400

    failure = _issue_signup_otp(user)
    if failure:
        return failure
    return jsonify({
        "message": "A new code has been sent to your email.",
        "email_sent": True,
        "resend_available_in": current_app.config["OTP_RESEND_COOLDOWN_SECONDS"],
    }), 200


@auth_bp.route("/forgot-password", methods=["POST"])
@ip_rate_limit("otp-send", 10, 900)
def forgot_password():
    """Step 1: user submits their registered email. We look the account up,
    generate a fresh OTP, store only its hash, and email the plaintext code
    to that exact registered address."""
    data = json_body()
    raw_email = text_field(data, "email", 254)
    if not raw_email:
        return jsonify({"error": "Email is required"}), 400
    email = _normalise_email(raw_email)
    if not email:
        return jsonify({"error": "Please enter a valid email address"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # The registration flow already reveals whether an email is taken
        # (409 "account already exists"), so this project's threat model
        # doesn't treat email-enumeration as sensitive; the error stays
        # explicit so the user gets clear feedback.
        return jsonify({"error": "No account found with this email address"}), 404
    if not user.is_active:
        return jsonify({"error": "This account has been disabled. Contact your administrator."}), 403

    failure = _issue_reset_otp(user)
    if failure:
        return failure

    log_action("FORGOT_PASSWORD_REQUEST", actor_id=user.id, actor_email=email,
               resource_type="user", resource_id=user.id)
    return jsonify({
        "success": True,
        "email_sent": True,
        "message": "A password reset code has been sent to your registered email.",
        "expires_in_minutes": current_app.config["OTP_TTL_MINUTES"],
        "resend_available_in": current_app.config["OTP_RESEND_COOLDOWN_SECONDS"],
    }), 200


@auth_bp.route("/verify-reset-otp", methods=["POST"])
@ip_rate_limit("otp-verify", 30, 900)
def verify_reset_otp():
    """Step 2: user submits the OTP they received. On success we issue a
    short-lived, single-use reset token that /reset-password requires,
    instead of letting the OTP itself be reused for the password change."""
    data = json_body()
    email = _normalise_email(text_field(data, "email", 254)) or ""
    otp_code = text_field(data, "otp_code", 12)

    if not email or not OTP_FORMAT.match(otp_code):
        return jsonify({"error": "Enter the 6-digit code from your email"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No account found with this email address"}), 404
    if not user.is_active:
        return jsonify({"error": "This account has been disabled. Contact your administrator."}), 403

    max_attempts = current_app.config["OTP_MAX_ATTEMPTS"]
    if not user.reset_otp_hash or not user.reset_otp_expires_at:
        return jsonify({"error": "No password reset was requested. Please request a new code.",
                        "code": "OTP_NOT_REQUESTED"}), 400

    if user.reset_otp_expires_at < datetime.utcnow():
        user.reset_otp_hash = None
        user.reset_otp_expires_at = None
        user.reset_otp_attempts = 0
        db.session.commit()
        return jsonify({"error": "This code has expired. Please request a new one.",
                        "code": "OTP_EXPIRED"}), 400

    if (user.reset_otp_attempts or 0) >= max_attempts:
        user.reset_otp_hash = None
        user.reset_otp_expires_at = None
        user.reset_otp_attempts = 0
        db.session.commit()
        return jsonify({"error": "Too many incorrect attempts. Please request a new code.",
                        "code": "OTP_LOCKED"}), 429

    if not check_otp(user.reset_otp_hash, otp_code, PURPOSE_RESET, email):
        user.reset_otp_attempts = (user.reset_otp_attempts or 0) + 1
        if user.reset_otp_attempts >= max_attempts:
            user.reset_otp_hash = None
            user.reset_otp_expires_at = None
            user.reset_otp_attempts = 0
            db.session.commit()
            log_action("OTP_LOCKOUT", actor_id=user.id, actor_email=email,
                       resource_type="user", resource_id=user.id, details="purpose=password-reset")
            return jsonify({"error": "Too many incorrect attempts. Please request a new code.",
                            "code": "OTP_LOCKED"}), 429
        db.session.commit()
        remaining = max_attempts - user.reset_otp_attempts
        return jsonify({"error": f"Invalid code. {remaining} attempt(s) remaining.",
                        "code": "OTP_INVALID"}), 400

    # OTP is correct and unexpired - consume it immediately so it cannot be
    # verified a second time, and issue a one-time reset token instead.
    reset_token = secrets.token_urlsafe(32)
    user.reset_token_hash = hash_token(reset_token)
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=10)
    user.reset_otp_verified = True
    user.reset_otp_hash = None
    user.reset_otp_expires_at = None
    user.reset_otp_attempts = 0
    db.session.commit()

    log_action("VERIFY_RESET_OTP", actor_id=user.id, actor_email=email,
               resource_type="user", resource_id=user.id)
    return jsonify({
        "message": "Code verified. You can now set a new password.",
        "reset_token": reset_token,
    }), 200


@auth_bp.route("/reset-password", methods=["POST"])
@ip_rate_limit("otp-verify", 30, 900)
def reset_password():
    """Step 3: user submits the reset token from step 2 plus a new password."""
    data = json_body()
    email = _normalise_email(text_field(data, "email", 254)) or ""
    reset_token = text_field(data, "reset_token", 200)
    new_password = data.get("new_password", "")

    pw_error = _password_error(new_password)
    if pw_error:
        return jsonify({"error": pw_error[0].upper() + pw_error[1:]}), 400

    user = User.query.filter_by(email=email).first() if email else None
    if not user:
        return jsonify({"error": "No account found with this email address"}), 404
    if not user.is_active:
        return jsonify({"error": "This account has been disabled. Contact your administrator."}), 403

    if not user.reset_otp_verified or not user.reset_token_hash:
        return jsonify({"error": "OTP verification is required before resetting your password."}), 400

    if not user.reset_token_expires_at or user.reset_token_expires_at < datetime.utcnow():
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        user.reset_otp_verified = False
        db.session.commit()
        return jsonify({"error": "Your reset session has expired. Please start again."}), 400

    if not check_token(user.reset_token_hash, reset_token):
        return jsonify({"error": "Invalid reset session. Please start again."}), 400

    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    # Clear every reset-related field so nothing here can be replayed.
    user.reset_otp_hash = None
    user.reset_otp_expires_at = None
    user.reset_otp_attempts = 0
    user.reset_otp_verified = False
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.session.commit()

    log_action("PASSWORD_RESET", actor_id=user.id, actor_email=email,
               resource_type="user", resource_id=user.id)
    return jsonify({"message": "Password has been reset successfully. You can now log in."}), 200


def _matching_totp_step(secret: str, code) -> int:
    """Return the 30-second time-step a TOTP code belongs to (within +-1 step), else None.
    Needed so a code can be recorded as used and never accepted twice."""
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    now = time.time()
    for offset in (-1, 0, 1):
        moment = now + offset * 30
        if secrets.compare_digest(totp.at(moment), code):
            return int(moment // 30)
    return None


@auth_bp.route("/login", methods=["POST"])
@ip_rate_limit("login-ip", 30, 300)
def login():
    data = json_body()
    email = text_field(data, "email", 254).lower()
    password = data.get("password", "") if isinstance(data.get("password", ""), str) else ""
    totp_code = data.get("totp_code")  # required only if MFA is enabled

    user = User.query.filter_by(email=email).first()
    # Per-account throttle: stops distributed guessing against one user even from many IPs.
    limited = hit_limit("login-account", email, 10, 900)
    if limited:
        return limited
    too_long = len(password.encode("utf-8")) > MAX_PASSWORD_BYTES  # bcrypt>=5 raises on >72 bytes
    if not user or too_long or not bcrypt.check_password_hash(user.password_hash, password):
        log_action("LOGIN_FAILED", actor_email=email, details="bad credentials")
        return jsonify({"error": "Invalid email or password"}), 401
    if not user.is_active:
        log_action("LOGIN_FAILED", actor_id=user.id, actor_email=email, details="account disabled")
        return jsonify({"error": "This account has been disabled. Contact your administrator."}), 403
    if not user.is_email_verified:
        return jsonify({"error": "Email not verified. Please verify your OTP first.",
                        "code": "EMAIL_NOT_VERIFIED"}), 403

    if user.mfa_enabled:
        if not totp_code:
            return jsonify({"error": "TOTP code required", "mfa_required": True}), 401
        step = _matching_totp_step(user.mfa_secret, totp_code)
        if step is None or step <= (user.mfa_last_used_step or 0):   # wrong code, OR a code already used (replay)
            log_action("LOGIN_FAILED", actor_id=user.id, actor_email=email, details="bad TOTP")
            return jsonify({"error": "Invalid MFA code"}), 401
        user.mfa_last_used_step = step   # burn this code (and every older one)
        db.session.commit()

    access_token = create_access_token(
        identity=user.id,
        additional_claims={"role": user.role, "email": user.email},
    )
    log_action("LOGIN_SUCCESS", actor_id=user.id, actor_email=email)
    return jsonify({"access_token": access_token, "user": user.to_dict()}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict()), 200


@auth_bp.route("/email-diagnostics", methods=["GET"])
@role_required("admin")
def email_diagnostics():
    """Admin-only, live SMTP diagnostic check (requirement: "actually test
    the email service", not just confirm env vars exist). Never returns the
    configured username or password - only booleans, config values that are
    safe to see (server/port/tls), and a categorized error if the live
    connection+login attempt fails."""
    return jsonify(mail_config_status()), 200
