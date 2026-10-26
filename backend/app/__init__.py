import logging

from flask import Flask, jsonify
from app.config import Config, is_placeholder
from app.extensions import db, jwt, bcrypt, mail, cors, migrate


def _check_secrets(app) -> None:
    """Refuse to run production with default/placeholder signing secrets and
    warn loudly in development. Values are never printed."""
    weak = [name for name in ("SECRET_KEY", "JWT_SECRET_KEY")
            if is_placeholder(app.config.get(name)) or len(app.config.get(name) or "") < 16]
    if not weak:
        return
    message = (f"{' and '.join(weak)} is unset, still a placeholder, or shorter than 16 characters. "
               f"Generate real secrets: python -c \"import secrets; print(secrets.token_hex(32))\"")
    if app.config.get("IS_PRODUCTION") and not app.config.get("TESTING"):
        raise RuntimeError(message)
    app.logger.warning(message)


def create_app(config_class=Config):
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app = Flask(__name__)
    app.config.from_object(config_class)
    _check_secrets(app)

    db.init_app(app)
    migrate.init_app(app, db, compare_type=True)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    cors.init_app(
        app,
        resources={r"/api/*": {
            "origins": app.config["FRONTEND_ORIGINS"],
            # The browser may only read these response headers from JS if they
            # are exposed; the download/preview code relies on them.
            "expose_headers": ["Content-Disposition", "X-Evidence-SHA256", "X-Evidence-Status"],
        }},
    )

    from app.models import User, Evidence, LedgerBlock, AuditLog, DigitalSignature, KeyRecord, RevokedToken  # noqa: F401

    @jwt.token_in_blocklist_loader
    def _reject_deactivated_users(jwt_header, jwt_payload):
        """Runs automatically for every @jwt_required()-protected request
        across the whole app (evidence, audit, mfa, signatures, reports,
        /auth/me, /api/admin/*). If an Admin deactivates an Invigilator,
        this makes that lockout immediate - the invigilator's existing
        access token stops working right away instead of staying valid
        until it naturally expires (JWT_ACCESS_TOKEN_EXPIRES = 8h)."""
        if db.session.get(RevokedToken, jwt_payload.get("jti")) is not None:   # logged out
            return True
        user = User.query.get(jwt_payload.get("sub"))
        return user is None or not user.is_active

    @app.after_request
    def _security_headers(response):
        """Defence-in-depth headers on every API response. (The SPA's own headers come from
        docker/nginx.conf; a CSP there is still an open item - docs/SECURITY_REPORT.md F-10.)"""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    from app.routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.admin_routes import admin_bp
    app.register_blueprint(admin_bp)

    from app.routes.evidence_routes import evidence_bp
    app.register_blueprint(evidence_bp)

    from app.routes.mfa_routes import mfa_bp
    app.register_blueprint(mfa_bp)

    from app.routes.signature_routes import signature_bp
    app.register_blueprint(signature_bp)

    from app.routes.audit_routes import audit_bp
    app.register_blueprint(audit_bp)

    from app.routes.report_routes import report_bp
    app.register_blueprint(report_bp)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "forensic-secure-storage-backend"}), 200

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def too_large(e):
        limit = app.config.get("MAX_UPLOAD_MB")
        return jsonify({"error": f"The upload is too large. The maximum allowed size is {limit} MB.",
                        "code": "FILE_TOO_LARGE"}), 413

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app
