"""Exercise the REAL smtplib transport (connect, STARTTLS with certificate
verification, AUTH LOGIN/PLAIN, send) against a local aiosmtpd server.

This proves the code path Gmail uses works end-to-end - it does NOT prove that
Gmail accepts your credentials; see README "Verify Gmail delivery".
"""
import datetime
import ipaddress
import re
import socket
import ssl

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import create_app
from app.extensions import db
from app.services import otp_service
from app.services.otp_service import describe_mail_error, mail_config_status, send_otp_email, send_password_reset_email
from tests.conftest import make_config

USER, PASSWORD = "otp.sender@gmail.example", "abcdefghijklmnop"


class Sink:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        return "250 OK"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def authenticator(server, session, envelope, mechanism, auth_data):
    if isinstance(auth_data, LoginPassword) and auth_data.login == USER.encode() \
            and auth_data.password == PASSWORD.encode():
        return AuthResult(success=True)
    return AuthResult(success=False, handled=False)


@pytest.fixture()
def plain_server():
    sink, port = Sink(), free_port()
    ctl = Controller(sink, hostname="127.0.0.1", port=port)
    ctl.start()
    yield sink, port
    ctl.stop()


@pytest.fixture()
def tls_server(tmp_path):
    cert, key = make_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sink, port = Sink(), free_port()
    ctl = Controller(sink, hostname="127.0.0.1", port=port, require_starttls=True, tls_context=ctx,
                     authenticator=authenticator, auth_required=True, auth_require_tls=True)
    ctl.start()
    yield sink, port, cert
    ctl.stop()


def smtp_app(tmp_path, port, **overrides):
    cfg = dict(MAIL_SUPPRESS_SEND=False, MAIL_SERVER="127.0.0.1", MAIL_PORT=port, MAIL_USE_TLS=False,
               MAIL_USE_SSL=False, MAIL_REQUIRE_AUTH=False, MAIL_USERNAME=None, MAIL_PASSWORD=None,
               MAIL_DEFAULT_SENDER=USER, MAIL_TIMEOUT_SECONDS=5)
    cfg.update(overrides)
    app = create_app(make_config(tmp_path, **cfg))
    return app


def test_otp_email_is_delivered_over_real_smtp_to_the_right_recipient(tmp_path, plain_server):
    sink, port = plain_server
    app = smtp_app(tmp_path, port)
    with app.app_context():
        send_otp_email("new.user@example.com", "314159")
        send_password_reset_email("forgetful@example.com", "271828")
    assert [m.rcpt_tos for m in sink.messages] == [["new.user@example.com"], ["forgetful@example.com"]]
    first = sink.messages[0].content.decode()
    assert "314159" in first and "verification code" in first and f"From:" in first and "Message-ID:" in first
    assert "271828" in sink.messages[1].content.decode()
    assert sink.messages[0].mail_from == USER


def test_no_login_attempted_when_auth_not_required_even_if_username_is_set(tmp_path, plain_server):
    sink, port = plain_server  # this server does not offer AUTH at all
    app = smtp_app(tmp_path, port, MAIL_REQUIRE_AUTH=False, MAIL_USERNAME=USER, MAIL_PASSWORD="whatever")
    with app.app_context():
        send_otp_email("someone@example.com", "123456")
    assert len(sink.messages) == 1


def test_starttls_with_certificate_verification_and_login_succeeds(tmp_path, tls_server, monkeypatch):
    sink, port, cert = tls_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))  # trust the test CA, exactly like a real CA bundle
    app = smtp_app(tmp_path, port, MAIL_USE_TLS=True, MAIL_REQUIRE_AUTH=True,
                   MAIL_USERNAME=USER, MAIL_PASSWORD=PASSWORD)
    with app.app_context():
        status = mail_config_status()
        assert status["connection_ok"] is True and status["error"] is None
        assert USER not in str(status) and PASSWORD not in str(status)  # booleans only, no secrets
        send_otp_email("someone@example.com", "123456")
    assert len(sink.messages) == 1 and sink.messages[0].rcpt_tos == ["someone@example.com"]
    assert "123456" in sink.messages[0].content.decode()


def test_wrong_password_gives_actionable_error_without_leaking_it(tmp_path, tls_server, monkeypatch, caplog):
    sink, port, cert = tls_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    app = smtp_app(tmp_path, port, MAIL_USE_TLS=True, MAIL_REQUIRE_AUTH=True,
                   MAIL_USERNAME=USER, MAIL_PASSWORD="not-the-right-password")
    with app.app_context():
        with pytest.raises(Exception) as err:
            send_otp_email("someone@example.com", "123456")
        message = describe_mail_error(err.value)
        assert "authentication failed" in message.lower() and "App Password" in message
        assert "not-the-right-password" not in message
        otp_service.log_mail_failure("signup", "someone@example.com", err.value)
    assert "not-the-right-password" not in caplog.text and "123456" not in caplog.text
    assert "s***@example.com" in caplog.text  # recipient is masked in logs
    assert not sink.messages


def test_untrusted_certificate_is_rejected_unlike_flask_mail_default(tmp_path, tls_server):
    """The server's self-signed certificate is NOT in the trust store here, so a
    verifying client must refuse to send credentials/OTP over that channel."""
    sink, port, _cert = tls_server
    app = smtp_app(tmp_path, port, MAIL_USE_TLS=True, MAIL_REQUIRE_AUTH=True,
                   MAIL_USERNAME=USER, MAIL_PASSWORD=PASSWORD)
    with app.app_context():
        with pytest.raises(ssl.SSLCertVerificationError) as err:
            send_otp_email("someone@example.com", "123456")
        assert "certificate verification failed" in describe_mail_error(err.value)
    assert not sink.messages


def test_unreachable_server_fails_fast_with_clear_message(tmp_path):
    app = smtp_app(tmp_path, free_port(), MAIL_TIMEOUT_SECONDS=3)
    with app.app_context():
        with pytest.raises(ConnectionRefusedError) as err:
            send_otp_email("someone@example.com", "123456")
        assert "refused" in describe_mail_error(err.value)


def test_missing_or_placeholder_credentials_are_reported_not_attempted(tmp_path):
    for username, password in [(None, None), ("your_email@gmail.com", "your_app_password")]:
        app = smtp_app(tmp_path, 1, MAIL_REQUIRE_AUTH=True, MAIL_USERNAME=username, MAIL_PASSWORD=password,
                       MAIL_DEFAULT_SENDER=username or "x@example.com")
        with app.app_context():
            status = mail_config_status()
            assert status["connection_ok"] is False
            assert "placeholder" in status["error"] or "missing" in status["error"]
            assert status["mail_username_configured"] is False and status["mail_password_configured"] is False


def test_end_to_end_register_over_real_smtp(tmp_path, plain_server):
    """Register through the HTTP API with real SMTP delivery, read the OTP from the
    'inbox' (the SMTP sink) and verify - the whole signup path, no mocks."""
    sink, port = plain_server
    app = smtp_app(tmp_path, port)
    with app.app_context():
        db.create_all()
        c = app.test_client()
        r = c.post("/api/auth/register", json={"full_name": "E2E", "email": "e2e@example.com",
                                               "password": "CorrectHorse-9"})
        assert r.status_code == 201 and r.get_json()["email_sent"] is True
        assert sink.messages[0].rcpt_tos == ["e2e@example.com"]
        code = re.search(r"code is: (\d{6})", sink.messages[0].content.decode()).group(1)
        assert code not in r.get_data(as_text=True)
        v = c.post("/api/auth/verify-otp", json={"email": "e2e@example.com", "otp_code": code})
        assert v.status_code == 200
        assert c.post("/api/auth/login", json={"email": "e2e@example.com", "password": "CorrectHorse-9"}).status_code == 200
