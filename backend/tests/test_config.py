"""Environment parsing: the mistakes that silently break Gmail SMTP."""
import pytest

from app import config


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ["MAIL_SERVER", "SMTP_HOST", "MAIL_PORT", "SMTP_PORT", "MAIL_USE_TLS", "MAIL_USE_SSL",
                 "MAIL_USERNAME", "SMTP_USERNAME", "MAIL_PASSWORD", "SMTP_PASSWORD"]:
        monkeypatch.delenv(name, raising=False)


def test_gmail_app_password_with_spaces_and_quotes_is_normalised(monkeypatch):
    monkeypatch.setenv("MAIL_PASSWORD", '"abcd efgh ijkl mnop"')
    assert config._mail_password() == "abcdefghijklmnop"
    monkeypatch.setenv("MAIL_PASSWORD", "  abcd efgh ijkl mnop \r\n")
    assert config._mail_password() == "abcdefghijklmnop"


def test_non_gmail_password_keeps_internal_spaces(monkeypatch):
    monkeypatch.setenv("MAIL_SERVER", "smtp.example.org")
    monkeypatch.setenv("MAIL_PASSWORD", "pass phrase")
    assert config._mail_password() == "pass phrase"


@pytest.mark.parametrize("port,tls,ssl_,expect", [
    ("587", "True", "False", (True, False)),
    ("465", "True", "False", (False, True)),    # 465 + STARTTLS is a classic mistake -> implicit SSL
    ("587", "True", "True", (True, False)),     # 587 + implicit SSL -> STARTTLS
    ("2525", "false", "false", (False, False)),
])
def test_tls_ssl_flags_are_made_consistent_with_the_port(monkeypatch, port, tls, ssl_, expect):
    monkeypatch.setenv("MAIL_PORT", port)
    monkeypatch.setenv("MAIL_USE_TLS", tls)
    monkeypatch.setenv("MAIL_USE_SSL", ssl_)
    assert config._mail_security() == expect


def test_smtp_style_variable_names_are_accepted_as_aliases(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "me@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", "abcd efgh ijkl mnop")
    assert config._env("MAIL_SERVER", "SMTP_HOST") == "smtp.gmail.com"
    assert config._mail_port() == 587
    assert config._env("MAIL_USERNAME", "SMTP_USERNAME") == "me@gmail.com"
    assert config._mail_password() == "abcdefghijklmnop"


def test_placeholder_detection():
    for v in [None, "", "your_email@gmail.com", "YOUR_APP_PASSWORD", "change_this_to_a_long_random_string"]:
        assert config.is_placeholder(v)
    assert not config.is_placeholder("real-value")


def test_invalid_port_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("MAIL_PORT", "not-a-number")
    assert config._mail_port() == 587
