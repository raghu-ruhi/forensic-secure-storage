#!/usr/bin/env python3
"""Check the e-mail (SMTP) configuration the backend ACTUALLY sees.

Run it where the backend runs, so you test the real environment:

    Docker :  docker compose exec backend python check_email.py
    Local  :  python check_email.py

    Add --send-to you@example.com to also send a real test message
    (it contains no OTP, only a short confirmation text).

It never prints the username, the password or any other secret - only whether
each setting is present - and it returns exit code 0 only when a real SMTP
login (and, with --send-to, a real send) succeeded.
"""
import argparse
import sys

from app import create_app
from app.services.otp_service import describe_mail_error, mail_config_status, send_email


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SMTP settings without exposing secrets.")
    parser.add_argument("--send-to", help="also send a test e-mail to this address")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        status = mail_config_status()
        print("Mail configuration seen by the backend process")
        print("----------------------------------------------")
        print(f"  MAIL_SERVER              : {status['mail_server']}")
        print(f"  MAIL_PORT                : {status['mail_port']}")
        print(f"  STARTTLS / implicit SSL  : {status['mail_use_tls']} / {status['mail_use_ssl']}")
        print(f"  MAIL_USERNAME set        : {status['mail_username_configured']}")
        print(f"  MAIL_PASSWORD set        : {status['mail_password_configured']}")
        print(f"  Sender address set       : {status['mail_sender_configured']}")
        print(f"  SMTP connect + login     : {'OK' if status['connection_ok'] else 'FAILED'}")
        if status["error"]:
            print(f"\nProblem: {status['error']}")
            return 1

        if args.send_to:
            try:
                send_email(
                    args.send_to,
                    "Forensic Secure Storage - SMTP test",
                    "This is a test message from check_email.py. If you can read it, "
                    "OTP e-mails will be delivered from this server.",
                )
            except Exception as exc:  # noqa: BLE001
                print(f"\nSending the test message failed: {describe_mail_error(exc)}")
                return 1
            print(f"\nTest message handed to the SMTP server for {args.send_to}. Check that inbox (and spam).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
