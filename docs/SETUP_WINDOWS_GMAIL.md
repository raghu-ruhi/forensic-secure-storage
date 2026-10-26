# Setup on Windows (CMD) with Docker Compose and Gmail OTP e-mail

## 1. Create a Gmail App Password (one time)
1. Sign in to the Google account that will SEND the OTP e-mails.
2. Turn on **2-Step Verification**: <https://myaccount.google.com/security>.
3. Open <https://myaccount.google.com/apppasswords>, create an app password (name it e.g. `forensic-storage`).
4. Google shows 16 letters like `abcd efgh ijkl mnop`. Copy them. (Spaces don't matter.)
   Your normal Gmail password will NOT work for SMTP. Workspace accounts may need the admin to allow app passwords.

## 2. Create your `.env`
Open CMD in the project folder (the one containing `docker-compose.yml`):
```
copy .env.example .env
notepad .env
```
Set at least:
```
SECRET_KEY=<64 random hex characters>
JWT_SECRET_KEY=<another 64 random hex characters>
MAIL_USERNAME=yourname@gmail.com
MAIL_PASSWORD=abcdefghijklmnop
ADMIN_EMAIL=you@example.com          (optional first admin)
ADMIN_PASSWORD=ChooseAStrongOne1
```
Generate the two keys with (requires Python): `python -c "import secrets; print(secrets.token_hex(32))"`
Save the file as plain text named exactly `.env` (not `.env.txt`; in Notepad choose "All files").

## 3. Start, then test the e-mail BEFORE using the UI
```
docker compose version
docker compose up --build -d
docker compose ps
docker compose exec backend python check_email.py
docker compose exec backend python check_email.py --send-to yourname@gmail.com
```
`check_email.py` must print `SMTP connect + login : OK` and the second command must put a test mail in your inbox
(check Spam). It never prints your password.
Open <http://localhost:5173>, register, and the 6-digit code arrives by e-mail.

## 4. After changing `.env`
```
docker compose up -d --force-recreate backend
```
(`docker compose restart` does NOT re-read `.env`.)  Logs: `docker compose logs -f backend`.

## 5. Run the automated tests (optional)
```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest
```
(The SQLite-based tests need no Docker, Postgres or Gmail.)

## Troubleshooting
| Symptom shown in the UI / `check_email.py` | Fix |
|---|---|
| `placeholder values` / `missing` | `.env` not in the project root, still has the example values, or backend not recreated |
| `App Password is required` / `authentication failed` | Use the 16-character App Password; confirm 2-Step Verification is on; `MAIL_USERNAME` is the full address |
| `Could not resolve` / `timed out` | Container has no internet, or a firewall/VPN/antivirus blocks outbound port 587 |
| `TLS certificate verification failed` | Antivirus/proxy intercepting TLS - disable HTTPS scanning for the container or use a different network |
| `docker compose` complains about `env_file` `required` | Upgrade Docker Desktop (Compose >= 2.24) |
| Backend exits with `exec ./entrypoint.sh: no such file` | Fixed in the Dockerfile (CRLF normalised); rebuild with `--build` |
