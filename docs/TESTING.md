# Testing Guide

## Prerequisites

Backend running at `http://localhost:5000` (via `python run.py` or
`docker compose up`). All examples below assume that base URL — adjust if
you deployed elsewhere.

## Sample test users

| Role | Email | Password |
|---|---|---|
| Investigator | jane@example.com | password123 |
| Admin | admin@example.com | password123 |

(These aren't pre-seeded — create them via `/api/auth/register` as shown below.)

## Sample evidence file

Any file works for a demo. A quick one to generate on the fly:

```bash
echo "This is fake forensic evidence content for testing purposes." > sample_evidence.txt
```

## Full curl walkthrough

```bash
BASE=http://localhost:5000/api

# 1. Register
curl -s -X POST $BASE/auth/register \
  -H "Content-Type: application/json" \
  -d '{"full_name":"Jane Investigator","email":"jane@example.com","password":"password123"}'
# The OTP is e-mailed to the address above; it is never returned by the API.

# 2. Verify OTP (replace 000000 with the real code from your email)
curl -s -X POST $BASE/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","otp_code":"000000"}'

# 3. Login
TOKEN=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"password123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Token: $TOKEN"

# 4. Upload evidence
EVIDENCE_ID=$(curl -s -X POST $BASE/evidence/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "case_number=CASE-2026-001" \
  -F "title=Suspect laptop RAM dump" \
  -F "description=Captured during raid" \
  -F "file=@sample_evidence.txt" | python3 -c "import sys,json; print(json.load(sys.stdin)['evidence']['id'])")
echo "Evidence ID: $EVIDENCE_ID"

# 5. Verify integrity (should show hash_match: true)
curl -s -X POST $BASE/evidence/$EVIDENCE_ID/verify -H "Authorization: Bearer $TOKEN"

# 6. Sign the evidence
curl -s -X POST $BASE/signatures/$EVIDENCE_ID/sign -H "Authorization: Bearer $TOKEN"

# 7. Verify the signature
curl -s $BASE/signatures/$EVIDENCE_ID/verify -H "Authorization: Bearer $TOKEN"

# 8. View the blockchain ledger
curl -s $BASE/evidence/$EVIDENCE_ID/ledger -H "Authorization: Bearer $TOKEN"

# 9. Check peer node consistency
curl -s $BASE/evidence/$EVIDENCE_ID/nodes -H "Authorization: Bearer $TOKEN"

# 10. Download the PDF report
curl -s $BASE/reports/$EVIDENCE_ID -H "Authorization: Bearer $TOKEN" -o report.pdf
echo "Report saved to report.pdf"
```

## Demo flow for a viva / presentation

This mirrors what a grader will want to see, in order:

1. **Register an investigator** — show the registration form, submit
2. **Verify OTP** — check the email inbox (the OTP is only delivered by e-mail, so configure
   `.env` first) and enter the code
3. **Login** — show the JWT being issued
4. **Upload evidence** — pick a file, fill in case number/title, submit;
   point out that the file is hashed, encrypted, and replicated to 3 nodes
   before it's ever written to permanent storage
5. **Show the SHA-256 hash** — visible on the Evidence Details page
6. **Show the encrypted file on disk** — `docker compose exec backend ls storage/uploads/`
   or `ls backend/storage/uploads/` locally; open one with `cat` to show it's
   unreadable ciphertext
7. **Show the blockchain ledger entry** — the UPLOAD block on the Evidence
   Details page, with its hash chained from the genesis hash
8. **Click "Verify Integrity"** — show it passes (hash_match: true, ledger
   valid, peer nodes consistent)
9. **Tamper with the file and show failure** — append bytes directly to the
   `.enc` file on disk (`echo "corrupted" >> backend/storage/uploads/<file>.enc`),
   then click Verify again — show it now reports `ciphertext_corrupted: true`
   and status flips to `tampered`
10. **Show audit logs** — log in as the admin account, open Audit Logs, show
    every action (register, login, upload, verify) with timestamps and IPs
11. **Generate a PDF report** — click "Download PDF Report", open it, walk
    through the case details, hash, ledger, and signature sections
12. **Verify the digital signature** — show the RSA signature status as
    "Valid", then (optionally) explain that if the file were re-signed with a
    different key or the hash changed, verification would fail

## Postman

Import `docs/postman_collection.json` into Postman. Set the collection
variable `baseUrl` (defaults to `http://localhost:5000/api`). After logging
in via the "Login" request, copy the `access_token` from the response into
the `token` collection variable — every other request already references
`{{token}}` in its Authorization header.


## Evidence view / download (curl)

```bash
# list what you may access, then view (inline preview types only) / download
curl -s $BASE/evidence -H "Authorization: Bearer $TOKEN"
curl -s $BASE/evidence/$EVIDENCE_ID/view     -H "Authorization: Bearer $TOKEN" -o preview.out
curl -s $BASE/evidence/$EVIDENCE_ID/download -H "Authorization: Bearer $TOKEN" -OJ -D headers.txt
# compare with the hash the server reports
grep -i x-evidence-sha256 headers.txt ; sha256sum sample_evidence.txt
```

Windows CMD equivalents use `curl.exe` and `certutil -hashfile sample_evidence.txt SHA256`.
Expected errors: 401 no/invalid token, 403 `ACCESS_DENIED` (not your evidence), 415 `PREVIEW_UNSUPPORTED`
(use download), 409 `INTEGRITY_MISMATCH` (stored copy no longer matches its upload hash).

## Automated tests

`cd backend && pip install -r requirements-dev.txt && python run_tests.py` (same on Windows CMD and Linux; writes
`backend/test-results/summary.md` with passed/failed/skipped per module) - covers OTP, password reset,
SMTP transport (local server), upload validation, access control, integrity and audit logging.
