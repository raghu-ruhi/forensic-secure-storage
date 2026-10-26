# Security report (local, authorised testing of this project only)

**Scope and method.** Static analysis (`bandit`), dependency audit (`pip-audit`, `npm audit`), and active tests run
against a *local test instance* (Flask test client, SQLite/PostgreSQL, emulated S3, local SMTP sink) in
`backend/tests/test_security.py` and the other test modules. No external system, no real AWS, no production data.
**Not done:** a dynamic scan (e.g. OWASP ZAP) of the running Docker stack, browser-based XSS/CSRF testing, a penetration
test of a deployed EC2/S3 environment, load/DoS testing, peer-network testing (there is no network layer to test - Phase 4
is unimplemented).
"Verified" = reproduced by a test that failed before the fix. "Potential" = reasoning only, not reproduced.

## Verified findings

| ID | Severity | Issue | Reproduction (before fix) | Remediation | Retest |
|---|---|---|---|---|---|
| F-01 | High | **Unlimited password guessing** on `/auth/login` | 15 wrong passwords for one account, no 429 | Per-IP (30/5 min) and per-account (10/15 min) limiter | `test_login_is_rate_limited_per_ip_and_per_account` passes |
| F-02 | Medium | **No logout / token revocation**: a stolen JWT stays valid 8 h | `POST /auth/logout` -> 404 | `POST /auth/logout`, `revoked_tokens` table (migration 0003), blocklist check on every request, frontend calls it | `test_logout_revokes_the_token` passes |
| F-03 | Medium | **TOTP replay**: a valid code accepted repeatedly within its window | same code logged in twice -> 200/200 | Track last accepted time-step per user (`mfa_last_used_step`, migration 0004) | `test_a_totp_code_cannot_be_replayed` passes |
| F-04 | Medium | **Ledger is not tamper-proof against a DB writer**: a consistent rewrite of all hashes verifies as valid | `test_KNOWN_LIMITATION_consistent_full_rewrite_is_not_detected` | **OPEN.** Needs signed blocks and/or external anchoring - i.e. the Phase-4 distributed ledger. Naive edits, deletions and relinking *are* detected (tests) | n/a |
| F-05 | High | **Vulnerable dependencies**: Flask 3.0.3, cryptography 42.0.8, Flask-Cors 4.0.1, python-dotenv 1.0.1 (several advisories); 3 high npm advisories | `pip-audit`, `npm audit` | Pinned Flask 3.1.3, cryptography 50.0.0, Flask-Cors 6.0.2, python-dotenv 1.2.2; `npm audit fix` | `pip-audit`: *No known vulnerabilities*; `npm audit --omit=dev`: 0; full suite re-run green on the new versions |
| F-06 | Low | No hardening headers on API responses | `X-Content-Type-Options` absent | `after_request` headers; nginx headers for the SPA | `test_api_responses_carry_security_headers` |
| F-07 | Low | Old key generator selected "best of 5 CSPRNG candidates" and mixed them with Python's `random` | code review | Replaced by CSPRNG IKM + HKDF; optimizer output is public salt | `test_fixed_optimizer_seed_never_makes_keys_reproducible` etc. |

Fixed in the previous change and still covered by tests: unverified TLS in SMTP STARTTLS (F-08), any user could read
any evidence (F-09), OTP returned in API responses (F-11), password >72 bytes crashed registration (F-12).

## Open / potential items
| ID | Status | Item |
|---|---|---|
| F-04 | Open (verified) | Ledger weakness above |
| F-10 | Open (potential) | **No Content-Security-Policy** on the SPA. A strict CSP must permit the API origin and `blob:` frames for PDF preview and could not be browser-tested here. Recommended starting point: `default-src 'self'; img-src 'self' blob: data:; frame-src blob:; connect-src 'self' <api-origin>; frame-ancestors 'none'` |
| P-1 | Potential | JWT kept in `localStorage`: any XSS would expose it (React escapes output and no `dangerouslySetInnerHTML` was found, but this was not browser-tested). Mitigation: CSP (F-10) or HttpOnly cookies + CSRF protection |
| P-2 | Potential | Rate limiter state is in-process: with N gunicorn workers the effective limit is up to N x; per-account OTP limits are DB-backed and exact |
| P-3 | Potential | The master key is a file on the application host (`master.key`); compromise of host = compromise of all key wrapping. KMS-backed key wrapping is future work |
| P-4 | Potential | 8-hour access tokens, no refresh/rotation |
| P-5 | Potential | Fernet is AES-128-CBC+HMAC (comments elsewhere said AES-256) |
| P-6 | Info | `bandit`: 3 LOW `try/except/pass` in best-effort connection cleanup (`otp_service.py`), intentional |
| P-7 | Not applicable | **CSRF:** the API authenticates with an `Authorization: Bearer` header, not cookies, so classic CSRF does not apply (becomes relevant only if cookies are adopted per P-1) |
| P-8 | Not testable | Peer-communication security: no network peers exist (Phase 4) |

## Areas tested with no issue found
JWT: `alg=none`, edited payload, corrupted/forged signature, wrong secret, expired token, deleted user, role-claim forgery;
SQL injection payloads in login, evidence fields and path parameters (ORM-parameterised); path traversal (upload
filenames and tampered DB rows); malicious uploads (executables, HTML, SVG, extension/content mismatch, oversize, empty);
unauthorised evidence access across all evidence endpoints; OTP expiry/replay/lockout/rate limits; CORS (only configured
origins, no wildcard); production start refusing placeholder secrets; debug disabled by the factory; secrets absent from
responses and logs.
