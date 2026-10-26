# Amazon S3 evidence storage on EC2

> **Status: implemented and tested against an EMULATED S3 (moto), NOT against real AWS.**
> No AWS resources were created and nothing here was deployed by the authors of this change. Every command below
> is unexecuted; verify each step in your own account (section 8 gives a checklist that proves it works).

Read `AWS_DEPLOYMENT.md` first for launching the instance, Docker and HTTPS. This guide replaces its section 9.

## 1. How it works
* `STORAGE_BACKEND=s3` makes **new** uploads go to S3; each evidence row remembers its own backend
  (`evidence.storage_backend`), so existing local evidence stays readable after the switch.
* What is stored: only **ciphertext** (per-file Fernet key, wrapped by the master key held by the app) written with
  S3 **server-side encryption** (SSE-S3 by default, SSE-KMS optional) and a SHA-256 checksum that S3 verifies; the app
  re-checks object size/checksum after every write (`StorageIntegrityError` on mismatch, object removed).
* Retrieval is **always proxied through the API** after the owner/admin check and the SHA-256 integrity check.
  No presigned URLs are issued (so there is no link that could outlive the authorization decision).
* Errors map to safe messages: `STORAGE_PERMISSION` (AccessDenied), `STORAGE_UNAVAILABLE` (network/throttle),
  `STORAGE_NOT_FOUND`, `STORAGE_INCOMPLETE`. AWS error text (ARNs, account ids) is logged server-side only.
* The application never deletes evidence. `delete()` exists only to clean up a *failed* upload (see 4 for IAM trade-off).
* **Master key:** `<STORAGE_PATH>/master.key` is NOT in S3. Losing it makes all evidence unrecoverable - back it up
  (offline, encrypted). Moving the master key to AWS KMS is future work.

## 2. Create the bucket (Linux / macOS shell; for Windows CMD replace `\` line breaks with `^`)
```bash
export BUCKET=my-forensic-evidence-123456   # globally unique
export REGION=eu-west-1
aws s3api create-bucket --bucket $BUCKET --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
aws s3api put-bucket-versioning --bucket $BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-ownership-controls --bucket $BUCKET \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
```
Also deny non-TLS access (save as `policy.json`, then `aws s3api put-bucket-policy --bucket $BUCKET --policy file://policy.json`):
```json
{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*",
 "Action":"s3:*","Resource":["arn:aws:s3:::BUCKET","arn:aws:s3:::BUCKET/*"],
 "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}
```
Recommended for forensic immutability: enable **S3 Object Lock** (must be set at bucket creation: add
`--object-lock-enabled-for-bucket`) in governance/compliance mode.

## 3. EC2 instance role (no access keys anywhere)
1. IAM -> Roles -> Create role -> trusted entity **EC2** -> attach the policy from section 4 -> name `forensic-ec2-role`.
2. EC2 -> instance -> Actions -> Security -> **Modify IAM role** -> `forensic-ec2-role`.
3. Do **not** set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`; boto3 picks up the role through the instance metadata
   service. Require IMDSv2 (`aws ec2 modify-instance-metadata-options --instance-id i-... --http-tokens required`).

## 4. Least-privilege IAM policy
```json
{"Version":"2012-10-17","Statement":[
 {"Sid":"EvidenceObjects","Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],
  "Resource":"arn:aws:s3:::BUCKET/evidence/*"},
 {"Sid":"ListForCleanErrors","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::BUCKET",
  "Condition":{"StringLike":{"s3:prefix":["evidence/*"]}}}
]}
```
* `ListBucket` makes S3 answer *404* instead of *403* for a missing key (clearer errors).
* **No `s3:DeleteObject`** is granted on purpose (evidence must not be deletable by a compromised app). Consequence:
  if a post-upload size check fails the app cannot remove the bad object; it logs the failure and the upload is
  rejected - clean such orphans manually, or add `s3:DeleteObject` only if your policy allows it.
* With SSE-KMS add `kms:GenerateDataKey` and `kms:Decrypt` on that key and set `S3_SSE=aws:kms`, `S3_KMS_KEY_ID`.

## 5. Security group
| Direction | Port | Source | Purpose |
|---|---|---|---|
| Inbound | 22 | your admin IP only | SSH |
| Inbound | 80, 443 | 0.0.0.0/0 | Nginx / HTTPS |
| Inbound | 5000, 5173, 5432 | **nobody** | backend/frontend/DB stay on localhost / private subnet |
| Outbound | 443 | 0.0.0.0/0 | S3, Gmail SMTP uses 587 (allow it too) |
If you use RDS, allow 5432 only from this instance's security group.

## 6. Environment (`.env` on the instance)
```
FLASK_ENV=production
SECRET_KEY=...        JWT_SECRET_KEY=...        # python -c "import secrets; print(secrets.token_hex(32))"
DATABASE_URL=postgresql://USER:PASS@HOST:5432/DB
STORAGE_BACKEND=s3
S3_BUCKET=my-forensic-evidence-123456
AWS_REGION=eu-west-1
S3_SSE=AES256
S3_CONNECT_TIMEOUT=5   S3_READ_TIMEOUT=30   S3_MAX_RETRIES=3
MAX_UPLOAD_MB=50
MAIL_USERNAME=...      MAIL_PASSWORD=...        # see SETUP_WINDOWS_GMAIL.md
```

## 7. Build, migrate, run
```bash
docker compose -f docker-compose.prod.yml --env-file .env up -d --build
docker compose -f docker-compose.prod.yml exec backend flask db current      # shows the applied revision
docker compose -f docker-compose.prod.yml logs -f backend
```
(The container entrypoint already runs `flask db upgrade`.) Windows CMD uses the same commands; use `copy` instead of `cp`.

## 8. Verification checklist (do these on the real deployment)
1. `aws s3api get-public-access-block --bucket $BUCKET` - all four flags `true`.
2. Upload a file in the UI, then `aws s3api head-object --bucket $BUCKET --key evidence/<id>.enc` shows
   `ServerSideEncryption` and `ChecksumSHA256`; `aws s3 cp s3://$BUCKET/evidence/<id>.enc -` is unreadable ciphertext.
3. Download in the UI; compare `sha256sum` with the hash on the evidence page.
4. From another machine: `curl https://$BUCKET.s3.amazonaws.com/evidence/<id>.enc` -> `403`.
5. Temporarily detach the instance role: uploads must fail with "evidence store refused access" (`STORAGE_PERMISSION`).
6. `docker compose ... exec backend env | grep -i aws_` must show **no** access keys.
