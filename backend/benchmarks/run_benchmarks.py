#!/usr/bin/env python3
"""Repeatable benchmark suite.  EVERY number is measured by running this script;
nothing is estimated. Results are only valid for the environment recorded in the
CSV/summary (see "environment"), and say nothing about multi-host or AWS runs.

  # measure a source tree (API suite works on the ORIGINAL code too = baseline)
  python benchmarks/run_benchmarks.py --root <path-to-backend> --label upgraded
  python benchmarks/run_benchmarks.py --root <path-to-original-backend> --label baseline --api-only

  # merge two runs into comparison tables
  python benchmarks/run_benchmarks.py --compare results/baseline.csv results/upgraded.csv

Suites
  api        health, upload, verify, (download) through the Flask test client, SQLite DB
  components key generation (legacy vs EO), Fernet enc/dec, SHA-256, ledger add/verify,
             local peer-folder replication (same-host simulation), S3 (moto-EMULATED,
             not real AWS), multiparty HE (OpenFHE)
"""
import argparse, csv, json, os, platform, statistics, sys, tempfile, time, io, shutil, importlib.util

SIZES = {"1KB": 1024, "100KB": 100 * 1024, "1MB": 1024 ** 2, "10MB": 10 * 1024 ** 2}
REPEATS = {"1KB": 15, "100KB": 15, "1MB": 10, "10MB": 5}
FIELDS = ["label", "environment", "suite", "operation", "size", "repeats", "failures",
          "median_ms", "p95_ms", "min_ms", "max_ms", "notes"]


def environment():
    cpu = "unknown"
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        cpu = platform.processor() or "unknown"
    mem = "unknown"
    try:
        mem = f"{int(next(l for l in open('/proc/meminfo') if l.startswith('MemTotal')).split()[1]) / 1024 ** 2:.1f} GiB"
    except Exception:
        pass
    return {"os": platform.platform(), "python": platform.python_version(), "cpu": cpu,
            "cores": os.cpu_count(), "ram": mem, "storage": "local tmpfs/disk (type not detected)",
            "network": "loopback only (no real network)", "db": "SQLite (file)"}


def pct(values, q):
    s = sorted(values)
    return s[min(len(s) - 1, max(0, round(q * (len(s) - 1))))]


def measure(fn, repeats, warmup=1):
    times, failures = [], 0
    for _ in range(warmup):
        try: fn()
        except Exception: pass
    for _ in range(repeats):
        t = time.perf_counter()
        try: fn()
        except Exception: failures += 1; continue
        times.append((time.perf_counter() - t) * 1000)
    return times, failures


class Recorder:
    def __init__(self, label, env_label):
        self.rows, self.label, self.env = [], label, env_label

    def add(self, suite, op, size, fn, repeats, notes="", warmup=1):
        times, failures = measure(fn, repeats, warmup)
        row = dict(label=self.label, environment=self.env, suite=suite, operation=op, size=size, repeats=repeats,
                   failures=failures, notes=notes,
                   median_ms=round(statistics.median(times), 3) if times else "",
                   p95_ms=round(pct(times, 0.95), 3) if times else "",
                   min_ms=round(min(times), 3) if times else "", max_ms=round(max(times), 3) if times else "")
        self.rows.append(row)
        print(f"{suite:10} {op:34} {size:>6}  median {row['median_ms']!s:>10} ms  p95 {row['p95_ms']!s:>10}  fail {failures}")


def load_app(root):
    sys.path.insert(0, root)
    tmp = tempfile.mkdtemp()
    os.environ.update(DATABASE_URL=f"sqlite:///{tmp}/bench.db", STORAGE_PATH=f"{tmp}/st", MASTER_KEY_PATH=f"{tmp}/st/m.key",
                      SECRET_KEY="b" * 40, JWT_SECRET_KEY="c" * 40, MAIL_SERVER="127.0.0.1")
    for node in "ABC":
        os.environ[f"NODE_{node}_PATH"] = f"{tmp}/st/node_{node.lower()}"
    from app import create_app
    app = create_app()
    return app, tmp


def api_suite(rec, root):
    app, tmp = load_app(root)
    import logging; logging.disable(logging.INFO)
    from app.extensions import db, bcrypt
    from app.models import User
    with app.app_context():
        db.create_all()
        db.session.add(User(full_name="Bench", email="bench@example.com", role="investigator", is_email_verified=True,
                            password_hash=bcrypt.generate_password_hash("Benchmark-pass-1").decode()))
        db.session.commit()
        c = app.test_client()
        tok = c.post("/api/auth/login", json={"email": "bench@example.com", "password": "Benchmark-pass-1"}).get_json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        rec.add("api", "GET /api/health", "-", lambda: c.get("/api/health"), 200)
        rec.add("api", "POST /auth/login (bcrypt)", "-",
                lambda: c.post("/api/auth/login", json={"email": "bench@example.com", "password": "Benchmark-pass-1"}), 10)
        has_download = None
        for name, size in SIZES.items():
            data = os.urandom(size)
            ids = []
            def up():
                r = c.post("/api/evidence/upload", headers=h, content_type="multipart/form-data",
                           data={"case_number": "B", "title": "bench", "file": (io.BytesIO(data), "bench.bin")})
                assert r.status_code == 201, r.get_data(as_text=True)[:200]
                ids.append(r.get_json()["evidence"]["id"])
            rec.add("api", "evidence insertion (upload+encrypt+hash+ledger)", name, up, REPEATS[name])
            eid = ids[-1]
            def ver():
                assert c.post(f"/api/evidence/{eid}/verify", headers=h).get_json()["hash_match"] is True
            rec.add("api", "integrity verification (decrypt+SHA-256+chain)", name, ver, REPEATS[name])
            if c.get(f"/api/evidence/{eid}/download", headers=h).status_code == 200:
                def dl():
                    assert c.get(f"/api/evidence/{eid}/download", headers=h).data == data
                rec.add("api", "authorized download (verify+decrypt)", name, dl, REPEATS[name])
        db.session.remove()
    shutil.rmtree(tmp, ignore_errors=True)


def components_suite(rec, root, original_root):
    import logging
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger("forensic.keygen").setLevel(logging.WARNING)
    app, tmp = load_app(root)
    import hashlib
    from cryptography.fernet import Fernet
    from app.services import key_generation_service as kg
    with app.app_context():
        # --- key generation: legacy (original code) vs Equilibrium Optimizer + HKDF
        spec = importlib.util.spec_from_file_location("legacy_kg", os.path.join(original_root, "app/services/key_generation_service.py"))
        legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
        rec.add("components", "key generation - LEGACY (baseline)", "32B", legacy.generate_optimal_key, 200, "original: best of 5 CSPRNG candidates")
        rec.add("components", "key generation - EO+HKDF default", "32B", kg.generate_optimal_key, 100, "pop=20, max_iter=50, patience=30")
        rec.add("components", "key generation - EO+HKDF (pop 40, 100 it)", "32B",
                lambda: kg.generate_key_with_stats(kg.EOParams(population=40, max_iter=100, patience=100)), 20)
        key = Fernet.generate_key(); f = Fernet(key)
        from app.services.blockchain_service import add_block, verify_chain
        for name, size in SIZES.items():
            data = os.urandom(size); ct = f.encrypt(data)
            rec.add("components", "SHA-256", name, lambda: hashlib.sha256(data).hexdigest(), REPEATS[name] * 2)
            rec.add("components", "Fernet encrypt", name, lambda: f.encrypt(data), REPEATS[name])
            rec.add("components", "Fernet decrypt", name, lambda: f.decrypt(ct), REPEATS[name])
            from app.services.peer_storage_service import replicate_bytes_to_nodes
            rec.add("components", "peer-folder replication x3 (SAME-HOST SIMULATION)", name,
                    lambda: replicate_bytes_to_nodes(ct, "bench.enc"), REPEATS[name])
        # --- ledger
        from app.extensions import db
        from app.models import User, Evidence
        db.create_all()
        u = User(full_name="b", email="l@example.com", password_hash="x", role="investigator"); db.session.add(u); db.session.commit()
        ev = Evidence(case_number="c", title="t", original_filename="a", encrypted_filename="a", file_size_bytes=1,
                      sha256_hash="0" * 64, encryption_key_id="k", uploader_id=u.id); db.session.add(ev); db.session.commit()
        rec.add("components", "ledger add_block (SQLite, hash-chain)", "-", lambda: add_block(ev.id, "BENCH", u.id, {"x": 1}), 100)
        rec.add("components", f"ledger verify_chain ({100 + 1} blocks)", "-", lambda: verify_chain(ev.id), 20)
        # --- S3, EMULATED
        try:
            import boto3
            from moto import mock_aws
            from app.services.storage.s3 import S3Storage
            os.environ.update(AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x", AWS_DEFAULT_REGION="eu-west-1")
            with mock_aws():
                boto3.client("s3", region_name="eu-west-1").create_bucket(Bucket="bench-bucket-1", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
                st = S3Storage("bench-bucket-1", region="eu-west-1")
                for name in ("1KB", "100KB", "1MB", "10MB"):
                    blob = os.urandom(SIZES[name])
                    rec.add("components", "S3 put+verify (moto EMULATED, not AWS)", name, lambda: st.put("k.enc", blob), REPEATS[name])
                    rec.add("components", "S3 get (moto EMULATED, not AWS)", name, lambda: st.get("k.enc"), REPEATS[name])
        except ImportError:
            print("moto/boto3 not installed - S3 suite skipped")
        # --- MHE
        try:
            from app.services.mhe_service import MultipartyKeys
            keys = None
            def kgen():
                nonlocal keys; keys = MultipartyKeys(["a", "b", "c"])
            rec.add("components", "MHE joint keygen (3 parties)", "-", kgen, 5, warmup=0)
            a, b = keys.encrypt([1, 2, 3]), keys.encrypt([4, 5, 6])
            rec.add("components", "MHE encrypt (3 slots)", "-", lambda: keys.encrypt([1, 2, 3]), 10)
            rec.add("components", "MHE add (ciphertext+ciphertext)", "-", lambda: keys.add(a, b), 20)
            s = keys.add(a, b)
            rec.add("components", "MHE decrypt (3 parties)", "-", lambda: keys.decrypt_as_owner(s, ["a", "b", "c"]), 10)
            rec.rows[-1]["notes"] = f"ciphertext size {len(keys.serialize(a)) / 1024:.0f} KiB"
        except ImportError:
            print("openfhe not installed - MHE suite skipped")
    shutil.rmtree(tmp, ignore_errors=True)


def write(rec, out):
    env = json.dumps(environment())
    for r in rec.rows: r["environment"] = env
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, FIELDS); w.writeheader(); w.writerows(rec.rows)
    print(f"\nwrote {out}  ({len(rec.rows)} rows)")


def compare(base_csv, new_csv):
    rows = lambda p: {(r["suite"], r["operation"], r["size"]): r for r in csv.DictReader(open(p, encoding="utf-8"))}
    b, n = rows(base_csv), rows(new_csv)
    print("| operation | size | baseline median ms | upgraded median ms | ratio (upgraded/baseline) |\n|---|---|---:|---:|---:|")
    for key in n:
        if key in b and b[key]["median_ms"] and n[key]["median_ms"]:
            bm, nm = float(b[key]["median_ms"]), float(n[key]["median_ms"])
            print(f"| {key[1]} | {key[2]} | {bm:.2f} | {nm:.2f} | {nm / bm:.2f}x |")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--original-root", help="backend dir of the original code (for the legacy key-gen baseline)")
    ap.add_argument("--label", default="upgraded"); ap.add_argument("--out")
    ap.add_argument("--api-only", action="store_true"); ap.add_argument("--compare", nargs=2)
    a = ap.parse_args()
    if a.compare: compare(*a.compare); sys.exit(0)
    rec = Recorder(a.label, "local-dev")
    api_suite(rec, a.root)
    if not a.api_only:
        components_suite(rec, a.root, a.original_root or a.root)
    write(rec, a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", f"{a.label}.csv"))
