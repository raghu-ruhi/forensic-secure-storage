# Benchmarks (LOCAL development environment only)

All numbers were produced by `backend/benchmarks/run_benchmarks.py` on the machine below. They describe **this
sandbox** and nothing else: **no multi-host, no real network, no real AWS/S3 measurements exist** - S3 rows use the moto
emulator (in-process), "peer-folder replication" copies to three local directories. Treat them as pending for real
infrastructure. Raw data: `backend/benchmarks/results/baseline.csv` and `upgraded.csv` (median / p95 / min / max, repeats,
failures = 0 for every row).

**Environment:** Linux 6.18 x86_64, Python 3.12.3, Intel Xeon @ 2.10 GHz, **1 core**, 3.9 GiB RAM, local disk (type not
detected), loopback only, SQLite database, Flask test client (no HTTP stack), single process.
Methodology: 1 warm-up run, then 5-15 repetitions per cell (200 for health), median and 95th percentile reported.
With so few repetitions at the larger sizes p95 is approximate.

## Baseline (original code) vs upgraded - API operations, median ms
| operation | size | baseline | upgraded | ratio |
|---|---|---:|---:|---:|
| GET /api/health | - | 0.23 | 0.25 | 1.07x |
| POST /auth/login (bcrypt) | - | 287.95 | 298.08 | 1.04x |
| evidence insertion | 1 KB | 10.76 | 128.29 | **11.92x** |
| evidence insertion | 100 KB | 12.01 | 128.45 | **10.70x** |
| evidence insertion | 1 MB | 22.09 | 132.78 | 6.01x |
| evidence insertion | 10 MB | 156.41 | 291.26 | 1.86x |
| integrity verification | 1 KB | 8.68 | 9.94 | 1.14x |
| integrity verification | 100 KB | 9.44 | 13.75 | 1.46x |
| integrity verification | 1 MB | 21.87 | 21.04 | 0.96x |
| integrity verification | 10 MB | 146.25 | 141.20 | 0.97x |

**Reading it honestly:** the upgrade made uploads ~6-12x slower for files up to 1 MB. The cause is key generation:
legacy 0.36 ms median vs Equilibrium-Optimizer + HKDF 106 ms (default: population 20, up to 50 iterations); with
population 40 / 100 iterations it is 433 ms. Verification is unchanged within noise. (The 10 MB insertion p95 of
566 ms vs 288 ms median shows run-to-run variance on a 1-core VM.) The optimizer adds no cryptographic strength
(ARCHITECTURE_PHASE2 section 4), so lowering `EEO_MAX_ITER`/`EEO_POPULATION` is a legitimate trade-off.
There is no baseline for download (the original has no such endpoint): upgraded median 6.9 ms (1 KB), 14.4 ms (1 MB), 113.8 ms (10 MB).

## Component timings, upgraded code, median ms
| component | 1 KB | 100 KB | 1 MB | 10 MB |
|---|---:|---:|---:|---:|
| SHA-256 | 0.001 | 0.069 | 0.73 | 7.6 |
| Fernet encrypt | 0.063 | 0.40 | 4.1 | 48.3 |
| Fernet decrypt | 0.047 | 0.51 | 5.1 | 54.4 |
| peer-folder replication x3 (same-host simulation) | 0.36 | 0.41 | 2.5 | 22.2 |
| S3 put + verify (**moto emulated**) | 3.7 | 5.2 | 7.4 | 56.0 |
| S3 get (**moto emulated**) | 2.0 | 2.3 | 2.7 | 11.2 |

Ledger (SQLite hash chain): `add_block` 2.67 ms; `verify_chain` over 101 blocks 1.22 ms.
Multiparty HE (OpenFHE, 3 parties): joint keygen 54.4 ms, encrypt 17.4 ms, add 0.19 ms, decrypt 17.6 ms; ciphertext ~1 MB.
Key generation: legacy 0.36 ms; EO+HKDF default 106 ms; pop 40 / 100 it 433 ms.

## Repeat the experiment
```
cd backend
pip install -r requirements-dev.txt
python benchmarks/run_benchmarks.py --root <ORIGINAL>\backend --label baseline --api-only
python benchmarks/run_benchmarks.py --label upgraded --original-root <ORIGINAL>\backend
python benchmarks/run_benchmarks.py --compare benchmarks/results/baseline.csv benchmarks/results/upgraded.csv
```
For real-infrastructure results, run the same script on the EC2 host with `STORAGE_BACKEND=s3` and a real
bucket (not yet scripted: the S3 rows currently use moto) and record instance type, region, and network conditions.
Memory/CPU utilisation per operation and timeouts under load were **not** measured.
