# public-verify-bench

A repeatable **CPU benchmark for secp256k1 ECDSA signature verification**,
using known-answer test (KAT) vectors. It measures how many signature
*verifications per second* a pure standard-library verifier achieves on this
machine, after first proving the verifier accepts valid signatures and rejects
corrupted ones.

This component measures **verification throughput in its own units
(verifications/second)**. It is not a key-search tool and reports no key-search
metric.

## Prerequisites

- Python 3.8+ (developed/tested on CPython 3.14). Standard library only — no
  third-party packages, no network access at runtime.

## Layout

| Path | Purpose |
|------|---------|
| `secp256k1_verify.py` | Pure-stdlib secp256k1 group ops + ECDSA verify. Also an RFC 6979 deterministic signer used *offline* to build fixtures. |
| `gen_fixtures.py` | Deterministically generates the synthetic KAT fixtures. |
| `fixtures/vectors.json` | Generated KAT vectors (**SYNTHETIC**, see below). |
| `fixtures/LICENSE` | CC0-1.0 dedication for the fixture data. |
| `benchmark.py` | Correctness gate + timed throughput measurement. |
| `test_verify.py` | Deterministic unit tests. |

## Data provenance and license

The fixtures are **SYNTHETIC and independently generated** by `gen_fixtures.py`
on this machine. Private keys are derived from `SHA-256` of a fixed public seed
string (`public-verify-bench/secp256k1/synthetic-kat/v1`) and exist only to
produce reproducible signatures; they are valueless and must never be reused.
Signatures use **RFC 6979** (HMAC-SHA256) deterministic nonces, so regenerating
reproduces byte-identical vectors — the `(r, s)` pair is itself the known
answer. The secp256k1 domain parameters are the public standard constants
(SEC 2 v2, §2.4.1, Certicom Research, 2010), not generated here.

Fixture data is dedicated to the public domain under **CC0-1.0**
(`fixtures/LICENSE`). Downloaded third-party dependencies are **not** used at
runtime; the benchmark depends only on the Python standard library.

## Exact commands

Run from inside this directory (`public-verify-bench/`).

```sh
# 1. (Re)generate the synthetic KAT fixtures (optional; vectors.json ships).
python3 gen_fixtures.py --count 128 --out fixtures/vectors.json

# 2. Run the deterministic tests.
python3 -m unittest -v

# 3. Run the benchmark (full default workload = 128 vectors x 5 repeats).
python3 benchmark.py --repeat 5

# Fast smoke run (subset) for a quick check:
python3 benchmark.py --limit 16 --repeat 2

# Save the report as JSON:
python3 benchmark.py --repeat 5 --json-out report.json
```

Note: run with plain `python3` from this directory so the module is importable.
Do **not** use `python3 -I` here — isolated mode removes the script directory
from `sys.path` and the `import secp256k1_verify` fails.

## What the benchmark records

Every run emits a JSON report with:

- `backend` — `pure-python-stdlib (int arithmetic, SHA-256/HMAC via hashlib)`
- `data_label` — marks the workload as SYNTHETIC
- `correctness_gate` — valid signatures accepted and corrupted signatures
  rejected, counted; timing only proceeds if this passes
- `workload_vectors`, `repeat_count`, `total_verifications`
- `wall_time_s`, `verifications_per_second`
- `peak_python_alloc_bytes` / `peak_python_alloc_kib` (tracemalloc, timed phase)
- `process_peak_rss_kib` (`resource.ru_maxrss`, KiB on Linux)
- `hardware_metadata` — only populated from a platform task descriptor at
  `$PVB_TASK_DESCRIPTOR` (JSON) if present; otherwise `device_details:
  "unknown"`. This tool does **not** probe the host for CPU/core details.

## Expected output

The correctness gate must report `passed: true` with
`valid_accepted == corrupted_rejected == total_valid_vectors`. Throughput
depends on the CPU; the pure-Python backend is intentionally dependency-free
and therefore slow (order of ~10 verifications/second per core on a typical
CPU). Example smoke run observed on the build machine (CPython 3.14, Linux):

```
gate True | workload 16 | total 32 | wall_s 2.73 | vps 11.7 | rss_kib 21280
```

`unittest` should report `Ran 10 tests ... OK`.
