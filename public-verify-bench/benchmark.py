#!/usr/bin/env python3
"""Repeatable CPU benchmark for secp256k1 ECDSA signature verification.

Measures verification throughput (verifications per second) of a pure
standard-library secp256k1 verifier against known-answer fixtures.

Protocol:
  1. Load fixtures (synthetic KAT vectors, see gen_fixtures.py).
  2. CORRECTNESS GATE (not timed): verify every valid signature must pass, and
     a corrupted copy of each signature must be rejected. Timing only runs if
     the gate passes.
  3. Timed phase: verify the whole workload `repeat` times, record wall time.

Reported: workload size, repeat counts, total verifications, wall time,
verifications/sec, per-run peak memory (tracemalloc, bytes/KiB) and process
peak RSS (resource.ru_maxrss, KiB on Linux), and backend name.

Hardware metadata: only emitted if the platform supplied a task descriptor at
$PVB_TASK_DESCRIPTOR (JSON). Otherwise device fields are reported "unknown";
this tool does not probe the host for CPU model, core count, etc.

Units: this measures verification throughput in verifications-per-second; it is
not a secp256k1 key-search metric.
"""

import argparse
import json
import os
import resource
import time
import tracemalloc

import secp256k1_verify as sk

BACKEND = "pure-python-stdlib (int arithmetic, SHA-256/HMAC via hashlib)"


def load_fixtures(path):
    with open(path) as f:
        data = json.load(f)
    prepared = []
    for v in data["vectors"]:
        pub = sk.decompress_pubkey(bytes.fromhex(v["pub_compressed_hex"]))
        prepared.append(
            {
                "pub": pub,
                "msg": bytes.fromhex(v["msg_hex"]),
                "r": int(v["r_hex"], 16),
                "s": int(v["s_hex"], 16),
                "valid": v["valid"],
            }
        )
    return data.get("provenance", {}), prepared


def correctness_gate(vectors):
    """Verify valid sigs accept and corrupted sigs reject. Returns dict."""
    ok_valid = 0
    ok_reject = 0
    for v in vectors:
        if not v["valid"]:
            continue
        if sk.verify(v["pub"], v["msg"], v["r"], v["s"]):
            ok_valid += 1
        # Corrupt s by one; a correct verifier must reject it.
        bad_s = (v["s"] + 1) % sk.N
        if not sk.verify(v["pub"], v["msg"], v["r"], bad_s):
            ok_reject += 1
    total = sum(1 for v in vectors if v["valid"])
    passed = (ok_valid == total) and (ok_reject == total)
    return {
        "total_valid_vectors": total,
        "valid_accepted": ok_valid,
        "corrupted_rejected": ok_reject,
        "passed": passed,
    }


def timed_run(vectors, repeat):
    count = 0
    t0 = time.perf_counter()
    for _ in range(repeat):
        for v in vectors:
            if sk.verify(v["pub"], v["msg"], v["r"], v["s"]):
                count += 1
    wall = time.perf_counter() - t0
    return count, wall


def load_task_descriptor():
    path = os.environ.get("PVB_TASK_DESCRIPTOR")
    if path and os.path.isfile(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {"note": "task descriptor present but unreadable"}
    return None


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--fixtures", default=os.path.join(here, "fixtures/vectors.json"))
    ap.add_argument("--repeat", type=int, default=5,
                    help="times the whole workload is verified in the timed phase")
    ap.add_argument("--limit", type=int, default=0,
                    help="use only the first N vectors (0 = all)")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()

    provenance, vectors = load_fixtures(args.fixtures)
    if args.limit > 0:
        vectors = vectors[: args.limit]

    gate = correctness_gate(vectors)
    if not gate["passed"]:
        print(json.dumps({"error": "correctness gate failed", "gate": gate}, indent=2))
        raise SystemExit(1)

    tracemalloc.start()
    tracemalloc.reset_peak()
    count, wall = timed_run(vectors, args.repeat)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ru_maxrss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    workload = len(vectors)
    total_verifs = workload * args.repeat
    vps = total_verifs / wall if wall > 0 else 0.0

    descriptor = load_task_descriptor()
    report = {
        "backend": BACKEND,
        "data_label": "SYNTHETIC (independently generated KAT fixtures)",
        "fixture_provenance": provenance,
        "correctness_gate": gate,
        "workload_vectors": workload,
        "repeat_count": args.repeat,
        "total_verifications": total_verifs,
        "wall_time_s": round(wall, 6),
        "verifications_per_second": round(vps, 3),
        "peak_python_alloc_bytes": peak,
        "peak_python_alloc_kib": round(peak / 1024, 1),
        "process_peak_rss_kib": ru_maxrss_kib,
        "process_peak_rss_unit": "KiB (Linux ru_maxrss)",
        "hardware_metadata": descriptor if descriptor is not None
        else {"source": "none", "device_details": "unknown"},
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
