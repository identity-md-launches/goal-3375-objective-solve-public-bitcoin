#!/usr/bin/env python3
"""Measure raw ECDSA verification and affine point addition separately."""

import argparse
import json
import os
import resource
import sys
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
    invalid_rejected = 0
    for v in vectors:
        actual = sk.verify(v["pub"], v["msg"], v["r"], v["s"])
        if not v["valid"]:
            invalid_rejected += not actual
            continue
        if actual:
            ok_valid += 1
        # Corrupt s by one; a correct verifier must reject it.
        bad_s = (v["s"] + 1) % sk.N
        if not sk.verify(v["pub"], v["msg"], v["r"], bad_s):
            ok_reject += 1
    total = sum(1 for v in vectors if v["valid"])
    invalid = len(vectors) - total
    passed = total > 0 and ok_valid == ok_reject == total and invalid_rejected == invalid
    return {
        "total_valid_vectors": total,
        "valid_accepted": ok_valid,
        "corrupted_rejected": ok_reject,
        "invalid_vectors": invalid,
        "invalid_rejected": invalid_rejected,
        "passed": passed,
    }


def verify_workload(vectors, repeat):
    count = 0
    for _ in range(repeat):
        for v in vectors:
            if sk.verify(v["pub"], v["msg"], v["r"], v["s"]):
                count += 1
    return count


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

    if args.repeat <= 0 or args.limit < 0:
        ap.error("--repeat must be positive and --limit nonnegative")
    report = run(args.fixtures, args.repeat, args.limit, load_task_descriptor())
    text = json.dumps(report, indent=2)
    print(text)
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(text + "\n")


def run(fixtures, repeat, limit=0, descriptor=None):
    start = time.perf_counter()
    provenance, vectors = load_fixtures(fixtures)
    if limit > 0:
        vectors = vectors[:limit]
    load_wall = time.perf_counter() - start

    start = time.perf_counter()
    gate = correctness_gate(vectors)
    gate_wall = time.perf_counter() - start
    if not gate["passed"]:
        print(json.dumps({"error": "correctness gate failed", "gate": gate}, indent=2))
        raise SystemExit(1)

    if tracemalloc.is_tracing():
        raise RuntimeError("disable tracemalloc before benchmarking")
    start = time.perf_counter()
    count = verify_workload(vectors, repeat)
    wall = time.perf_counter() - start

    # Affine G + 2G exercises ordinary addition with distinct x coordinates.
    double = sk.point_add(sk.G, sk.G)
    additions = 10_000
    start = time.perf_counter()
    for _ in range(additions):
        point = sk.point_add(sk.G, double)
    addition_wall = time.perf_counter() - start
    if point != sk.scalar_mul(3, sk.G) or not sk.is_on_curve(point):
        raise RuntimeError("point-addition workload returned an incorrect point")

    tracemalloc.start()
    try:
        start = time.perf_counter()
        traced_count = verify_workload(vectors, repeat)
        allocation_wall = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    expected = gate["total_valid_vectors"] * repeat
    if count != expected or traced_count != expected:
        raise RuntimeError("verification workload accepted an unexpected count")
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        rss /= 1024
    workload = len(vectors)
    total_verifs = workload * repeat

    return {
        "backend": BACKEND,
        "data_label": "SYNTHETIC (baseline signature corpus)",
        "fixture_provenance": provenance,
        "correctness_gate": gate,
        "workload_vectors": workload,
        "repeat_count": repeat,
        "total_verifications": total_verifs,
        "load_wall_time_s": load_wall,
        "correctness_wall_time_s": gate_wall,
        "timing_traced": False,
        "accepted_in_timed_phase": count,
        "point_addition": {
            "workload": "affine G + 2G",
            "total_additions": additions,
            "wall_time_s": addition_wall,
            "additions_per_second": additions / addition_wall,
        },
        "allocation_wall_time_s": allocation_wall,
        "allocation_verifications": total_verifs,
        "wall_time_s": round(wall, 6),
        "verifications_per_second": round(total_verifs / wall, 3),
        "peak_python_alloc_bytes": peak,
        "peak_python_alloc_kib": round(peak / 1024, 1),
        "process_peak_rss_kib": rss,
        "process_peak_rss_unit": "KiB (ru_maxrss, process lifetime high-water mark)",
        "hardware_metadata": descriptor if descriptor is not None
        else {"source": "none", "device_details": "unknown"},
    }


if __name__ == "__main__":
    main()
