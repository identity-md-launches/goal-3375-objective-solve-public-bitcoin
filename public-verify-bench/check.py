#!/usr/bin/env python3
"""Run the isolated, offline ECDSA regression and benchmark acceptance check."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import benchmark
import test_verify
import verify_vectors

FIXTURE_HASHES = {
    "vectors.json": "b2a93674959ab6938447134b8738aff8385b3d4e3a9d9c10637e5826c7210812",
    "rfc6979.json": "d705ccb08b2afea49cc14e11c7e530c95317a4c6db483ec5cec9c9dabaa9ebf6",
    "wycheproof.json": "066fa22dc93a1c19e0329d1713051be38ebaf299640408d6c86f5bf8c5b490f2",
}


def main():
    start = time.perf_counter()
    for name, expected in FIXTURE_HASHES.items():
        actual = hashlib.sha256((HERE / "fixtures" / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"{name}: SHA-256 mismatch: {actual}, expected {expected}")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromModule(module)
                               for module in (test_verify, verify_vectors))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1

    # The existing oracle script builds from the adjacent vendored MIT C
    # sources and checks all baseline points, signatures and verifications.
    oracle_start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="ecdsa-oracle-", dir=HERE) as tmp:
        oracle = subprocess.run(
            ["sh", "secp-oracle/check.sh", "--require-baseline"], cwd=ROOT,
            env={**os.environ, "TMPDIR": tmp}, stdout=subprocess.PIPE, text=True,
            check=True,
        )
    oracle_report = json.loads(oracle.stdout)
    if oracle_report["baseline_status"] != "passed" or oracle_report["discrepancies"]:
        raise RuntimeError(f"independent oracle gate failed: {oracle_report}")
    oracle_report["build_and_check_wall_time_s"] = time.perf_counter() - oracle_start
    print(json.dumps({"oracle": oracle_report}), flush=True)

    report = benchmark.run(HERE / "fixtures" / "vectors.json", repeat=1)
    print(json.dumps({"benchmark": report}), flush=True)
    print(json.dumps({
        "status": "passed",
        "unittest_methods": result.testsRun,
        "rfc6979_nonce_cases": len(verify_vectors.read_vectors("rfc6979.json")),
        "wycheproof_cases": sum(len(group["tests"])
                               for group in verify_vectors.read_vectors("wycheproof.json")),
        "fixture_sha256": FIXTURE_HASHES,
        "acceptance_wall_time_s": time.perf_counter() - start,
    }), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
