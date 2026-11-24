#!/usr/bin/env python3
"""Reproducible generated-challenge measurements, one fresh CPU process per case."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
COMPONENT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", required=True, help="Explicit disposable synthetic-only directory")
    parser.add_argument("--output", help="Public JSON measurements, never checkpoints or DP records")
    args = parser.parse_args()
    scratch = Path(args.scratch).absolute()
    scratch.mkdir(parents=True, exist_ok=True)
    # No input file or production option exists: every challenge is generated locally.
    cases = [
        (17, "lower", 0, "bench-v1"), (17, "upper", 0, "bench-v1"),
        (257, "middle", 0, "bench-v1"), (4096, "seeded", 0, "bench-v1"),
        (65536, "lower", 0, "bench-v1"), (65536, "upper", 4, "bench-v1"),
        (1 << 20, "seeded", 0, "compare-v1"), (1 << 20, "seeded", 4, "compare-v1"),
        (1 << 24, "seeded", 8, "large-synthetic-v1"),
    ]
    measurements = []
    for width, position, dp_bits, seed in cases:
        with tempfile.TemporaryDirectory(prefix="synthetic-bench-", dir=scratch) as temporary:
            directory = Path(temporary) / "state"
            command = [sys.executable, "-I", "-B", str(COMPONENT / "run.py"),
                       "--private-dir", str(directory), "--synthetic-width", str(width),
                       "--synthetic-position", position, "--dp-bits", str(dp_bits), "--seed", seed,
                       "--max-records", "50000", "--max-steps", "1000000", "--max-seconds", "30"]
            child = subprocess.run(command, capture_output=True, env={}, timeout=45)
            if child.returncode != 0:
                raise RuntimeError("synthetic benchmark did not solve within its bounds")
            metrics = json.loads((directory / "metrics.json").read_bytes())
            # Only allowlisted aggregate fields reach the output. No checkpoint or DP data is read.
            allowed = ("deviceLabel", "mode", "seed", "setupWallSeconds", "solveWallSeconds",
                       "deliveryWallSeconds", "totalWallSeconds", "solveCpuSeconds", "setupProcessPeakRssBytes",
                       "processPeakRssBytes", "steps", "walkStepsPerSecond", "setupOperations", "solveOperations",
                       "deliveryVerificationOperations", "retainedDpRecords", "status")
            item = {key: metrics[key] for key in allowed}
            item.update(label="synthetic-generated", lowerBoundBits=140, lowerBound="2^139",
                        width=width, position=position, dpBits=dp_bits)
            measurements.append(item)
    report = {"schema": "private-search-benchmark@1", "objectiveStatus": "INCOMPLETE",
              "deviceLabel": "unknown", "pythonVersion": ".".join(map(str, sys.version_info[:3])),
              "workers": 1, "networkUsed": False, "productionExecuted": False,
              "measurementNotes": {
                  "wall": "Seconds from monotonic clock. Setup includes synthetic generation, initialization and initial checkpoint.",
                  "solve": "Loop wall time includes collision verification and periodic checkpoints; excludes final save/delivery.",
                  "memory": "Bytes, peak RSS of each fresh task process only; process lifetime high-water mark, not a solve-only allocation count.",
                  "operations": "Integer counts: scalar multiplications, point addition calls, doublings, modular inversions; doubling can also be an addition call.",
                  "throughput": "Actual walk steps divided by solve wall seconds, not keys tested or a GPU estimate.",
                  "delivery": "Final independent verification is measured even with no external candidate sink in this synthetic benchmark.",
              }, "measurements": measurements}
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded)
        print(json.dumps({"status": "ok", "syntheticTrials": len(measurements), "productionExecuted": False}))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
