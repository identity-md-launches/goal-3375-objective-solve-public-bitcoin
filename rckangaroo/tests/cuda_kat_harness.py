#!/usr/bin/env python3
"""OPTIONAL CUDA known-answer harness (range >= 32 bits).

This runs the REAL built solver on a generated challenge with a KNOWN private
key and checks that the recovered 32 big-endian bytes equal that key. It is a
GPU CORRECTNESS test and REQUIRES a compatible GPU + CUDA build. It is kept OUT
of the mandatory offline CPU tests on purpose.

Run ONLY if the task explicitly supplies compatible GPU/CUDA capability:

  python3 -I rckangaroo/tests/cuda_kat_harness.py \
      --solver-bin rckangaroo/upstream/build-cuda/bin/rckangaroo \
      --range-bits 48 --dp 14 \
      --private-dir /entrant/private/outside/checkout

Exit codes: 0 pass, 1 KAT mismatch, 3 solver binary unavailable (prerequisite
unmet -> report NOT RUN with this reason).

It delegates all fd handling, scrubbing, and private-file writing to
adapter/rck_adapter.py 'kat'. No host inventory, no rented hardware.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "adapter", "rck_adapter.py")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--solver-bin", required=True)
    p.add_argument("--range-bits", type=int, default=48)
    p.add_argument("--dp", type=int, default=14)
    p.add_argument("--seed", default="harness")
    p.add_argument("--private-dir", required=True)
    p.add_argument("--timeout", type=float, default=None)
    args = p.parse_args()

    if args.range_bits < 32:
        print("NOT RUN: range-bits must be >= 32 for a meaningful known-answer test")
        return 3
    if not os.path.isfile(args.solver_bin):
        print("NOT RUN: solver binary not found at %r" % args.solver_bin)
        print("Unmet prerequisite: build with rckangaroo/build/build_cuda.sh on a CUDA/GPU host.")
        return 3

    cmd = [sys.executable, "-I", ADAPTER,
           "--checkout-root", os.path.abspath(os.path.join(HERE, "..", "..")),
           "kat", "--solver-bin", args.solver_bin,
           "--range-bits", str(args.range_bits), "--dp", str(args.dp),
           "--seed", args.seed, "--private-dir", args.private_dir]
    if args.timeout:
        cmd += ["--timeout", str(args.timeout)]
    print("[cuda_kat] running:", " ".join(cmd))
    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    sys.exit(main())
