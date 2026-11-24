#!/usr/bin/env python3
"""Regenerate fixtures/fixtures.json deterministically (seed below). Synthetic keys only."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kcpu
SEED = "kangaroo-cpu-fixtures-v1"
N = kcpu.N
CASES = [  # (label, width_bits, offset, where)
    ("w32-random", 32, None, "random"),
    ("w36-start-endpoint", 36, None, "start"),
    ("w36-end-endpoint", 36, None, "end"),
    ("w20-narrow-high-offset-near-n", 20, N - 2**20 - 0x1234567, "random"),
    ("w24-narrow-high-offset-end-endpoint", 24, N - 2**24 - 2, "end"),
    ("w28-high-offset-2^255", 28, 2**255 + 0xABCDEF, "start"),
    ("w44-thread-scaling", 44, None, "random"),
    ("w46-save-resume", 46, None, "random"),
    ("w0-singleton", 0, None, "start"),
    ("w12-start-plus-one", 12, None, "start1"),
    ("w16-end-minus-one", 16, None, "end1"),
    ("w24-high-offset-near-n-start-endpoint", 24, N - 2**24 - 0x777, "start"),
    ("w40-thread-kat", 40, None, "random"),
    ("w56-rate-bounded", 56, None, "random"),
    ("w50-save-resume", 50, None, "random"),
]
def build():
    return {"seed": SEED, "note": "SYNTHETIC known-answer fixtures; synthetic_key is generated, never a real key",
            "cases": [kcpu.make_fixture(SEED, l, w, o, wh) for l, w, o, wh in CASES]}
if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "fixtures.json")
    json.dump(build(), open(out, "w"), indent=1); print(out)
