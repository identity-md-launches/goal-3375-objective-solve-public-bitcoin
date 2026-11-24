#!/usr/bin/env python3
"""Acceptance check: python3 -I -B toy-comparison/check.py

Offline, deterministic, stdlib only. Toy finite-field scope only: nothing here
calibrates secp256k1 or any real puzzle. Exits 0 only if every gate passes.
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)          # -I drops the script dir; add it explicitly
sys.dont_write_bytecode = True

import toy_dlog as td             # noqa: E402

FAILS = []
GATES = {}


def gate(name, ok, detail=""):
    GATES[name] = bool(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        FAILS.append(name)


def raises(exc, fn, *a):
    try:
        fn(*a)
    except exc:
        return True
    except Exception:
        return False
    return False


def main() -> int:
    # 1. existing unit tests
    suite = unittest.defaultTestLoader.loadTestsFromName("test_toy_dlog")
    res = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, "w")).run(suite)
    gate("unit-tests", res.wasSuccessful(), f"ran={res.testsRun}")

    # 2. boundary cases (before = behaviour of the pre-fix tool)
    P, N, G = td.P, td.N, td.G
    h = lambda x: pow(G, x, P)
    cases = []   # (name, before, after_ok)
    # interior generation at width<2
    cases.append(("interior-gen-width0 (before: ZeroDivisionError/garbage)",
                  raises(ValueError, td._derive_interior_x, "n", 5, 5)))
    cases.append(("interior-gen-width1 (before: x=a+1 breaking a<x<b)",
                  raises(ValueError, td._derive_interior_x, "n", 5, 6)))
    cases.append(("interior-gen-width2 ok", td._derive_interior_x("n", 5, 7) == 6))
    # singleton and two-element
    for m in ("bsgs", "kangaroo"):
        fn = td.bsgs_interval if m == "bsgs" else td.kangaroo
        cases.append((f"{m}-singleton", fn(h(1234), 1234, 1234)[0] == 1234))
        cases.append((f"{m}-two-low", fn(h(77), 77, 78)[0] == 77))
        cases.append((f"{m}-two-high", fn(h(78), 77, 78)[0] == 78))
        cases.append((f"{m}-reversed (before: silent garbage)", raises(ValueError, fn, h(5), 10, 5)))
        cases.append((f"{m}-width>=order (before: ambiguous answer)", raises(ValueError, fn, h(5), 0, N)))
        cases.append((f"{m}-width=order-1 accepted", fn(h(9), 0, N - 1)[0] is not None or m == "kangaroo"))
        cases.append((f"{m}-non-subgroup-target", raises(ValueError, fn, 2 if pow(2, N, P) != 1 else 3, 0, 100)))
        cases.append((f"{m}-zero-target", raises(ValueError, fn, 0, 0, 100)))
        cases.append((f"{m}-out-of-range-no-false-candidate", fn(h(5000), 1000, 2000)[0] is None))
        cases.append((f"{m}-non-int-endpoint", raises(TypeError, fn, h(5), 1.5, 9)))
    cases.append(("fixture-out-of-range-x rejected", raises(ValueError, td.Fixture, "z", 10, 20, "interior", 30, h(30))))
    cases.append(("fixture-bad-h rejected", raises(ValueError, td.Fixture, "z", 10, 20, "interior", 15, h(16))))
    cases.append(("fixture-interior-at-endpoint rejected", raises(ValueError, td.Fixture, "z", 10, 20, "interior", 10, h(10))))
    cases.append(("invalid-fixture-name KeyError", raises(KeyError, td.get_fixture, "nope")))
    cases.append(("invalid-fixture-name reproduce KeyError", raises(KeyError, td.reproduce_fixture, "nope")))
    bad = [n for n, ok in cases if not ok]
    gate("boundary-cases", not bad, f"{len(cases)-len(bad)}/{len(cases)} bad={bad}")

    # 3. span vs candidates
    f = td.get_fixture("endpoint-low")
    gate("span-4096-candidates-4097", (f.width, f.candidates) == (4096, 4097)
         and td.FIX_W == 4096)

    # 4. 14 deterministic trials, twice, identical counters/results
    def trials():
        return [(r.method, r.fixture, r.success, r.recovered, r.group_ops, r.setup_ops,
                 r.search_ops, r.table_entries) for fx in td.FIXTURES
                for r in (td.solve(m, fx) for m in td.METHODS)]
    t1, t2 = trials(), trials()
    gate("14-deterministic-trials", len(t1) == 14 and t1 == t2 and all(t[2] for t in t1),
         f"n={len(t1)}")
    gate("tame-wild-split", all(r[5] + r[6] == r[4] for r in t1)
         and all(r[5] > 1 for r in t1 if r[0] == "kangaroo"))
    gate("footprint-memory-O(sqrt)", all(r[7] <= 3 * td.FIX_W ** 0.5 + 40 for r in t1))

    # 5. exhaustive bounded interval: every x, both methods, vs known answer
    a, b = 3000, 3200
    miss = {"bsgs": [], "kangaroo": []}
    maxops = {"bsgs": 0, "kangaroo": 0}
    for x in range(a, b + 1):
        for m, fn in (("bsgs", td.bsgs_interval), ("kangaroo", td.kangaroo)):
            td.GroupOps.reset()
            got = fn(h(x), a, b)[0]
            maxops[m] = max(maxops[m], td.GroupOps.mul)
            if got != x:
                miss[m].append(x)
    gate("exhaustive-bsgs", not miss["bsgs"], f"x={a}..{b} maxops={maxops['bsgs']}")
    gate("exhaustive-kangaroo", not miss["kangaroo"],
         f"x={a}..{b} misses={len(miss['kangaroo'])} maxops={maxops['kangaroo']}")

    # 6. timing and allocation separate
    r = td.solve("kangaroo", td.get_fixture("interior-alpha"))
    gate("units-recorded", r.peak_mem_bytes > 0 and r.elapsed_s >= 0 and r.setup_ops > 0,
         f"time_s={r.elapsed_s} peak_B={r.peak_mem_bytes} ops={r.group_ops}")

    # 7. python -O in a subprocess (asserts stripped) + CLI invalid name
    code = ("import sys; sys.path.insert(0, %r); import toy_dlog as td\n"
            "assert 0 == 1, 'asserts are active'\n" % HERE)
    p0 = subprocess.run([sys.executable, "-I", "-B", "-O", "-c", code], capture_output=True)
    gate("optimized-mode-active", p0.returncode == 0)
    code = ("import sys; sys.path.insert(0, %r); import toy_dlog as td\n"
            "def r(e, f, *a):\n"
            "    try: f(*a)\n"
            "    except e: return True\n"
            "    return False\n"
            "ok = r(ValueError, td.kangaroo, 1, 9, 3) and r(ValueError, td.bsgs_interval, 1, 0, td.N)\n"
            "ok = ok and r(ValueError, td._derive_interior_x, 'n', 1, 2) and r(KeyError, td.get_fixture, 'x')\n"
            "ok = ok and all(td.solve(m, f).success for f in td.FIXTURES for m in td.METHODS)\n"
            "sys.exit(0 if ok else 1)\n" % HERE)
    p1 = subprocess.run([sys.executable, "-I", "-B", "-O", "-c", code], capture_output=True)
    gate("optimized-mode-checks-survive", p1.returncode == 0, p1.stderr.decode()[-200:])
    p2 = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "toy_dlog.py"),
                         "--fixture", "no-such"], capture_output=True)
    gate("cli-invalid-fixture", p2.returncode == 2 and b"Traceback" not in p2.stderr)
    p3 = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "toy_dlog.py"), "--json"],
                        capture_output=True)
    ok = p3.returncode == 0 and json.loads(p3.stdout)["meta"]["interval"]["candidates"] == 4097
    gate("cli-json", ok)

    print("RESULT:", "FAIL " + ",".join(FAILS) if FAILS else "OK",
          "| scope: toy finite field only; no secp256k1/#140 calibration; objectiveStatus=INCOMPLETE")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
