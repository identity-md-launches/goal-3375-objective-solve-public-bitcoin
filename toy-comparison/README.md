# Toy interval discrete-log benchmark (synthetic / educational)

A small, self-contained teaching tool that compares **two classic interval
discrete-logarithm methods** on a **fixed toy cyclic group whose order fits in
16 bits**. Everything it runs on is generated internally from named deterministic
seeds with known answers.

> ## Synthetic-data / scope label
> **All data here is synthetic.** The group has order `N = 65393` (16 bits) — it
> is *not* secp256k1, *not* Bitcoin, and has nothing to do with any real key or
> the 140-bit interval mentioned in the surrounding goal. Nothing measured here
> transfers to a real curve or predicts the cost of any real search. The tool is
> deliberately limited to its built-in group and fixture set. It reports **only**
> measurements taken on those fixtures.

## What it compares

Problem: given `H = G**x (mod P)` with the promise `x ∈ [a, b]`, recover `x`.

| method | file symbol | idea | time | memory |
|--------|-------------|------|------|--------|
| Baby-step / Giant-step (interval) | `bsgs_interval` | build a table of `G**j`, stride by `G**(-m)` | `O(√W)` | `O(√W)` |
| Pollard kangaroo / lambda (interval) | `kangaroo` | tame kangaroo lays footprints from the top of the interval; wild kangaroo seeks a collision | `O(√W)` expected | small (footprint table) |

Both methods are run on the **same instances** (identical `H, a, b`). `W = b - a`.

The kangaroo here is a didactic **single-table** variant (tame footprints held in
a dict, one wild kangaroo), chosen for clarity; it is deterministic because every
jump depends only on the current point value.

## The group (pinned, verified at import)

- `P = 130787` — safe prime
- `N = 65393` — `(P-1)/2`, prime, the group order (16 bits)
- `G = 4` — generator of the order-`N` subgroup

`verify_group()` runs at import and asserts primality of `N` and `P`, that
`P = 2N+1`, that `N < 2**16`, and that `G` has full order `N`.

## Fixtures (deterministic, known answers)

One fixed interval `[1000, 5096]` (width `4096`) with 7 fixtures:

- `endpoint-low`  — `x = a` (interval low endpoint)
- `endpoint-high` — `x = b` (interval high endpoint)
- `interior-alpha|bravo|charlie|delta|echo` — strictly interior `x`, each
  derived as `a + 1 + (SHA256("toy-dlog|<name>|<a>|<b>") mod (W-1))`.

The secret `x` of every fixture is a **pure function of its name** (no RNG, no
clock). An interrupted trial is reproduced by re-running the same fixture name
(`--fixture <name>`); `reproduce_fixture()` rebuilds the identical instance.

## Measurement method

- **group operations** — every modular multiplication goes through `gmul()`,
  which increments a global counter; this is the implementation-independent cost.
- **elapsed time** — `time.perf_counter()` around the solve call only.
- **memory** — `tracemalloc` peak bytes around the solve call only.
- **termination limit** — each method reports the cap on its own work (BSGS:
  table size + giant steps; kangaroo: tame steps + wild step budget). Trials are
  asserted to stay within that limit in the tests.

## Prerequisites

- Python **3.8+** (developed and checked on CPython 3.12). **Standard library
  only** — no third-party packages, no network access, no build step.

## Exact commands

Run from inside the `toy-comparison/` directory:

```sh
# 1. Run the full benchmark (human-readable table)
python3 toy_dlog.py

# 2. Machine-readable output
python3 toy_dlog.py --json

# 3. Reproduce / resume a single trial by name
python3 toy_dlog.py --fixture interior-charlie

# 4. Steadier timing (keeps best of N timed repeats; op counts unchanged)
python3 toy_dlog.py --repeat 5

# 5. Deterministic test suite
python3 -m unittest -v test_toy_dlog
#   or:  python3 test_toy_dlog.py
```

## Expected output

`python3 toy_dlog.py` prints a header and a 14-row table (7 fixtures × 2 methods)
and ends with:

```
# summary: 14/14 trials solved (7 fixture(s) x 2 methods)
```

Every row shows `ok = Y`, `recov == exp`, a positive `g-ops` count within the
printed `limit`, and a kangaroo `note` of `collision`. Group-operation counts and
recovered values are **stable across runs** (determinism); only `time(s)` and the
exact `mem(B)` may vary slightly with the host.

Representative numbers (CPython 3.12, one machine — timings are host-dependent):

```
fixture          kind           method    ok  recov  exp    g-ops   limit  mem(B)   time(s)
endpoint-low     endpoint-low   bsgs      Y   1000   1000   66      130    4656     ~0.0002
endpoint-low     endpoint-low   kangaroo  Y   1000   1000   522     624    25296    ~0.002
interior-charlie interior       bsgs      Y   4102   4102   113     130    4688     ~0.0002
interior-charlie interior       kangaroo  Y   4102   4102   260     624    25248    ~0.0006
```

Reading it: on this width-4096 toy interval, **BSGS uses far fewer group
operations** (tens) than the single-table **kangaroo** (hundreds), but BSGS holds
a full `√W` baby-step table. This is the expected textbook trade-off *for this toy
size*; it is **not** a claim about any real-size problem.

`python3 -m unittest -v test_toy_dlog` ends with `OK` (18 tests).

## Files

- `toy_dlog.py` — group, both methods, fixtures, measurement harness, CLI.
- `test_toy_dlog.py` — 18 deterministic unit tests (stdlib `unittest`).
- `README.md` — this file.
