# kangaroo-cpu: pinned native comparator for JeanLucPons/Kangaroo (synthetic only)

This is a comparison component only. It **refuses production targets**. The objective (Bitcoin Puzzle #140) stays **INCOMPLETE**.
It does not gate the CPU fallback. The full-width production search is a separate component (private-search).

## Acceptance (offline, self-contained)
```
python3 -I -B kangaroo-cpu/check_offline.py            # mandatory; exit 0 = all gates pass
python3 -I -B kangaroo-cpu/check_offline.py --rebuild  # also rebuilds from source if g++ is present (informational)
```
- No network, downloads, compiler or `make` are needed.
- The backend is `bin/kangaroo-linux-x86_64-static`: statically linked, stripped, Linux x86-64, 2.2 MB. Its sha256 is pinned in `PROVENANCE.json`.
- The check **fails** (exit 1) if the binary is missing, has the wrong hash, does not run, or the host is not Linux x86-64. A skipped backend never counts as a pass.
- Gates:
  - **provenance:** hashes of the vendored files, the patches and the binary.
  - **unit:** pure-Python tests.
  - **refusal:** #140 key and interval, and width > 2^125. These are refused before any process starts.
  - **backend:** the binary runs and reports `Kangaroo v2.2`.
  - **kat:** 10 known-answer cases. Each answer is re-verified independently in Python.
  - **threads:**
    - a w40 solve with 1 and 2 threads;
    - a bounded run (`-m 0.004`) on a 2^56 range that counts jumps, giving a rate for 1 vs 2 threads.
  - **resume:**
    - `-w -wi 1 -ws`;
    - SIGKILL 0.5 s after the first save on a 2^50 synthetic range (retried up to 5× if a run solves before its first save);
    - `-i` resume, which must solve, verify and load a non-zero saved count.
- Reports for each run:
  - startup time (until the first `SolveKeyCPU Thread`);
  - walk time;
  - exact jump count (`[KCPU-COUNT]`);
  - process memory: sampled `/proc` VmHWM (7–15 MB on this host). The `wait4` ru_maxrss value is also given, but Linux keeps the Python parent's fork-time peak (~22 MB) across exec, so it is only an upper bound.
- No key material is printed.

## Lower-endpoint / point-at-infinity fix (patch 0003)
- **Cause.** Upstream shifts the target point: `K' = K - start·G`. When the key equals `start`, `K'` is the point at infinity. `AddDirect` then computes `ModInv(0)`, every wild kangaroo walks garbage, and the run never finds the key. The singleton interval `start == end` always fails the same way.
- **Reproduced** with a build that leaves out 0003: `build.py --exclude-patch 0003-start-endpoint-infinity.patch`. The w36, w28@2^255+…, w24-near-n start-endpoint cases and the singleton case all abort unsolved at `-m 2`. See `MEASUREMENTS.json` → `lower_endpoint_reproduction`.
- **Fix (minimal, reviewed):**
  - `InitSearchKey` checks whether `K == SP·G` (SP = start, or start+W/2 with symmetry).
  - If so, `Run` resolves the key exactly through `Output()`, which re-derives the public key, and prints `[KCPU-ENDPOINT]` with 0 walk ops.
  - `CreateHerd` also redraws zero start distances, which give z = 0 and corrupt the batched inversion.
  - It also redraws wild starts whose x equals `keyToSearch.x`, which give dx = 0. Both redraws are bounded.
  - No range or width check was changed.
- **Tested** on the lower endpoint, the singleton, start+1, end-1, the upper endpoint, high offsets just below n, and 2^255+offset.
- **Not patched:** a kangaroo that lands exactly on ±(jump point) during the walk. This only matters for very small ranges and is upstream behaviour.

## Contents
| path | what |
|---|---|
| `upstream/` | JeanLucPons/Kangaroo `37576c82d198c20fca65b14da74138ae6153a446`, GPLv3 (LICENSE.txt and notices unmodified), vendored as ordinary files; archive sha256 `65c39d0a…01c2` |
| `patches/0001` | clang compatibility (no arithmetic change) |
| `patches/0002` | exact `[KCPU-COUNT]` jump counters |
| `patches/0003` | start endpoint / infinity handling (above) |
| `patches/0004` | `#include <cstdint>` in Timer.h. GCC 13 fails without it: `Timer.h:36 'uint32_t' has not been declared` |
| `bin/kangaroo-linux-x86_64-static` | vendored backend = upstream + 0001..0004, built by `build.py --static` (GPL-3.0; the corresponding source is this directory) |
| `build.py` | offline build: verifies hashes, applies patches, compiles the 16 CPU translation units; `--static`, `--exclude-patch` |
| `kcpu.py` | adapter: pure-Python secp256k1, fixture guard, quarantined bounded jobs, measurement parsing |
| `check_offline.py` | mandatory acceptance check (above) |
| `gen_fixtures.py`, `fixtures/fixtures.json` | deterministic SYNTHETIC fixtures (seed `kangaroo-cpu-fixtures-v1`) |
| `measure.py` | older measurement script (still works); `MEASUREMENTS.json` is now written from `check_offline.py --rebuild --json` |
| `tests/test_kcpu.py` | unit tests; integration tests run with `KCPU_BINARY=kangaroo-cpu/bin/kangaroo-linux-x86_64-static` |

## Reproducible binary recipe
```
python3 -I kangaroo-cpu/build.py --out "$TMPDIR/kcpu-build" --jobs 4 --static
cp "$TMPDIR/kcpu-build/kangaroo" kangaroo-cpu/bin/kangaroo-linux-x86_64-static   # then update PROVENANCE.json vendored_binary.sha256
```
On the measuring host (Ubuntu g++ 13.3.0, static glibc 2.39), rebuilding gave the same sha256 as the vendored file.

## Safety
- Widths above 2^125 are refused (`MAX_WIDTH_BITS = 125`, the backend's 126-bit distance field). The guard is unchanged.
- The #140 public key and the interval [2^139, 2^140-1] are refused.
- A fixture is refused unless it is labelled `SYNTHETIC-` and its public key is re-derived from its own synthetic scalar.
- Upstream stdout, key files and work files go to `$TMPDIR/kcpu-synthetic-storage/job-*`, which is deleted after each job.
