# kangaroo-cpu: pinned CPU comparison harness for JeanLucPons/Kangaroo

Comparison component only. It **refuses production targets**, and the objective (Bitcoin Puzzle #140) stays **INCOMPLETE**.
The full-width production fallback is a separate component (private-search).

## Contents
| path | what |
|---|---|
| `upstream/` | JeanLucPons/Kangaroo at `37576c82d198c20fca65b14da74138ae6153a446`, vendored as ordinary files from the codeload archive (sha256 `65c39d0a…01c2`). GPLv3 `LICENSE.txt` and all per-file notices are kept unmodified. Only the repo's `.gitignore` is left out. |
| `PROVENANCE.json` | URL, commit, archive sha256, the sha256 of every vendored file and every patch, and notes on the toolchain |
| `patches/0001-clang-compat.patch` | Puts the GCC-only `__rdtsc`, `_subborrow_u64` and `_addcarry_u64` shims behind `!__clang__` (clang uses its own intrinsics with the same pointer cast) and changes `bind` to `::bind`. Arithmetic is unchanged. |
| `patches/0002-exact-group-op-count.patch` | Prints `[KCPU-COUNT] session_group_ops=… offset_group_ops=…` (the exact jump counters) after the threads join, so results don't depend on the `MK/s` / `Count 2^x` labels. The search is unchanged. |
| `build.py` | Offline build without CUDA. It verifies the hashes, copies the source to `--out`, applies the patches and compiles the Makefile's 16 non-GPU translation units. |
| `kcpu.py` | Adapter with a pure-Python secp256k1 implementation. It generates fixtures, checks them independently and runs bounded jobs (`-m`) inside disposable quarantine directories. It reports exact op counts, wall times and peak RSS (from `wait4`). |
| `gen_fixtures.py`, `fixtures/fixtures.json` | Deterministic synthetic known-answer cases (seed `kangaroo-cpu-fixtures-v1`) |
| `measure.py`, `MEASUREMENTS.json` | Measurement suite and its recorded output |
| `tests/test_kcpu.py` | Unit tests, plus integration tests when `KCPU_BINARY` is set |

## Offline commands (repo root)
```
python3 -I kangaroo-cpu/build.py --out "$TMPDIR/kcpu-build" --cxx g++ --jobs 2
#  no g++ on host? any clang++ works; the measurements used: --cxx "zig c++ -target x86_64-linux-gnu" (zig 0.13.0)
python3 -I -m unittest discover -s kangaroo-cpu/tests -v
KCPU_BINARY="$TMPDIR/kcpu-build/kangaroo" python3 -I -m unittest discover -s kangaroo-cpu/tests -v
python3 -I kangaroo-cpu/measure.py --binary "$TMPDIR/kcpu-build/kangaroo" --out "$TMPDIR/m.json" --threads2 2
```
`build.py` exits 2 with a `BUILD-FAIL:` message if the compiler or `patch` is missing, if a hash doesn't match, or if a compile or link step fails.
Notes from this host:
- No gcc, g++, clang or make was installed.
- Unpatched upstream fails under clang:
  - `Int.h:241` static `__rdtsc` redeclaration
  - `Int.cpp:533` `__builtin_ia32_sbb_u64` is undeclared
  - `Network.cpp:743` `bind` resolves to `std::bind`

## Safety
- Widths above 2^125 are refused (the backend's 126-bit signed distance field). The range check itself is not edited.
- The #140 public key and the interval [2^139, 2^140-1] are refused.
- Any fixture is refused if it is not labeled `SYNTHETIC-` or if its public key is not re-derived from its own synthetic scalar.
- Upstream stdout, `-o` key files and work files go to `$TMPDIR/kcpu-synthetic-storage/job-*`, which is deleted after each job.

## Findings (see MEASUREMENTS.json)
- **Solved and verified:** the random-key cases, the end endpoint, narrow 2^20 and 2^24 intervals just below n, and 1- and 2-thread runs at 2^44.
- **Key equal to the interval start was not found** (w36, and w28 at offset 2^255+…). Both runs aborted at 8× the expected ops. A likely cause is that the shifted wild start becomes the point at infinity. Treat this as an upstream limitation.
- **Interrupted save/resume:**
  - Setup: `-w -wi 1 -ws`, then SIGKILL at 3 s.
  - The work file held 1024 kangaroos, the full one-thread herd, tame and wild together.
  - On resume, `FectchKangaroos` reported `[2^10.00 kangaroos loaded] [0 created]` and the run solved and verified the key.
  - `offset_group_ops` equalled the saved count. Work done after the last periodic save is lost.
