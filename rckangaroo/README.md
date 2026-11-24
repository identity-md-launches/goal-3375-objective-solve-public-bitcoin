# RCKangaroo private adapter

A source-pinned, leak-hardened private adapter around
[RetiredC/RCKangaroo](https://github.com/RetiredC/RCKangaroo), a GPU Pollard
Kangaroo ECDLP solver. It is one component of a larger objective; this directory
delivers **only** the vendored solver plus a private output/runner wrapper. It
does **not** build a GPU binary here, solve puzzle #140, or pay anyone.

License: upstream is GPLv3 (`upstream/LICENSE.TXT`). This adapter is distributed
under the same terms as a derivative of GPLv3 source.

## Layout

| Path | What it is |
|------|------------|
| `upstream/` | Vendored reviewed source at pinned commit `618473a…`, patched |
| `patches/0001-candidate-fd-key-sink.patch` | The exact review diff of the key-sink change |
| `adapter/rck_adapter.py` | Private wrapper: owns `--candidate-fd`, scrubs logs, writes private files |
| `adapter/btccrypto.py` | Std-lib secp256k1 + base58check + bech32m helpers |
| `adapter/manifest_140.json` | Fixed #140 challenge identity (real mode is locked to this) |
| `tests/test_output_path.py` | Offline, CPU-only output-path / leak tests (no CUDA) |
| `tests/fake_solver.py` | Synthetic solver stand-in for those tests |
| `tests/cuda_kat_harness.py` | Optional GPU known-answer harness (range >= 32) |
| `build/build_cuda.sh` | Optional reproducible CUDA source-build recipe |
| `PROVENANCE.json`, `SHA256SUMS.txt` | Pinned commit, hashes, exclusions |
| `docs/` | Security model and checkpoint limitations |

## The key never leaves except as 32 private bytes

Upstream printed the recovered key to stdout and appended it to `RESULTS.TXT`.
The patch removes both sinks. The patched binary instead writes the recovered
key as **exactly 32 big-endian bytes** to an inherited file descriptor named by
`--candidate-fd`, and **fails closed** (exit 2, no key on any stream) if the fd
is missing or any write fails. Real/main mode refuses to start without
`--candidate-fd`. See `patches/0001-candidate-fd-key-sink.patch`.

The wrapper (`rck_adapter.py`) owns the read end of that fd. It:

- passes the write end to the child via `pass_fds`, appends `--candidate-fd N`;
- reads exactly 32 bytes, else fails closed (no partial persistence);
- writes the candidate to a private file **outside the checkout**, mode `0600`;
- **never** prints key bytes and **scrubs** child stdout/stderr of anything that
  looks like key material (the phrase "private key" or a 40–64 hex run) before
  echoing a sanitized summary, so a crashing/garrulous subprocess cannot leak.

Sensitive files live under an entrant-supplied `--private-dir` that must be
outside this repository; the wrapper refuses a path inside the checkout.

## Modes

- `verify-manifest` — offline: validates the recipient bech32m mainnet checksum,
  the pubkey→address match, and start == 2^139. (Live UTXO state is not checked.)
- `selftest-output` — offline output-path test driver (used by the test suite).
- `kat` — generated known-answer test against the **real** built solver. Needs a
  GPU/CUDA build. Builds a small-range challenge with a known key and checks the
  recovered 32 bytes equal it.
- `real140` — entrant-private real run, locked to `manifest_140.json`. Refuses
  unless `--i-am-entrant-private-host` is set and `--private-dir` is outside the
  checkout. Prints only the next claim action, never the key.

## Offline commands (no GPU)

```
python3 -I rckangaroo/tests/test_output_path.py
python3 -I rckangaroo/adapter/rck_adapter.py verify-manifest
```

## Optional GPU path (entrant's own machine only)

```
CUDA_ROOT=/usr/local/cuda-12.x bash rckangaroo/build/build_cuda.sh
python3 -I rckangaroo/tests/cuda_kat_harness.py \
    --solver-bin rckangaroo/upstream/build-cuda/bin/rckangaroo \
    --range-bits 48 --dp 14 --private-dir /path/outside/checkout
```

The GPU known-answer test is a correctness test and is kept out of the mandatory
offline suite. Run it only where compatible GPU/CUDA capability is actually
supplied; otherwise treat it as NOT RUN with the unmet prerequisite recorded.

## Checkpoints

`-tames` saves **tame precomputation only**, not full wild-walk state. This is
not a complete resume. See `docs/CHECKPOINTS.md`.

## Scope and honesty

No host inventory, no rented/paid compute, no network downloads at runtime, no
submodules. No upstream throughput figure (e.g. the README's GH/s numbers) is
treated as a measurement here. The objective is **INCOMPLETE**: this component
delivers a runnable, leak-hardened package, not a solved key or a paid prize.
