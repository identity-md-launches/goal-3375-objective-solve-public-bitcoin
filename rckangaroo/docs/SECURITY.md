# Security model: never expose a recovered key

## Threat

A solved ECDLP yields a private key controlling real funds. Any copy of it in a
log, a shared repository, a transcript, stdout, or a world-readable file is a
compromise. The shared worker running the search must not be trusted with it.

## Controls in this adapter

1. **Single private sink.** The patched solver emits the key only as 32
   big-endian bytes to an inherited `--candidate-fd`. Upstream's stdout
   `PRIVATE KEY` print and its `RESULTS.TXT` writer are removed
   (`patches/0001-candidate-fd-key-sink.patch`).

2. **Fail closed.** If `--candidate-fd` is absent, or any write/flush to it
   fails, the solver scrubs its buffer and exits non-zero **without** disclosing
   the key. Real/main mode refuses to start without `--candidate-fd`.

3. **No key on logs.** The wrapper captures child stdout/stderr but NEVER echoes
   it raw: only a constant, allowlisted set of counters/booleans is surfaced
   publicly. Its leak detector flags the phrase "private key", long hex runs,
   long decimal runs (a 140-bit scalar is ~42 digits), and base64-shaped runs,
   and redacts matching lines before any internal comparison. A crashing or
   noisy subprocess cannot leak a key through a diagnostic dump.

4. **Bounded, deadlocked-proof I/O.** The wrapper drains the child's
   stdout/stderr concurrently from the moment of spawn (so a pipe-filling child
   cannot wedge the candidate read) and enforces a deadline measured from spawn.
   It reads EXACTLY 32 bytes and requires a clean EOF; a short, empty, held-open
   (no-EOF), or over-long (33-byte) frame fails closed with no candidate.

5. **Private, external, no-follow files.** Candidate bytes are written mode
   `0600` with `O_CREAT|O_EXCL|O_NOFOLLOW` (never following a symlink, never
   overwriting/truncating an existing file) under an entrant-supplied
   `--private-dir` that must be **outside** the checkout. Containment is decided
   physically by `realpath` (not a lexical prefix), so `..`/symlink tricks cannot
   smuggle a path back into the repository. The child runs in that private
   working directory, so a stray file it writes cannot land in the repo.

6. **fd sink is never a standard stream.** The patched solver rejects a
   `--candidate-fd` below 3, so the key sink can never be stdin/stdout/stderr;
   the wrapper likewise hands the child a private inherited fd `>= 3`.

7. **Pinned manifest.** `verify-manifest`/`real140` trust the mutable
   `manifest_140.json` only after it matches pinned #140 constants (target
   address, pubkey, interval start, recipient). A tampered manifest is rejected
   and `real140` independently re-derives the recovered candidate's pubkey and
   range before any handoff.

8. **Real run is entrant-private.** `real140` is locked to the fixed #140
   manifest and refuses to run without an explicit
   `--i-am-entrant-private-host` acknowledgement. The production solve belongs on
   an entrant-controlled machine, never a shared worker.

## What this adapter does not do

- It does not sign or broadcast a transaction. The 32-byte candidate is handed
  to a separate, regtest-tested secure-claim tool.
- It does not read machine credentials, home, environment, or configuration for
  its work, inventory the host, or rent hardware.
- It does not treat any upstream throughput figure as a measurement.

## Entrant-controlled private runner

Because the shared worker is untrusted, the real solve is designed to run under
the entrant's control: build with `build/build_cuda.sh` on the entrant's GPU
host, run through `adapter/rck_adapter.py real140` with a private dir outside any
repository, and move the resulting candidate file to the claim tool over a
private channel.
