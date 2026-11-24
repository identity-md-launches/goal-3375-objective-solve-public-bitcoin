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

3. **No key on logs.** The wrapper captures child stdout/stderr, never echoes it
   raw, and redacts the phrase "private key" and any 40–64 hex run before
   printing a sanitized summary. A crashing subprocess cannot leak a key through
   a diagnostic dump.

4. **Private, external files.** Candidate bytes are written mode `0600` under an
   entrant-supplied `--private-dir` that must be **outside** the checkout. The
   wrapper refuses a path inside the repository.

5. **Real run is entrant-private.** `real140` is locked to the fixed #140
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
