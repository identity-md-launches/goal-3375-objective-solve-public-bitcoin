# Standalone private CPU kangaroo

This component implements a bounded, single-process Pollard kangaroo engine using
Python's exact integers and actual secp256k1 arithmetic. **The Bitcoin #140
objective is INCOMPLETE.** Only generated synthetic challenges were executed on
the contributor worker. No real private key was recovered, no production walks
were run, and no transaction was signed or broadcast.

Python 3.10+ on Linux with `hashlib` RIPEMD-160 support is required; the recorded
run used Python 3.13.5. There
are no third-party packages, submodules, build steps, network calls, configuration
discovery, runtime downloads, or GPU requirements. Device identity is `unknown`.
The implementation is original; reviewed references are pinned in [SOURCES.md](SOURCES.md).

## Offline checks and synthetic execution

Run from the checkout root:

```sh
python3 -I -B private-search/check_integration.py
python3 -I -B -m unittest discover -s private-search/tests -v
python3 -I -B private-search/run.py
python3 -I -B private-search/bench.py --scratch test/scratch/private-search-bench --output private-search/benchmarks.json
```

The default run generates a labelled synthetic target in a 4,096-element interval
beginning at `2^139`; it reports counters and status, never the recovered scalar.
Synthetic widths are capped at `2^24`. The CLI cannot load arbitrary targets and
explicitly rejects the production public key in synthetic mode. Test scaffolding
uses `test/scratch/` and is not part of the deliverable.

This synthetic private-file demonstration also exercises the launcher and resume
protocol. Use a new empty `state` directory for the first command. The first run
normally returns exit code 3 because its 17-step allowance is exhausted:

```sh
mkdir -p test/scratch/private-search-demo
python3 -I -B private-search/launch.py --private-dir "$(pwd)/test/scratch/private-search-demo/state" --synthetic-width 65536 --synthetic-position lower --seed demo-v1 --max-steps 17 --max-seconds 5 --export-dp
python3 -I -B private-search/launch.py --private-dir "$(pwd)/test/scratch/private-search-demo/state" --synthetic-width 65536 --synthetic-position lower --seed demo-v1 --max-steps 10000 --max-seconds 5 --export-dp --resume
```

The generated candidate is exactly 32 bytes in the synthetic private directory's
`candidate.bin`. Tests check its value without printing it. A nonempty candidate
file is never overwritten. `run.py` alone accepts a pre-opened `--candidate-fd`;
`launch.py` creates that private file and passes its descriptor to a child process.
The launcher defaults to synthetic mode too.

## Entrant-only private start and resume

Run these commands **only on an entrant-controlled private Linux machine**. Set
the two shell variables to your actual absolute paths; the state directory must
be outside the physical source checkout. Its parent must already exist. The
launcher creates the final directory with mode 0700. Existing directories and
files must already have the required owner and permissions; the program does
not silently change them.

```sh
task_checkout=/absolute/path/to/checkout
task_private=/absolute/path/outside/checkout/puzzle140-cpu
python3 -I -B "$task_checkout/private-search/launch.py" --mode real --entrant-controlled --private-dir "$task_private" --seed entrant-v1 --worker-id cpu-001 --generation 0 --dp-bits 61 --max-records 10000 --max-steps 100000 --max-seconds 60 --checkpoint-steps 1000 --export-dp
```

Resume with the same manifest, seed, worker ID, generation, DP bits, and record cap (or a larger cap after saturation):

```sh
python3 -I -B "$task_checkout/private-search/launch.py" --mode real --entrant-controlled --private-dir "$task_private" --seed entrant-v1 --worker-id cpu-001 --generation 0 --dp-bits 61 --max-records 10000 --max-steps 100000 --max-seconds 60 --checkpoint-steps 1000 --export-dp --resume
```

These are finite per-invocation budgets, not an estimate that this CPU can solve
the production interval. Each resume adds at most the requested number of walk
steps. The time budget starts before setup and is checked between walk steps and
restored DP validations. Startup arithmetic, an individual step, filesystem I/O,
final checkpointing, and candidate verification/delivery can extend wall time
past the cooperative deadline. There is no unbounded candidate-pipe write.
`SIGINT` and `SIGTERM` request a checkpoint at a consistent step boundary;
`SIGKILL` loses only work since the last successful checkpoint. Do not run two
processes against one state directory.

Production mode fixes the entire [production manifest](production-manifest.json):

| Field | Fixed value |
| --- | --- |
| Public key | `031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640` |
| Address | `1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo` |
| Inclusive interval | `[2^139, 2^140 - 1]`, exactly `2^139` elements |
| Sole prize recipient | `bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx` |
| Manifest SHA-256 | `81b6d1ba0c3cb55713d7056670f67eef4573a9f84f55320c207a5f847f556050` |

Startup checks the public key is on secp256k1, derives and compares its compressed
mainnet P2PKH address, validates the recipient's mainnet v1/32-byte Bech32m
checksum, and compares the manifest with compiled constants. The declared range
is exact. This is a local consistency check; it does not independently establish
the historical challenge announcement or current spendable UTXOs. The entrant
must verify those before real execution and again before any claim. A coordinator
must also test its separate signing/claim workflow on fresh isolated regtest.

This component provides neither a signer nor a broadcaster. After recovery, the
remaining action is to feed the private 32-byte candidate to an entrant-controlled
claim tool, independently verify `kG = Q`, the interval, and current UTXOs, then
pay only the fixed recipient less network fees and verify confirmation. Never
upload `candidate.bin`, checkpoints, DP snapshots, or any production state.

## Algorithm and checkpoint contract

The tame walk starts at `(upper + offset_t) G`, with that full absolute scalar as
its distance. The wild walk starts at `Q + offset_w G`, with signed distance
`offset_w`. Default worker `local`, generation 0 uses zero offsets. Other starts
derive offsets from SHA-256 of canonical JSON
`["kangaroo-start@1", seed, workerId, generation, herd]`, reduced modulo
`max(1, isqrt(width))`; the wild offset is negated. All distances remain exact
signed integers without modular reduction in checkpoints or export records.

The common jump table has 32 positive lengths. Entry 0 is 1. Entries 1..31 are
`1 + SHA256(canonical(["kangaroo-jumps@1", str(width), seed, index])) mod
max(2, isqrt(width))`, interpreting the digest as an unsigned big-endian integer.
Each jump point is the corresponding length times G. Selection is the big-endian
integer `SHA256(b"kangaroo-select@1\0" + compressed_point) mod 32`. At infinity,
the selector uses the single byte `00`; infinity is never exported as a DP.
`jumpHash` is SHA-256 of the exact canonical description produced by
`engine.jump_table`, including lengths, compressed points, width, seed, and
selector version. Canonical JSON is sorted-key, ASCII, no whitespace, no NaN.

Tame and wild advance alternately. A point is distinguished when the low
`dpBits` of `SHA256(b"kangaroo-dp@1\0" + compressed_point)` are zero. The table
retains at most `maxRecords` unique **full 33-byte compressed points**, including
parity. A cross-herd full-point match gives `(d_tame - d_wild) mod n`. Acceptance
requires the inclusive interval, a valid nonzero secp256k1 scalar, and `kG = Q`
using a separate affine scalar multiplication implementation. The walk uses
affine additions and Jacobian scalar multiplication for setup. No solved-key
patterns, prefix guesses, or interval enumeration are used.

The checkpoint contains both live walks, exact distances, next-herd cursor,
counts, jump/manifest hashes, DP table, and any verified collision evidence. It
does not contain a separately formatted candidate key. Collision evidence can
reveal the key and is therefore private. Resume validates point/distance equations
and every retained record before accepting the state. Checkpoint SHA-256 detects
corruption; it is not an authentication code against someone who can modify the
private directory. A record cap stops the run with `memory_limit`; it never silently evicts DPs.
The distinguished point that reached the cap is the most recently advanced live
walk, retained in the checkpoint even though it is not yet in the table or DP
export. Existing `kangaroo-state@1` saturated checkpoints use the same encoding.
Restore validates the pending point and does not advance it. Resume with the same
parameters and a larger `--max-records` inserts that point before the next step;
keep `--dp-bits` explicit when increasing capacity. Only a saturated checkpoint
accepts a larger cap, up to 100,000 records; the 64 MiB checkpoint limit also
applies. At that ceiling the run remains honestly saturated: retain the private
checkpoint, arrange an independently implemented lossless store/coordinator, or
start another generation; this engine cannot itself continue that walk beyond
the ceiling. A coordinator must not assume the exported table includes the pending
point. There is no automatic infinite retry loop.

`density_plan(width, max_records)` models eight times ceil(sqrt(width)) aggregate
steps and chooses `dpBits` so the independent-uniform-hash expected DP visits
are at most half the cap. For width 2^139 and 10,000 records this gives 61 bits;
production defaults use this model, and explicit values 0..256 are accepted.
This is only a sizing heuristic, not a bound on runtime, collision probability,
actual records, memory, or chance of solving. Walk correlations, uneven work,
multiple workers and runs longer than the model can saturate it. Sparse DPs can
also delay collision detection. Measure and plan for each private deployment.

Private storage uses descriptor-relative opens, `O_NOFOLLOW`, exclusive locks,
same-directory temporary files, `fsync`, atomic replacement, and directory
`fsync`. Directory components cannot be symlinks. Files must be regular, owned by
the current process UID, mode 0600, and have one hard link; the directory must be
0700 and contain only recognized state files. A previous interrupted `.pending`
write is discarded after validation, preserving the last committed checkpoint.
The checkpoint is authoritative; optional `dp.jsonl` and `metrics.json` snapshots
can lag it if a later write fails.

Exit codes are 0 for a verified solution (synthetic or private real), 3 for a
bounded stop/interruption/record cap, and 2 for refusal or error. Errors use fixed
messages without exception strings, input values, keys, or private paths.
Production stdout contains only mode, status, and delivery status; detailed
counters and measurements stay in the private directory's `metrics.json`.
`candidateDelivered: false` on an ordinary synthetic run is expected. A real
run cannot begin without the sink, private directory, entrant attestation, and
explicit step/time limits. Core dumps are disabled. Python is not constant-time
and cannot reliably erase its integers or prevent privileged/same-UID inspection,
swap, or external backups; production belongs on a trusted private machine.

## Future coordinator interface

All coordination is private and local in this component. No network listener,
remote upload, external worker, or new companion component is needed for tests.

| Interface | Contract |
| --- | --- |
| `manifestHash` | SHA-256 of the complete canonical manifest, binding target, interval, network, and recipient |
| `jumpHash` | Exact deterministic jump description hash; all cooperating walks must agree |
| `workerId`, `walkId`, `generation` | Assign unique worker/generation tuples; `walkId` is `tame` or `wild`; IDs use `[A-Za-z0-9_-]{1,64}`, generation is an integer in `[0, 2^31)` |
| `herd` | `tame` means `P = distance*G`; `wild` means `P = Q + distance*G` |
| `point` | Lowercase 66-hex-character canonical SEC1 compressed point, including parity |
| `distance` | Canonical **signed decimal string**, never a JSON number or float; no plus, leading zeros, exponent, or negative zero |
| `dpBits` | Agreed run configuration; DPs use the common predicate above; not part of each record |
| `dp.jsonl` | Atomic snapshot of retained `walk-dp@1` records plus collision evidence if solved; replay and deduplicate, do not assume append-only delivery |
| Candidate | Exactly 32 unsigned big-endian bytes on inherited `--candidate-fd`, verified before writing; no text framing |

Every DP record has exactly these fields:

```text
schema="walk-dp@1", manifestHash, jumpHash, workerId, walkId,
generation, herd, point, distance
```

The consumer must validate schema, hashes, the full point, distance equation, and
DP predicate before merging records. Index collisions by
`(manifestHash, jumpHash, point)` and require opposite herds; an x-coordinate
match alone is insufficient. Deduplicate by the complete record, and use the
worker/generation/walk tuple to detect replay. `validate_record` and
`verified_collision` are local integration primitives; their return values must
remain private. Assign generations and seeds persistently so a restarted worker
does not duplicate a walk. Check derived starting points for accidental duplicate
offsets, particularly in tiny synthetic ranges. Coordinated walks intentionally
overlap; these are not disjoint key-space partitions.

A custom parent may create `os.pipe()`, pass only its write FD to `run.py` using
`subprocess.Popen(..., pass_fds=(write_fd,), env={})`, and close its copy of the
write FD. The private receiver reads exactly 32 bytes and requires EOF. The FD
must be write-only, at least 3, and cannot alias stdin/stdout/stderr. Linux
anonymous pipes are accepted after pipefs verification and made nonblocking;
named FIFOs, sockets, terminals, append-mode FDs, and unrelated files are refused.
The other supported sink is the empty 0600 `candidate.bin` in the selected
private directory. The launcher opens it and actually inherits its FD into the
child. The parent must protect the receiver; FD checks cannot attest what that
parent does with the bytes.

Collision evidence is checkpointed before delivery. A crash after the write but
before acknowledgment can cause delivery again on a new pipe: the consumer must
be idempotent and must not sign/broadcast twice blindly. Broken/full pipes fail
closed and leave the solved checkpoint for a fresh private receiver. A partially
written or nonempty file is refused on restart and must be inspected privately;
the program never truncates it.

## Evidence and limits

The standalone tests include both interval endpoints, small widths near `2^139`,
multiple seeds and generations, invalid targets, out-of-interval collision
rejection, step/time/record failures, exact signed distances wider than 256 bits,
opposite-y/full-point discrimination, deterministic interrupt/resume equality,
real OS signals, private FD delivery, atomic-write failure, corrupted checkpoints,
symlink/hard-link attacks, and normal/error-path secret sentinels.

[benchmarks.json](benchmarks.json) records nine generated trials in fresh CPU
processes with setup wall time, solve wall time, process CPU time, actual walk
steps/second, EC operation counts, retained records, seed, and process peak RSS
in bytes. Setup and final verification are separate from solve measurements;
point doublings can also count as point addition calls. RSS is a process-lifetime
high-water mark, not an isolated solve allocation count. Sparse-DP and all-point
runs with the same seed/range provide a reproducible CPU comparison. Upper-end
trials may solve at setup because the initial tame and wild points coincide.

RCKangaroo's pinned source and license were reviewed; its GPU binary was not
built or run. No GPU capability was assumed or probed. There is no measured GPU
comparison, no production throughput claim, and no extrapolated completion
promise. Production execution, adversarial host security, claiming/regtest,
live UTXO verification, and confirmed payment remain untested in this component.

The integration command uses pinned synthetic points generated with the landed
native secp-oracle; see [SOURCES.md](SOURCES.md) for provenance. It reports when
only fixtures were checked. Setting `PRIVATE_SEARCH_ORACLE_SO` to an independently
built copy of the oracle library also checks every fixture against the live native
backend. The full-width initialization check uses a generated synthetic point and
mocks manifest validation only; it does not execute production walks.
