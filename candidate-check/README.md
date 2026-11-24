# candidate-check: private candidate verifier for Puzzle #140

Checks one 32-byte candidate scalar against the fixed public Bitcoin Puzzle #140
manifest and reports booleans only. It recovers nothing, signs nothing and pays
nothing. **Goal status stays INCOMPLETE** until a real key is verified on an
entrant-controlled machine and the prize payment is confirmed; a passing
synthetic test is not a recovered #140 key.

| Fixed public field | Value |
| --- | --- |
| Compressed public key | `031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640` |
| Compressed P2PKH address | `1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo` |
| Inclusive interval | `[2^139, 2^140 - 1]` |
| Candidate encoding | exactly 32 raw bytes, big-endian |
| `manifest_sha256` | `15cad4c3c92f31e8a60e6a85b11dd6044201209e0060d48248e260a920e6f048` |
| `source_bundle_sha256` | `1fce4ebb6478341b1c16a50de49c6dc803bfa1ed2d90ca43b760d3a17783a091` |

There is no option, environment variable, file or function argument that
changes the production key, address or interval.

## Files

| File | Role |
| --- | --- |
| `candidate_check.py` | Production command and in-process API (fixed manifest only). |
| `synthetic_api.py` | Separate synthetic-test API and command; refuses the production target. |
| `cc_core.py` | Shared evaluation, descriptor reading, report and exit discipline. |
| `cc_primitives.py` | secp256k1 (two independent multipliers), SEC1, RIPEMD-160, Base58Check. |
| `tests/test_candidate_check.py` | Offline tests (published vectors, boundaries, leak tests). |
| `SHA256SUMS` | SHA-256 of every file above and this README. |

Python 3.8+ standard library only (`hashlib` SHA-256, `hmac`, `json`, `os`, `re`,
`sys`, optional `resource`). No vendored or downloaded dependency, no network,
no import from any other component of this repository. RIPEMD-160 is
implemented here, so the OpenSSL legacy provider is not needed.

## Offline test commands

From the repository root:

```sh
(cd candidate-check && sha256sum -c SHA256SUMS)
python3 -B -m unittest discover -s candidate-check/tests -p 'test_*.py' -v
python3 -I -B candidate-check/candidate_check.py --manifest
```

With only this directory copied elsewhere: `cd` into it and use
`python3 -B -m unittest discover -s tests -p 'test_*.py' -v`.

The tests use published curve vectors, interval boundaries and labelled
SYNTHETIC scalars derived from fixed public strings. They never search for,
load or guess the real key.

## Entrant-private verification command

Run only on a machine the entrant controls. `CANDIDATE_FILE` is a path the
entrant chooses on private storage (suggested mode `0600`); it must hold exactly
32 raw bytes, the big-endian scalar, with no hex, newline or prefix. This tool
never takes a candidate path, never writes a file and reads nothing else.

```sh
cd candidate-check
sha256sum -c SHA256SUMS
python3 -I -B candidate_check.py --manifest          # compare both hashes with the table above
python3 -I -B candidate_check.py --candidate-fd 3 3< "$CANDIDATE_FILE"; echo "exit=$?"
```

From a private producer that writes the 32 raw bytes to its stdout:

```sh
"$PRIVATE_PRODUCER" | python3 -I -B candidate_check.py --candidate-fd 0; echo "exit=$?"
```

Never pass the candidate as an argument or environment variable. Descriptors
1 and 2 and terminals are refused. The descriptor is read to EOF (at most 33
bytes are consumed) and closed.

### Exit status and output

| Exit | Meaning |
| --- | --- |
| 0 | every check true: `candidate_verified` is `true` |
| 1 | at least one check false (including a descriptor that did not deliver exactly 32 bytes) |
| 2 | usage or descriptor error; fixed usage text on stderr |
| 3 | internal error or failed known-answer self-test; nothing on stderr |

stdout is one line of canonical JSON (sorted keys). For a candidate:

```json
{"candidate_verified":false,
 "checks":{"descriptor_exact_32_bytes":true,"p2pkh_address_match":false,
           "public_key_match":false,"scalar_in_interval":true,"scalar_valid":true},
 "component":"candidate-check","manifest_sha256":"15ca...f048","mode":"PRODUCTION",
 "production_candidate_verified":false,"schema":"candidate-check/v1",
 "scope":"candidate verification only; ...","source_bundle_sha256":"...",
 "source_sha256":{"candidate_check.py":"...","cc_core.py":"...","cc_primitives.py":"...","synthetic_api.py":"..."}}
```

- `descriptor_exact_32_bytes`: the descriptor delivered exactly 32 bytes then EOF.
- `scalar_valid`: `1 <= k <= n-1`.
- `scalar_in_interval`: `2^139 <= k <= 2^140-1`.
- `public_key_match`: compressed SEC1 of `k*G` equals the fixed public key. `k*G` is
  computed twice (Jacobian double-and-add, affine Montgomery ladder with a
  different inverse); disagreement is exit 3.
- `p2pkh_address_match`: Base58Check(00 || RIPEMD160(SHA256(SEC1))) equals the fixed
  address, and the hash160 equals the one decoded from the address.

Errors are `{"candidate_verified":false,"component":...,"error":"<fixed code>","mode":...,
"production_candidate_verified":false,"schema":...}`. Error codes are a fixed list in
`cc_core.ERROR_CODES`; exception text, arguments and input bytes are never printed.
Output for two different candidates with the same booleans is byte-identical.

## Interface for the claim integration

Subprocess (preferred; the candidate stays out of argv and the environment):

1. Create a pipe, start `python3 -I -B candidate_check.py --candidate-fd <read end>`
   with only that descriptor inherited, write the 32 bytes, close the write end.
2. Proceed only if the exit status is 0 **and** the parsed JSON has
   `production_candidate_verified == true`, `mode == "PRODUCTION"`,
   `manifest_sha256` equal to the value above and `source_bundle_sha256` equal to
   the pinned value above. Treat anything else as not verified.

In-process (the claim tool already holds the key in memory):

```python
import candidate_check
report = candidate_check.verify_production_candidate(candidate_32_bytes)   # bytes or bytearray
ok = report["production_candidate_verified"] is True
```

`verify_production_candidate_fd(fd)` does the same from an open descriptor.
Neither takes a target. `source_bundle_sha256` is the SHA-256 of the four
`"<sha256>  <name>\n"` lines for the source files in name order;
`manifest_sha256` is the SHA-256 of the canonical JSON printed by `--manifest`
under `manifest`.

## Synthetic-test API

`synthetic_api.py` exercises the same evaluation and output code on generated
challenges. Reports always carry `mode: "SYNTHETIC"`, `synthetic_notice` and
`production_candidate_verified: false`; labels must start with `SYNTHETIC-`; the
production public key (either parity) and address are refused with
`production_target_refused`.

```python
import synthetic_api
d = synthetic_api.make_challenge("SYNTHETIC-demo", 21, 16, 31)   # public descriptor from a known scalar
synthetic_api.check_synthetic_candidate((21).to_bytes(32, "big"), d)["candidate_verified"]   # True
```

```sh
python3 -I -B synthetic_api.py --challenge-file challenge.json --candidate-fd 3 3< synthetic.bin
```

Descriptor keys (all required, no others): `label`, `compressed_public_key`
(66 lowercase hex), `p2pkh_address`, `interval_lower_hex`, `interval_upper_hex`
(64 lowercase hex each, `1 <= lower <= upper <= n-1`).

## Limits

- Not constant time, and Python cannot erase `int`/`bytes` copies; the read buffer
  is overwritten best-effort and core dumps are disabled best-effort. Use a private
  machine, not a shared worker.
- The verifier does not check UTXOs, build transactions or confirm payment.
- The production command has only been run with synthetic, non-matching
  candidates. Its all-true path is exercised through the synthetic API, which
  shares the evaluation and output code.
