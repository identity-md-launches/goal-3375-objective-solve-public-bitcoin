# Fixed public manifest verifier

Standalone, offline Python component for the assigned Puzzle #140 manifest.
It verifies the supplied encodings and their consistency. The overall puzzle
objective remains **INCOMPLETE**: this component does not recover a key or pay a prize.

## Run

Prerequisites: Python 3.8 or later, with `hashlib` SHA-256 and RIPEMD-160 support.
RIPEMD-160 availability depends on the Python build's cryptographic provider;
if unavailable, the verifier reports `FAIL` and exits 1. No pip packages, downloaded
dependencies, external executables, node, account, or network access are needed.

From the repository root:

```sh
python3 -B identity-check/verify.py
python3 -B -m unittest discover -s identity-check -p 'test_*.py' -v
```

Or, with only this directory copied to another location:

```sh
cd identity-check
python3 -B verify.py
python3 -B -m unittest discover -s . -p 'test_*.py' -v
```

The verifier prints deterministic JSON to stdout. Exit 0 means every local check
passed; exit 1 means a validation/prerequisite failure; exit 2 means unsupported
arguments. `--help` prints usage and exits 0. There are no manifest overrides,
private-key arguments, input files, stdin reads, environment lookups, or wallet
interfaces. Unknown arguments are rejected without echoing them. Imported helper
functions accept public encodings for testing; never pass secrets to this component.

## Fixed inputs and expected results

| Public field | Fixed value |
| --- | --- |
| Compressed SEC | `031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640` |
| Mainnet P2PKH | `1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo` |
| Sole recipient | `bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx` |
| Inclusive interval | `[2^139, 2^140 - 1]` |

Expected JSON values (selected fields; the full output also includes the manifest,
interval, and explicit limitations):

```json
{
  "overall": "PASS",
  "goal_status": "INCOMPLETE",
  "derived_mainnet_p2pkh_address": "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
  "scripts_hex": {
    "challenge_p2pkh": "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac",
    "derived_key_p2pkh": "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac",
    "recipient_witness_v1": "512046bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f"
  }
}
```

All six entries in `checks` must have `status: PASS`:

- `compressed_sec_point`: exact 33-byte hex, compressed prefix, field bounds,
  square-root existence, curve equation, and parity. secp256k1 has cofactor 1;
  a finite on-curve point needs no additional subgroup test.
- `challenge_mainnet_p2pkh`: Base58 alphabet, decoded size, checksum, and version 00.
- `public_key_hash160`: SHA-256 then RIPEMD-160 of the validated compressed SEC.
- `public_key_address_match`: derived mainnet Base58Check equals the supplied address.
- `recipient_mainnet_bech32m_v1_32`: ASCII, case, length, alphabet, Bech32m checksum,
  HRP `bc`, witness version 1, canonical bit padding, and exactly 32 program bytes.
- `interval_scalar_bounds`: the stated interval is nonempty and inside the valid
  scalar domain. This does **not** prove the unknown private key is in that interval.

Dependent checks are `SKIP` when a prerequisite fails; this still makes `overall`
fail. Independent checks continue. A script is `null` when its own input did not
validate. On a valid-but-mismatched key/address, both public scripts are emitted to
make the discrepancy reviewable; consumers must gate on the exit code/overall status.
Scripts are locking scriptPubKeys, not signed transactions or unlocking scripts.

## Tests and boundaries

Expected test output ends with `Ran 34 tests` and `OK` (timing varies).
Tests include SEC 2 generator coordinates, a known generator HASH160/P2PKH pair,
RIPEMD-160's empty-message digest, published BIP350 vectors, and fixed-manifest
regressions. Every alternative Base58 character at each challenge-address position
and every alternative Bech32 data/checksum character at each recipient position is
tested for rejection. Synthetic fixtures exercise correct checksums on wrong
networks, wrong witness versions/lengths, legacy Bech32, noncanonical padding,
malformed SEC points, and valid-but-unrelated public keys. CLI output, exit codes,
determinism, and missing RIPEMD-160 behavior are checked.

**Synthetic fixtures are only tests**, never recovered puzzle keys, recipient
substitutions, or evidence of a real search. Tests use no randomness or downloaded
runtime references. The fixture encoder shares the checksum primitive; published
BIP350 vectors provide a separate known-answer check of that primitive.

Offline results do not establish challenge provenance, private-key interval
membership, current UTXOs/prize, recipient control, a recovered solution, or a
confirmed payment. Those remain separate tasks. No search, signing, broadcast,
or paid service is performed by this component. No requester input is missing
for this bounded deliverable.

Specifications consulted while developing (not fetched at runtime):

- [Standards for Efficient Cryptography 2, version 2.0, section 2.4.1](https://www.secg.org/sec2-v2.pdf): secp256k1 parameters.
- [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki): Bech32 formatting and padding.
- [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki): Bech32m checksum and published vectors.
