# Synthetic secp256k1 known-answer oracle

From the repository root, build the C library and run the full offline check:

```sh
sh secp-oracle/check.sh --require-baseline
```

A standalone copy of this directory can run `sh check.sh`. The check uses a C99
compiler with shared-library support, POSIX shell utilities, GNU `sha256sum`
and Python 3's standard library. The temporary library is removed on exit.
With the trunk baseline present, either command checks it. A standalone run
reports an absent baseline as unavailable. The strict flag makes absence an
error.

To emit a fresh deterministic copy for inspection:

```sh
sh secp-oracle/check.sh --emit > /tmp/imd-p140-e2-secp-oracle-v1.json
cmp secp-oracle/fixtures.json /tmp/imd-p140-e2-secp-oracle-v1.json
```

## Fixture semantics

All scalars and challenges are public **SYNTHETIC** values. The seed namespace
is `imd-p140-e2-secp-oracle-v1`. The generator hashes ASCII strings of the
form `namespace:label` with SHA-256. Interval starts, widths and interiors
are derived from separate labels. The two closed intervals each include
their lower endpoint, upper endpoint, one interior scalar and one scalar
immediately outside each endpoint.

The corpus gives compressed and uncompressed SEC public keys for each interval
case. Interval membership is independent of signature validity. ECDSA vectors
use 32-byte digests and 64-byte compact signatures with 32-byte big-endian
`r` followed by `s`. Each case has a deterministic RFC 6979 low-S signature,
a mismatched digest, a zero-r signature and a high-S twin rejected by
libsecp256k1's low-S policy.

Distances cover `2^b - 1`, `2^b` and `2^b + 1` for each of the four boundary
exponents 125, 126, 128 and 139. They give the exact decimal distance, its bit
length, its fixed-width unsigned big-endian encoding, and the compressed SEC
encoding of `distance * G`. These are serialization cases with directly
computed answers. [Fixture schema](fixture.schema.json)

Corpus SHA-256 is
`052edfd8c642935025f5b6865b669843b45cd1e5bdb090efcfd1bcc79ab78e69`.
The test compares the committed bytes with both the hash and a fresh generation.
The JSON Schema was independently validated during delivery with Python's
`jsonschema` CLI, which is optional for consumers.

## Source and license provenance

- The unmodified C source subset is from bitcoin-core/secp256k1 release
  v0.6.0, commit `0cdc758a56360bf58a851fe91085a327ec97685a`. The pinned
  codeload archive had SHA-256
  `385c115a21ee1ff31d0b0320acc2b278c92f7bde971f510566ad481a38835be0`.
  The build uses the include closure of the three core translation units
  with `USE_FORCE_WIDEMUL_INT64`, `ECMULT_WINDOW_SIZE=5` and optional
  modules disabled. The 42 retained files, including the MIT license,
  are covered by the per-file checksum manifest.
  [Release](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.6.0) ·
  [Pinned archive](https://codeload.github.com/bitcoin-core/secp256k1/tar.gz/0cdc758a56360bf58a851fe91085a327ec97685a) ·
  [MIT license](vendor/secp256k1/COPYING) · [Checksums](vendor.sha256)
- The published point answers come from the generator and group order in
  Standards for Efficient Cryptography 2 (SEC 2), §2.4.1, and the scalar/x
  pairs in BIP 340 test vectors 0–3. The checks use the latter as point
  vectors. [SEC 2 v2](https://www.secg.org/sec2-v2.pdf#page=13) ·
  [Pinned BIP 340 CSV](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv) ·
  [BIP 340 license notice](published-points.LICENSE)
- The baseline is the CC0-1.0 `public-verify-bench` corpus from trunk commit
  `aebd9183af6a4b1643ddd1e71277f0e8166f3eda`, SHA-256
  `b2a93674959ab6938447134b8738aff8385b3d4e3a9d9c10637e5826c7210812`.
  The driver reads its fixture data and reproduces the documented seed
  derivation. libsecp256k1 independently computes the points and signatures.
  [Baseline corpus](../public-verify-bench/fixtures/vectors.json) ·
  [Baseline license](../public-verify-bench/fixtures/LICENSE)

## Observed results

The strict run passed 559 assertions, including six published point comparisons,
384 baseline cryptographic comparisons (128 each for compressed point bytes,
compact signature bytes and verification) and three baseline metadata checks.
There were zero discrepancies. The remaining 166 assertions cover corpus and
serialization checks. The isolated component passed 172 assertions.

One measured strict build and test completed in 2.94 s wall time with
79,064 KiB peak RSS as reported by GNU time. The Python driver including its
calls into the C library took 0.036737 s in that run. Device label is unknown.
These measurements are for the synthetic oracle.
