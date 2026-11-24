# Reference provenance

All runnable source in this directory is original standard-library Python.
No reviewed implementation or third-party binary is vendored or executed.
These references are data, not runtime inputs; all commands and tests work offline.

| Reference | Version / immutable location | Use |
| --- | --- | --- |
| Standards for Efficient Cryptography 2 (SEC 2) | [Version 2.0, January 27, 2010, section 2.4.1](https://www.secg.org/sec2-v2.pdf) | secp256k1 field, group order and generator parameters |
| Bitcoin BIP 350 | [BIP 350 specification](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) (deployed specification; BSD-2-Clause) | Bech32m constant, checksum rules and witness version validation; independently implemented |
| RCKangaroo | [commit 618473acd7f5e696be5ec4f8377c18cc55c1361c](https://github.com/RetiredC/RCKangaroo/tree/618473acd7f5e696be5ec4f8377c18cc55c1361c) | Source/algorithm and license inspection only |

RCKangaroo review inspected CUDA device setup, the DP representation and
`Collision_SOTA` candidate verification in `RCKangaroo.cpp`. The code uses a GPU
walk design with compact DP records and a final scalar-multiplication check. The
CPU engine here uses full compressed points and an explicit private checkpoint
format. The reviewed GPL-3.0 license applies to RCKangaroo; no code was copied.
Upstream speed claims are not measurements of this task's hardware.

The following bytes were fetched from the pinned RCKangaroo commit on
2026-11-24 and hashed with SHA-256:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| [RCKangaroo.cpp](https://github.com/RetiredC/RCKangaroo/blob/618473acd7f5e696be5ec4f8377c18cc55c1361c/RCKangaroo.cpp) | 20085 | `ef2a2819f33456c52be2a06d9c97db62d8f12e524d3d598b0c9c4a8e2ce805f0` |
| [LICENSE.TXT](https://github.com/RetiredC/RCKangaroo/blob/618473acd7f5e696be5ec4f8377c18cc55c1361c/LICENSE.TXT) | 35147 | `8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903` |
| [README.md](https://github.com/RetiredC/RCKangaroo/blob/618473acd7f5e696be5ec4f8377c18cc55c1361c/README.md) | 4172 | `65327d14621769c411a4ae58a27b557c25b01171854c1ec56b8315810ee586f3` |

The production public key, interval, challenge address, and recipient originate
in the task brief. Local tests independently check their mathematical/address
consistency. This component makes no assertion about current chain balances or
the challenge's historical announcement. No RPC or block explorer was queried.

The integration check additionally uses the landed [secp-oracle](../secp-oracle/README.md)
libsecp256k1 source, commit `0cdc758a56360bf58a851fe91085a327ec97685a`,
BSD-3-Clause license in `secp-oracle/vendor/secp256k1/COPYING` and file pins in
`secp-oracle/vendor.sha256`. `oracle-fixtures.json` contains only synthetic
points generated locally by that native library for this integration check;
its SHA-256 is `b0975d21d420910aeb2b27ce0a01761e4b1213a91d1d538a5d09e663b038545b`.
The mandatory offline check verifies the pins and fixtures without requiring a
compiler. To additionally compare every fixture against a newly built native
library, set `PRIVATE_SEARCH_ORACLE_SO` to its absolute path before invoking the
same check. The fixture-only mode is not a live native-backend run.
