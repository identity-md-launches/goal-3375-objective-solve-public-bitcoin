#!/usr/bin/env python3
"""Deterministically generate secp256k1 ECDSA known-answer fixtures.

SYNTHETIC DATA. These vectors are *independently generated* on this machine by
this script; they are not drawn from any external/real wallet or key. Private
keys here are derived from a fixed public seed string and exist only to produce
reproducible signatures for benchmarking a verifier. They have no value and
must never be reused.

Determinism: private keys come from SHA-256 of a public counter string, and
signatures use RFC 6979 (HMAC-SHA256). Re-running reproduces byte-identical
output, so the signature (r, s) is itself the "known answer".

Usage:
    python3 gen_fixtures.py --count 256 --out fixtures/vectors.json
"""

import argparse
import hashlib
import json
import os

import secp256k1_verify as sk

SEED = b"public-verify-bench/secp256k1/synthetic-kat/v1"
PROVENANCE = {
    "label": "SYNTHETIC — independently generated, not real-world keys",
    "generator": "gen_fixtures.py",
    "seed": SEED.decode(),
    "curve": "secp256k1 (SEC 2 v2 section 2.4.1)",
    "hash": "SHA-256",
    "nonce": "RFC 6979 (HMAC-SHA256)",
    "signature_form": "low-s (BIP62 canonical)",
    "license": "CC0-1.0 (public domain dedication) — see fixtures/LICENSE",
}


def _priv_from_index(i):
    h = hashlib.sha256(SEED + b":" + str(i).encode()).digest()
    k = int.from_bytes(h, "big") % sk.N
    return k if k != 0 else 1


def build(count):
    vectors = []
    for i in range(count):
        priv = _priv_from_index(i)
        msg = b"pvb-msg-" + str(i).encode()
        r, s = sk.sign(priv, msg)
        px, py = sk.pubkey_point(priv)
        pub_compressed = bytes([0x02 | (py & 1)]) + px.to_bytes(32, "big")
        vectors.append(
            {
                "index": i,
                "msg_hex": msg.hex(),
                "pub_compressed_hex": pub_compressed.hex(),
                "r_hex": format(r, "064x"),
                "s_hex": format(s, "064x"),
                "valid": True,
            }
        )
    return {"provenance": PROVENANCE, "count": count, "vectors": vectors}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=256)
    ap.add_argument("--out", default="fixtures/vectors.json")
    args = ap.parse_args()
    data = build(args.count)
    here = os.path.dirname(os.path.abspath(__file__))
    out = args.out if os.path.isabs(args.out) else os.path.join(here, args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"wrote {args.count} synthetic KAT vectors to {out}")


if __name__ == "__main__":
    main()
