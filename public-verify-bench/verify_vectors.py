"""Offline published-vector regressions for the raw ECDSA verifier."""

import hashlib
import json
from pathlib import Path
import unittest

import secp256k1_verify as sk

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DER_REJECTIONS = {6, 8, 10, 23, 155, 232}


def read_vectors(name):
    return json.loads((FIXTURES / name).read_bytes())


def check_nonces(test):
    for row in read_vectors("rfc6979.json"):
        with test.subTest(case=row["case"]):
            secret = int(row["scalar_hex"], 16)
            digest = hashlib.sha256(bytes.fromhex(row["message_hex"])).digest()
            test.assertEqual(next(sk._rfc6979_k(secret, digest)), int(row["nonce_hex"], 16))


def decode_der_signature(signature):
    """Decode the strict short-form DER used by secp256k1 signatures.

    Keep encoding checks in the harness, since the benchmark accepts integers.
    Canonical positive integers of any short-form length reach the scalar checks.
    """
    if len(signature) < 2 or signature[0] != 0x30 or signature[1] & 0x80:
        raise ValueError("expected short-form DER sequence")
    if signature[1] != len(signature) - 2:
        raise ValueError("incorrect sequence length")

    offset = 2
    scalars = []
    for _ in range(2):
        if offset + 2 > len(signature) or signature[offset] != 0x02:
            raise ValueError("expected DER integer")
        length = signature[offset + 1]
        offset += 2
        if not 1 <= length < 128 or offset + length > len(signature):
            raise ValueError("incorrect integer length")
        value = signature[offset:offset + length]
        if value[0] & 0x80 or (length > 1 and value[0] == 0 and value[1] < 128):
            raise ValueError("negative or non-minimal integer")
        scalars.append(int.from_bytes(value, "big"))
        offset += length
    if offset != len(signature):
        raise ValueError("unexpected trailing data")
    return tuple(scalars)


class TestPublishedVectors(unittest.TestCase):
    def test_wycheproof(self):
        for group in read_vectors("wycheproof.json"):
            public = sk.decompress_pubkey(bytes.fromhex(group["publicKey"]))
            for row in group["tests"]:
                with self.subTest(tcId=row["tcId"], description=row["comment"]):
                    der = bytes.fromhex(row["sig"])
                    if row["tcId"] in DER_REJECTIONS:
                        self.assertEqual(row["result"], "invalid")
                        with self.assertRaises(ValueError):
                            decode_der_signature(der)
                        continue
                    r, s = decode_der_signature(der)
                    self.assertIn(row["result"], ("valid", "invalid"))
                    self.assertEqual(sk.verify(public, bytes.fromhex(row["msg"]), r, s),
                                     row["result"] == "valid")

    def test_mutations_of_published_positive(self):
        group = read_vectors("wycheproof.json")[0]
        row = group["tests"][0]
        self.assertEqual(row["tcId"], 1)
        public = sk.decompress_pubkey(bytes.fromhex(group["publicKey"]))
        message = bytes.fromhex(row["msg"])
        r, s = decode_der_signature(bytes.fromhex(row["sig"]))
        self.assertTrue(sk.verify(public, message, r, s))
        for name, point, msg, bad_r, bad_s in (
            ("message", public, message + b"\x00", r, s),
            ("wrong on-curve point", sk.G, message, r, s),
            ("off-curve point", (public[0], (public[1] + 1) % sk.P), message, r, s),
            ("infinity", sk.INF, message, r, s),
            ("negative r", public, message, -1, s),
            ("negative s", public, message, r, -1),
            ("r == n", public, message, sk.N, s),
            ("s == n", public, message, r, sk.N),
        ):
            with self.subTest(mutation=name):
                self.assertFalse(sk.verify(point, msg, bad_r, bad_s))

    def test_malformed_sec1(self):
        x = sk.GX.to_bytes(32, "big")
        y = sk.GY.to_bytes(32, "big")
        for name, encoding in (
            ("infinity", b"\x00"),
            ("short compressed", b"\x02" + x[:-1]),
            ("trailing byte", b"\x02" + x + b"\x00"),
            ("unsupported prefix", b"\x06" + x + y),
            ("x outside field", b"\x02" + sk.P.to_bytes(32, "big")),
            ("no square root", b"\x02" + bytes(32)),
            ("off curve", b"\x04" + x + (sk.GY + 1).to_bytes(32, "big")),
            ("y outside field", b"\x04" + x + sk.P.to_bytes(32, "big")),
        ):
            with self.subTest(encoding=name), self.assertRaises(ValueError):
                sk.decompress_pubkey(encoding)
