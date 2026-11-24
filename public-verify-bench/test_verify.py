#!/usr/bin/env python3
"""Deterministic tests for the secp256k1 verifier and fixtures.

Run with: python3 -B -m unittest -v   (from this directory)
No third-party deps; standard library only.
"""

import json
import os
import unittest

import secp256k1_verify as sk
from verify_vectors import check_nonces

HERE = os.path.dirname(os.path.abspath(__file__))


class TestCurve(unittest.TestCase):
    def test_generator_on_curve(self):
        self.assertTrue(sk.is_on_curve(sk.G))

    def test_order_of_G(self):
        # Left-to-right binary multiplication with the full integer scalar.
        # The production scalar_mul reduces by N before doing any group work.
        def unreduced(k):
            point = sk.INF
            for bit in bin(k)[2:]:
                point = sk.point_add(point, point)
                if bit == "1":
                    point = sk.point_add(point, sk.G)
            return point

        self.assertIsNone(unreduced(sk.N))
        self.assertEqual(unreduced(sk.N - 1), (sk.GX, sk.P - sk.GY))
        self.assertEqual(unreduced(sk.N + 1), sk.G)

    def test_decompress_roundtrip(self):
        priv = 0x1234567890ABCDEF
        px, py = sk.pubkey_point(priv)
        comp = bytes([0x02 | (py & 1)]) + px.to_bytes(32, "big")
        self.assertEqual(sk.decompress_pubkey(comp), (px, py))


class TestSignVerify(unittest.TestCase):
    def test_sign_then_verify(self):
        priv = 0xDEADBEEF
        msg = b"hello secp256k1"
        r, s = sk.sign(priv, msg)
        self.assertTrue(sk.verify(sk.pubkey_point(priv), msg, r, s))

    def test_rfc6979_deterministic(self):
        check_nonces(self)

    def test_reject_corrupted_s(self):
        priv, msg = 0xABCDEF, b"tamper"
        r, s = sk.sign(priv, msg)
        self.assertFalse(sk.verify(sk.pubkey_point(priv), msg, r, (s + 1) % sk.N))

    def test_reject_wrong_message(self):
        priv = 0x11223344
        r, s = sk.sign(priv, b"msg-a")
        self.assertFalse(sk.verify(sk.pubkey_point(priv), b"msg-b", r, s))

    def test_reject_out_of_range(self):
        priv, msg = 0x55, b"range"
        r, s = sk.sign(priv, msg)
        pub = sk.pubkey_point(priv)
        self.assertFalse(sk.verify(pub, msg, 0, s))
        self.assertFalse(sk.verify(pub, msg, r, sk.N))

    def test_low_s_canonical(self):
        r, s = sk.sign(0x77, b"low-s")
        self.assertLessEqual(s, sk.N // 2)


class TestFixtures(unittest.TestCase):
    def test_fixtures_verify(self):
        path = os.path.join(HERE, "fixtures", "vectors.json")
        self.assertTrue(os.path.isfile(path), "run gen_fixtures.py first")
        with open(path) as f:
            data = json.load(f)
        self.assertGreater(data["count"], 0)
        for v in data["vectors"]:
            pub = sk.decompress_pubkey(bytes.fromhex(v["pub_compressed_hex"]))
            msg = bytes.fromhex(v["msg_hex"])
            r, s = int(v["r_hex"], 16), int(v["s_hex"], 16)
            self.assertTrue(sk.verify(pub, msg, r, s), f"vector {v['index']}")


if __name__ == "__main__":
    unittest.main()
