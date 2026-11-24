"""Deterministic offline tests. Generated/mutated encodings are SYNTHETIC.

No fixture represents a recovered puzzle key. The generator point is a standard
public SEC 2 vector. Bech32m vectors are from BIP350 (linked in README.md).
"""

import contextlib
import functools
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import verify as v


GENERATOR = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
GENERATOR_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GENERATOR_ADDRESS = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
BIP350_ADDRESS = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"


def fixture_words(program):
    """Synthetic fixture encoder using a bit string, unlike the decoder."""
    bits = "".join(format(byte, "08b") for byte in program)
    bits += "0" * ((-len(bits)) % 5)
    return [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]


def fixture_address(hrp="bc", version=1, program=bytes(range(32)),
                    constant=v.BECH32M, words=None):
    """Synthetic checksum-correct mutations; never a payment destination."""
    data = [version] + (fixture_words(program) if words is None else words)
    return fixture_encode(hrp, data, constant)


def fixture_encode(hrp, data, constant=v.BECH32M):
    """Synthetic Bech32m envelope, also supporting empty witness data."""
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = v.polymod(expanded + data + [0] * 6) ^ constant
    return hrp + "1" + "".join(v.BECH32[n] for n in data) + "".join(
        v.BECH32[(checksum >> shift) & 31] for shift in range(25, -1, -5))


class SecTests(unittest.TestCase):
    def test_standard_generator_coordinates(self):
        x, y = v.compressed_point(GENERATOR)
        self.assertEqual(x, int(GENERATOR[2:], 16))
        self.assertEqual(y, GENERATOR_Y)
        self.assertEqual(v.compressed_point("03" + GENERATOR[2:]), (x, v.FIELD - y))

    def test_fixed_point_equation_parity(self):
        x, y = v.compressed_point(v.PUBLIC_KEY)
        self.assertEqual(y * y % v.FIELD, (x**3 + 7) % v.FIELD)
        self.assertEqual(y % 2, 1)

    def test_invalid_sec_encodings(self):
        fixtures = ["", "00", GENERATOR[:-2], GENERATOR + "00",
                    "04" + GENERATOR[2:], "06" + GENERATOR[2:],
                    "00" + GENERATOR[2:], "02" + "ff" * 32,
                    "02" + format(v.FIELD, "064x"),
                    "02" + "00" * 32,  # x=0 gives nonsquare 7 on secp256k1
                    "03" + "00" * 32,
                    "0x" + GENERATOR, " " + GENERATOR, GENERATOR + "\n",
                    "02" + "gg" * 32,
                    "04" + GENERATOR[2:] + format(GENERATOR_Y, "064x")]
        for sec in fixtures:
            with self.subTest(sec=sec):
                with self.assertRaises(v.InvalidPublicInput):
                    v.compressed_point(sec)

    def test_uppercase_hex(self):
        self.assertEqual(v.compressed_point(GENERATOR.upper()), v.compressed_point(GENERATOR))


class Base58Tests(unittest.TestCase):
    def test_standard_generator_address(self):
        address, digest = v.derive_p2pkh(GENERATOR)
        self.assertEqual(address, GENERATOR_ADDRESS)
        self.assertEqual(digest.hex(), "751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertEqual(v.p2pkh_payload(address), digest)

    def test_fixed_address_payload(self):
        digest = v.p2pkh_payload(v.CHALLENGE_ADDRESS)
        self.assertEqual(digest.hex(), "ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a")
        self.assertEqual(v.derive_p2pkh(v.PUBLIC_KEY), (v.CHALLENGE_ADDRESS, digest))

    def test_every_single_character_substitution(self):
        for index, original in enumerate(v.CHALLENGE_ADDRESS):
            for char in v.BASE58:
                if char != original:
                    damaged = v.CHALLENGE_ADDRESS[:index] + char + v.CHALLENGE_ADDRESS[index + 1:]
                    with self.assertRaises(v.InvalidPublicInput):
                        v.p2pkh_payload(damaged)

    def test_wrong_network_and_script_type_with_valid_checksum(self):
        digest = bytes(range(20))  # SYNTHETIC public payload
        for version in (111, 5, 196):
            with self.subTest(version=version):
                address = v.base58check_encode(bytes([version]) + digest)
                with self.assertRaisesRegex(v.InvalidPublicInput, "mainnet P2PKH"):
                    v.p2pkh_payload(address)

    def test_invalid_alphabet_whitespace_and_length(self):
        for address in ("", "1" * 26, "1" * 36, " " + v.CHALLENGE_ADDRESS,
                        v.CHALLENGE_ADDRESS + "\n", "0" + v.CHALLENGE_ADDRESS[1:],
                        "I" + v.CHALLENGE_ADDRESS[1:], "1" + v.CHALLENGE_ADDRESS):
            with self.subTest(address=address):
                with self.assertRaises(v.InvalidPublicInput):
                    v.p2pkh_payload(address)

    def test_leading_zero_payload_roundtrip(self):
        digest = bytes(range(20))  # SYNTHETIC; includes a leading zero byte
        self.assertEqual(v.p2pkh_payload(v.base58check_encode(b"\0" + digest)), digest)

    def test_hashlib_ripemd160_known_answer(self):
        self.assertEqual(hashlib.new("ripemd160", b"").hexdigest(),
                         "9c1185a5c5e9fc54612808977ee8f548b2258d31")

    def test_script_rejects_wrong_length(self):
        with self.assertRaises(v.InvalidPublicInput):
            v.p2pkh_script(bytes(19))


class Bech32mTests(unittest.TestCase):
    def test_bip350_generic_vectors(self):
        for address in ("A1LQFN3A", "a1lqfn3a",
                        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"):
            with self.subTest(address=address):
                v.decode_bech32m(address)

    def test_bip350_invalid_generic_vectors(self):
        for address in ("\x201xj0phk", "\x7f1g6xzxy", "\x801vctc34",
                        "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g",
                        "lt1igcx5c0", "in1muywd", "mm1crxm3i", "M1VUXWEZ",
                        "16plkw9", "1p2gdwpf"):
            with self.subTest(address=address):
                with self.assertRaises(v.InvalidPublicInput):
                    v.decode_bech32m(address)

    def test_bip350_witness_vector(self):
        self.assertEqual(v.recipient_program(BIP350_ADDRESS).hex(), GENERATOR[2:])
        self.assertEqual(v.recipient_program(BIP350_ADDRESS.upper()).hex(), GENERATOR[2:])

    def test_fixed_recipient(self):
        self.assertEqual(v.recipient_program(v.RECIPIENT).hex(),
                         "46bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f")
        self.assertEqual(v.recipient_program(v.RECIPIENT.upper()), v.recipient_program(v.RECIPIENT))

    def test_every_single_data_or_checksum_substitution(self):
        for index in range(3, len(v.RECIPIENT)):
            for char in v.BECH32:
                if char != v.RECIPIENT[index]:
                    damaged = v.RECIPIENT[:index] + char + v.RECIPIENT[index + 1:]
                    with self.assertRaisesRegex(v.InvalidPublicInput, "checksum"):
                        v.recipient_program(damaged)

    def test_wrong_network_with_valid_checksum(self):
        for hrp in ("tb", "bcrt", "tc"):
            with self.subTest(hrp=hrp):
                address = fixture_address(hrp=hrp)
                self.assertEqual(v.decode_bech32m(address)[0], hrp)
                with self.assertRaisesRegex(v.InvalidPublicInput, "mainnet HRP"):
                    v.recipient_program(address)

    def test_wrong_checksum_variant(self):
        with self.assertRaisesRegex(v.InvalidPublicInput, "checksum"):
            v.recipient_program(fixture_address(constant=1))

    def test_wrong_versions(self):
        for version in (0, 2, 16, 17, 31):
            with self.subTest(version=version):
                with self.assertRaisesRegex(v.InvalidPublicInput, "version 1"):
                    v.recipient_program(fixture_address(version=version))

    def test_wrong_program_lengths(self):
        for length in (0, 1, 2, 20, 31, 33, 40):
            with self.subTest(length=length):
                with self.assertRaisesRegex(v.InvalidPublicInput, "32 bytes"):
                    v.recipient_program(fixture_address(program=bytes(range(length))))

    def test_padding_with_valid_checksums(self):
        words = fixture_words(bytes(range(32)))
        for bad_words in (words[:-1] + [words[-1] | 1], words + [0, 0]):
            with self.subTest(words=bad_words):
                with self.assertRaisesRegex(v.InvalidPublicInput, "padding"):
                    v.recipient_program(fixture_address(words=bad_words))

    def test_empty_data_section(self):
        with self.assertRaises(v.InvalidPublicInput):
            v.recipient_program("bc1gmk9yu")  # published BIP350 invalid witness vector
        with self.assertRaisesRegex(v.InvalidPublicInput, "version 1"):
            v.recipient_program(fixture_encode("bc", []))

    def test_case_length_alphabet_and_whitespace(self):
        for address in ("bC" + v.RECIPIENT[2:], v.RECIPIENT + "\n",
                        " " + v.RECIPIENT, "bc1" + "q" * 88,
                        v.RECIPIENT[:-1] + "i", v.RECIPIENT[:-1] + "é",
                        "bc1qqqqq", "", "bcqqqqqqqq"):
            with self.subTest(address=address):
                with self.assertRaises(v.InvalidPublicInput):
                    v.recipient_program(address)

    def test_synthetic_roundtrips(self):
        for offset in range(32):
            program = bytes((offset + i * 7) % 256 for i in range(32))
            self.assertEqual(v.recipient_program(fixture_address(program=program)), program)


class ReportAndCliTests(unittest.TestCase):
    def test_fixed_report(self):
        result = v.verify_manifest()
        self.assertEqual(result["overall"], "PASS")
        self.assertEqual(len(result["checks"]), 6)
        self.assertTrue(all(c["status"] == "PASS" for c in result["checks"].values()))
        self.assertEqual(result["goal_status"], "INCOMPLETE")
        self.assertEqual(result["scripts_hex"], {
            "challenge_p2pkh": "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac",
            "derived_key_p2pkh": "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac",
            "recipient_witness_v1": "512046bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f"})
        bounds = result["interval"]
        self.assertEqual(int(bounds["lower_inclusive_hex"], 16), 2**139)
        self.assertEqual(int(bounds["upper_inclusive_hex"], 16), 2**140 - 1)
        self.assertEqual(int(bounds["candidate_count_decimal"]), 2**139)

    def test_valid_but_unrelated_public_key_fails_match(self):
        result = v.verify_manifest(public_key=GENERATOR)
        self.assertEqual(result["checks"]["compressed_sec_point"]["status"], "PASS")
        self.assertEqual(result["checks"]["public_key_address_match"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_failures_do_not_hide_independent_checks(self):
        result = v.verify_manifest(public_key="02" + "00" * 32)
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["checks"]["compressed_sec_point"]["status"], "FAIL")
        self.assertEqual(result["checks"]["public_key_address_match"]["status"], "SKIP")
        self.assertEqual(result["checks"]["recipient_mainnet_bech32m_v1_32"]["status"], "PASS")
        self.assertIsNone(result["scripts_hex"]["derived_key_p2pkh"])

    def test_invalid_addresses_emit_no_script_for_that_field(self):
        result = v.verify_manifest(challenge_address="invalid", recipient="invalid")
        self.assertEqual(result["overall"], "FAIL")
        self.assertIsNone(result["scripts_hex"]["challenge_p2pkh"])
        self.assertIsNone(result["scripts_hex"]["recipient_witness_v1"])
        self.assertIsNotNone(result["scripts_hex"]["derived_key_p2pkh"])

    def test_missing_ripemd160_fails_closed(self):
        with mock.patch.object(v.hashlib, "new", side_effect=ValueError("unavailable")):
            result = v.verify_manifest()
        self.assertEqual(result["overall"], "FAIL")
        self.assertEqual(result["checks"]["public_key_hash160"], {
            "status": "FAIL", "detail": "Python hashlib RIPEMD-160 support is required"})
        self.assertEqual(result["checks"]["public_key_address_match"]["status"], "SKIP")

    def test_main_returns_one_for_each_failed_field(self):
        original = v.verify_manifest
        for kwargs in ({"public_key": GENERATOR}, {"public_key": "invalid"},
                       {"challenge_address": "invalid"}, {"recipient": "invalid"}):
            output = io.StringIO()
            with self.subTest(kwargs=kwargs), contextlib.redirect_stdout(output):
                with mock.patch.object(v, "verify_manifest", functools.partial(original, **kwargs)):
                    self.assertEqual(v.main([]), 1)
            self.assertEqual(json.loads(output.getvalue())["overall"], "FAIL")

    def test_cli_success_and_determinism(self):
        command = [sys.executable, "-B", str(Path(v.__file__).resolve())]
        first = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        second = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stderr, "")
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout), v.verify_manifest())

    def test_cli_rejects_inputs_without_echo(self):
        marker = "unrecognized-public-input"
        process = subprocess.run([sys.executable, "-B", str(Path(v.__file__).resolve()), marker],
                                 capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertNotIn(marker, process.stderr)

    def test_help(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(v.main(["--help"]), 0)
        self.assertIn("fixed public manifest", output.getvalue())


if __name__ == "__main__":
    unittest.main()
