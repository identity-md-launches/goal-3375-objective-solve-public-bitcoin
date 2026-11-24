"""Offline tests for candidate-check. Synthetic data only.

Every scalar used here is either a published curve test vector, an interval
boundary, or a labelled SYNTHETIC value derived from a fixed public string.
A pass of this suite is not a recovered Puzzle #140 key.

Run from the repository root:
    python3 -B -m unittest discover -s candidate-check/tests -p 'test_*.py' -v
"""

import ast
import base64
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT_DIR = os.path.dirname(HERE)
sys.path.insert(0, COMPONENT_DIR)

import candidate_check  # noqa: E402
import cc_core  # noqa: E402
import cc_primitives as prim  # noqa: E402
import synthetic_api  # noqa: E402

PRODUCTION_CLI = os.path.join(COMPONENT_DIR, "candidate_check.py")
SYNTHETIC_CLI = os.path.join(COMPONENT_DIR, "synthetic_api.py")
PRODUCTION_MANIFEST_SHA256 = "15cad4c3c92f31e8a60e6a85b11dd6044201209e0060d48248e260a920e6f048"
LOW = 2 ** 139
HIGH = 2 ** 140 - 1
REPORT_KEYS = {"component", "schema", "mode", "manifest_sha256", "source_sha256",
               "source_bundle_sha256", "checks", "candidate_verified",
               "production_candidate_verified", "scope"}
ERROR_KEYS = {"component", "schema", "mode", "error", "candidate_verified",
              "production_candidate_verified"}

# Published secp256k1 vectors (k, x, y): SEC 2 generator and the widely
# reproduced "secp256k1 test vectors" list (C. Batson, 2014).
PUBLISHED_POINTS = (
    (1, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
     "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    (2, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
     "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
    (3, "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
    (7, "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
     "6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"),
    (112233445566778899, "A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29",
     "5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76"),
    (prim.N - 2, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
     "E51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705"),
    (prim.N - 1, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
     "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777"),
)
# Long-public solved puzzle keys #1..#5 with their compressed P2PKH addresses and ranges.
PUBLISHED_ADDRESSES = (
    (1, 1, 1, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    (3, 2, 3, "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb"),
    (7, 4, 7, "19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA"),
    (8, 8, 15, "1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e"),
    (21, 16, 31, "1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k"),
)
# RIPEMD-160 vectors from the original specification.
RIPEMD_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
)


def synthetic_scalar(tag, lower=1, upper=prim.N - 1):
    """Deterministic labelled synthetic scalar in [lower, upper]."""
    digest = hashlib.sha256(("candidate-check SYNTHETIC SECRET SENTINEL " + tag).encode()).digest()
    return lower + int.from_bytes(digest, "big") % (upper - lower + 1)


def be32(value):
    return value.to_bytes(32, "big")


SENTINEL_IN_RANGE = be32(synthetic_scalar("in-range", LOW, HIGH))
SENTINEL_FULL = be32(synthetic_scalar("full-width", 2 ** 255, prim.N - 1))


def wif(secret, compressed):
    return prim.base58check_encode(b"\x80" + secret + (b"\x01" if compressed else b""))


def forbidden_forms(secret):
    """Byte strings that must never appear in output for a 32-byte secret."""
    forms = set()
    texts = [secret.hex(), secret.hex().upper(), secret[::-1].hex(), secret[::-1].hex().upper(),
             str(int.from_bytes(secret, "big")), str(int.from_bytes(secret, "little")),
             base64.b64encode(secret).decode(), base64.urlsafe_b64encode(secret).decode(),
             wif(secret, True), wif(secret, False), "%x" % int.from_bytes(secret, "big")]
    scalar = int.from_bytes(secret, "big")
    if 1 <= scalar < prim.N:
        x, y = prim.multiply_jacobian(scalar)
        sec = prim.encode_compressed(x, y)
        texts += ["%064x" % x, "%064X" % x, "%064x" % y, "%064X" % y,
                  prim.p2pkh_address_from_compressed(sec), prim.hash160(sec).hex()]
    for text in texts:
        forms.add(text.encode())
    for text, width in ((secret.hex(), 16), (secret.hex().upper(), 16), (secret[::-1].hex(), 16),
                        (repr(secret)[2:-1], 16), (repr(list(secret))[1:-1], 24),
                        (str(scalar), 12), (base64.b64encode(secret).decode(), 12),
                        (wif(secret, True), 12), (wif(secret, False), 12)):
        for start in range(0, len(text) - width + 1):
            forms.add(text[start:start + width].encode())
    stripped = secret.lstrip(b"\x00")
    for start in range(0, len(stripped) - 8 + 1):
        forms.add(stripped[start:start + 8])
    forms.add(secret)
    return forms


def run_cli(script, args, payload=None, chunks=None, stdout=None, env=None):
    """Run a command. '{fd}' in args is replaced by a pipe delivering payload then EOF."""
    read_end = write_end = None
    pass_fds = ()
    if payload is not None or chunks is not None:
        read_end, write_end = os.pipe()
        pass_fds = (read_end,)
        args = [arg.replace("{fd}", str(read_end)) for arg in args]
    proc = subprocess.Popen([sys.executable, "-I", "-B", script] + list(args),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if stdout is None else stdout,
                            stderr=subprocess.PIPE, pass_fds=pass_fds, env=env)
    if read_end is not None:
        os.close(read_end)
        try:
            for index, chunk in enumerate(chunks if chunks is not None else [payload]):
                if index:
                    time.sleep(0.15)
                if chunk:
                    os.write(write_end, chunk)
        except BrokenPipeError:
            pass
        finally:
            os.close(write_end)
    out, err = proc.communicate(timeout=120)
    return proc.returncode, out or b"", err


def run_harness(code):
    """Run a python -c harness with the component directory importable."""
    prelude = "import sys; sys.dont_write_bytecode = True; sys.path.insert(0, %r)\n" % COMPONENT_DIR
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", prelude + code],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


class PublishedVectorTests(unittest.TestCase):
    def test_curve_constants(self):
        self.assertEqual(prim.P, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
        self.assertTrue(prim.is_on_curve(prim.GX, prim.GY))
        self.assertEqual(pow(2, prim.P - 1, prim.P), 1)

    def test_published_points_by_both_multipliers(self):
        for scalar, x_hex, y_hex in PUBLISHED_POINTS:
            expected = (int(x_hex, 16), int(y_hex, 16))
            self.assertEqual(prim.multiply_jacobian(scalar), expected)
            self.assertEqual(prim.multiply_ladder(scalar), expected)
            self.assertEqual(prim.multiply_checked(scalar), expected)
            encoded = prim.encode_compressed(*expected)
            self.assertEqual(encoded.hex().upper(), "0%d%s" % (2 + expected[1] % 2, x_hex))
            self.assertEqual(prim.decode_compressed(encoded), expected)

    def test_multipliers_agree_on_synthetic_scalars_and_group_law(self):
        for index in range(12):
            scalar = synthetic_scalar("agree-%d" % index)
            point = prim.multiply_jacobian(scalar)
            self.assertEqual(point, prim.multiply_ladder(scalar))
            self.assertTrue(prim.is_on_curve(*point))
            negated = prim.multiply_jacobian(prim.N - scalar)
            self.assertEqual(negated, (point[0], prim.P - point[1]))
        a, b = synthetic_scalar("law-a", 1, 2 ** 200), synthetic_scalar("law-b", 1, 2 ** 200)
        self.assertEqual(prim.multiply_jacobian(b, prim.multiply_jacobian(a)),
                         prim.multiply_ladder(a * b % prim.N))

    def test_ripemd160_published_vectors(self):
        for message, digest in RIPEMD_VECTORS:
            self.assertEqual(prim.ripemd160(message).hex(), digest)
        for size in (55, 56, 57, 63, 64, 65, 119, 120, 128):
            try:
                reference = hashlib.new("ripemd160", b"\xa5" * size).digest()
            except ValueError:
                self.skipTest("hashlib has no ripemd160 to compare against")
            self.assertEqual(prim.ripemd160(b"\xa5" * size), reference)

    def test_published_addresses(self):
        for scalar, _lower, _upper, address in PUBLISHED_ADDRESSES:
            encoded = prim.encode_compressed(*prim.multiply_checked(scalar))
            self.assertEqual(prim.p2pkh_address_from_compressed(encoded), address)
            self.assertEqual(prim.p2pkh_hash_from_address(address), prim.hash160(encoded))

    def test_invalid_scalars_rejected_by_multipliers(self):
        for scalar in (0, -1, prim.N, prim.N + 1, 2 ** 256 - 1, 2 ** 256, True and 1.0, "1", None):
            for multiply in (prim.multiply_jacobian, prim.multiply_ladder, prim.multiply_checked):
                with self.assertRaises(prim.PrimitiveError):
                    multiply(scalar)

    def test_invalid_points_rejected(self):
        gx = prim.GX.to_bytes(32, "big")
        # x = 0, 5, 7, 9 have no curve point (Euler criterion, checked independently here).
        for x in (0, 5, 7, 9):
            self.assertNotEqual(pow((x ** 3 + 7) % prim.P, (prim.P - 1) // 2, prim.P), 1)
            with self.assertRaises(prim.PrimitiveError):
                prim.decode_compressed(b"\x02" + x.to_bytes(32, "big"))
        bad = [b"\x04" + gx, b"\x00" + gx, b"\x05" + gx, b"\x02" + gx[:-1], b"\x02" + gx + b"\x00",
               b"", b"\x00", b"\x02" + prim.P.to_bytes(32, "big"),
               b"\x02" + (prim.P + 1).to_bytes(32, "big"), b"\x03" + b"\xff" * 32,
               "02" + gx.hex(), None]
        for encoding in bad:
            with self.assertRaises(prim.PrimitiveError):
                prim.decode_compressed(encoding)
        self.assertFalse(prim.is_on_curve(prim.GX, prim.GY + 1))
        self.assertFalse(prim.is_on_curve(prim.GX + prim.P, prim.GY))
        self.assertFalse(prim.is_on_curve(0, 0))
        with self.assertRaises(prim.PrimitiveError):
            prim.encode_compressed(prim.GX, prim.GY + 1)
        with self.assertRaises(prim.PrimitiveError):
            prim.multiply_jacobian(2, (prim.GX, prim.GY + 1))
        with self.assertRaises(prim.PrimitiveError):
            prim.multiply_ladder(2, (1, 1))

    def test_base58check_strictness(self):
        address = PUBLISHED_ADDRESSES[0][3]
        for text in (address[:-1], address + "1", address[:-1] + "J", "0" + address[1:], "", "l",
                     address.encode(), None, "3" + address[1:]):
            with self.assertRaises(prim.PrimitiveError):
                prim.p2pkh_hash_from_address(text)

    def test_self_test_passes_and_fails_closed(self):
        cc_core.self_test()
        original = prim.ripemd160
        try:
            prim.ripemd160 = lambda data: b"\x00" * 20
            with self.assertRaises(cc_core.Refusal) as caught:
                cc_core.self_test()
            self.assertEqual(caught.exception.code, "self_test_failed")
            self.assertEqual(caught.exception.exit_status, cc_core.EXIT_INTERNAL)
        finally:
            prim.ripemd160 = original


class ProductionPathTests(unittest.TestCase):
    """The production target with synthetic, non-matching candidates only."""

    def assert_report(self, report, mode="PRODUCTION"):
        expected_keys = REPORT_KEYS | ({"synthetic_notice"} if mode == "SYNTHETIC" else set())
        self.assertEqual(set(report), expected_keys)
        self.assertEqual(report["mode"], mode)
        self.assertEqual(set(report["checks"]), set(cc_core.CHECK_NAMES))
        for value in list(report["checks"].values()) + [report["candidate_verified"],
                                                        report["production_candidate_verified"]]:
            self.assertIsInstance(value, bool)
        self.assertEqual(report["candidate_verified"], all(report["checks"].values()))

    def test_fixed_public_manifest(self):
        target = cc_core.production_target()
        self.assertEqual(target.public_key.hex(),
                         "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640")
        self.assertEqual(target.address, "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo")
        self.assertEqual((target.lower, target.upper), (2 ** 139, 2 ** 140 - 1))
        self.assertTrue(prim.is_on_curve(*prim.decode_compressed(target.public_key)))
        self.assertEqual(prim.p2pkh_address_from_compressed(target.public_key), target.address)
        self.assertEqual(cc_core.manifest_sha256(target), PRODUCTION_MANIFEST_SHA256)
        canonical = ('{"candidate_encoding":"32-byte big-endian scalar","compressed_public_key":'
                     '"031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640",'
                     '"curve":"secp256k1","interval_lower_hex":"%064x","interval_upper_hex":"%064x",'
                     '"label":"bitcoin-puzzle-140","mode":"PRODUCTION","p2pkh_address":'
                     '"1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"}' % (2 ** 139, 2 ** 140 - 1))
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), PRODUCTION_MANIFEST_SHA256)

    def test_interval_boundaries(self):
        for scalar, inside in ((LOW - 1, False), (LOW, True), (LOW + 1, True), (HIGH - 1, True),
                               (HIGH, True), (HIGH + 1, False), (1, False), (prim.N - 1, False)):
            report = candidate_check.verify_production_candidate(be32(scalar))
            self.assert_report(report)
            self.assertEqual(report["checks"], {
                "descriptor_exact_32_bytes": True, "scalar_valid": True,
                "scalar_in_interval": inside, "public_key_match": False,
                "p2pkh_address_match": False})
            self.assertFalse(report["candidate_verified"])
            self.assertFalse(report["production_candidate_verified"])

    def test_invalid_scalars(self):
        for scalar in (0, prim.N, prim.N + 1, 2 ** 256 - 1):
            report = candidate_check.verify_production_candidate(be32(scalar))
            self.assertEqual(report["checks"], {
                "descriptor_exact_32_bytes": True, "scalar_valid": False,
                "scalar_in_interval": False, "public_key_match": False,
                "p2pkh_address_match": False})

    def test_endianness(self):
        big = be32(LOW)
        little = LOW.to_bytes(32, "little")
        self.assertNotEqual(big, little)
        self.assertTrue(candidate_check.verify_production_candidate(big)["checks"]["scalar_in_interval"])
        report = candidate_check.verify_production_candidate(little)
        self.assertTrue(report["checks"]["scalar_valid"])
        self.assertFalse(report["checks"]["scalar_in_interval"])

    def test_in_process_failure_is_a_fixed_refusal_without_chained_exception(self):
        marker = SENTINEL_IN_RANGE.hex()
        original = prim.multiply_checked

        def boom(scalar):
            raise RuntimeError("leak " + marker + " %d" % scalar)
        try:
            prim.multiply_checked = boom
            with self.assertRaises(cc_core.Refusal) as caught:
                cc_core.evaluate(SENTINEL_IN_RANGE, cc_core.production_target())
        finally:
            prim.multiply_checked = original
        error = caught.exception
        self.assertEqual((error.code, error.exit_status, str(error), error.args),
                         ("internal_error", 3, "refused", ("refused",)))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)

    def test_wrong_length_or_type(self):
        for candidate in (b"", b"\x01", SENTINEL_IN_RANGE[:31], SENTINEL_IN_RANGE + b"\x00",
                          SENTINEL_IN_RANGE * 2, SENTINEL_IN_RANGE.hex(), 5, None,
                          list(SENTINEL_IN_RANGE)):
            report = candidate_check.verify_production_candidate(candidate)
            self.assert_report(report)
            self.assertEqual(set(report["checks"].values()), {False})

    def test_no_alternate_production_target(self):
        self.assertEqual(list(inspect.signature(candidate_check.verify_production_candidate).parameters),
                         ["candidate"])
        self.assertEqual(list(inspect.signature(candidate_check.verify_production_candidate_fd).parameters),
                         ["fd"])
        self.assertEqual(list(inspect.signature(cc_core.production_target).parameters), [])
        for extra in (["--public-key", "02" + "11" * 32], ["--address", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"],
                      ["--range", "1:2"], ["--lower", "1"], ["--upper", "2"], ["--interval=1:2"],
                      ["--challenge-file", "x.json"], ["--manifest"], ["--help"], ["extra"],
                      ["--candidate-fd", "{fd}"]):
            code, out, err = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"] + extra,
                                     payload=SENTINEL_IN_RANGE)
            self.assertEqual(code, 2, extra)
            report = json.loads(out)
            self.assertEqual(set(report), ERROR_KEYS)
            self.assertEqual(report["error"], "usage")
            self.assertEqual(err.decode(), candidate_check.USAGE + "\n")

    def test_environment_cannot_change_target(self):
        noisy = {"PATH": "/usr/bin:/bin", "PUBLIC_KEY": "02" + "11" * 32, "PUZZLE_ADDRESS": "x",
                 "CANDIDATE_CHECK_PUBLIC_KEY": "02" + "11" * 32, "CANDIDATE_CHECK_RANGE": "1:2",
                 "PYTHONPATH": "/nonexistent", "PYTHONINSPECT": "", "PYTHONSTARTUP": "/nonexistent"}
        clean = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=SENTINEL_IN_RANGE,
                        env={"PATH": "/usr/bin:/bin"})
        dirty = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=SENTINEL_IN_RANGE, env=noisy)
        self.assertEqual(clean, dirty)
        self.assertEqual(clean[0], 1)
        self.assertEqual(json.loads(clean[1])["manifest_sha256"], PRODUCTION_MANIFEST_SHA256)

    def test_cli_boundaries_truncation_and_exit_codes(self):
        cases = ((be32(LOW), 1, True, True), (be32(HIGH), 1, True, True),
                 (be32(LOW - 1), 1, True, False), (be32(HIGH + 1), 1, True, False),
                 (LOW.to_bytes(32, "little"), 1, True, False),
                 (b"", 1, False, False), (b"\x80", 1, False, False),
                 (be32(LOW)[:31], 1, False, False), (be32(LOW)[1:], 1, False, False),
                 (be32(LOW) + b"\n", 1, False, False), (be32(LOW) * 2, 1, False, False),
                 (be32(LOW).hex().encode(), 1, False, False))
        for payload, exit_code, exact, inside in cases:
            code, out, err = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=payload)
            self.assertEqual((code, err), (exit_code, b""))
            report = json.loads(out)
            self.assert_report(report)
            self.assertEqual(report["checks"]["descriptor_exact_32_bytes"], exact)
            self.assertEqual(report["checks"]["scalar_in_interval"], inside)
            self.assertFalse(report["checks"]["public_key_match"])
            self.assertFalse(report["production_candidate_verified"])

    def test_cli_descriptor_errors(self):
        for args in (["--candidate-fd", "1"], ["--candidate-fd", "2"], ["--candidate-fd", "-1"],
                     ["--candidate-fd", "3x"], ["--candidate-fd", ""], ["--candidate-fd", "1234567"],
                     ["--candidate-fd=two"]):
            code, out, err = run_cli(PRODUCTION_CLI, args)
            self.assertEqual(code, 2, args)
            self.assertEqual(json.loads(out)["error"], "candidate_descriptor_invalid")
        code, out, err = run_cli(PRODUCTION_CLI, ["--candidate-fd", "777"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"], "candidate_descriptor_unreadable")
        for args in ([], ["--candidate-fd"], ["--bogus"]):
            code, out, err = run_cli(PRODUCTION_CLI, args)
            self.assertEqual((code, json.loads(out)["error"]), (2, "usage"))

    def test_cli_help_and_manifest(self):
        code, out, err = run_cli(PRODUCTION_CLI, ["--help"])
        self.assertEqual((code, out.decode(), err), (0, candidate_check.USAGE + "\n", b""))
        code, out, err = run_cli(PRODUCTION_CLI, ["--manifest"])
        self.assertEqual((code, err), (0, b""))
        report = json.loads(out)
        self.assertEqual(report["manifest_sha256"], PRODUCTION_MANIFEST_SHA256)
        self.assertEqual(report["manifest"], cc_core.public_manifest(cc_core.production_target()))
        self.assertNotIn("candidate_verified", report)
        for name, digest in report["source_sha256"].items():
            with open(os.path.join(COMPONENT_DIR, name), "rb") as handle:
                self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), digest)

    def test_output_depends_only_on_booleans(self):
        first = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=SENTINEL_IN_RANGE)
        second = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"],
                         payload=be32(synthetic_scalar("other-in-range", LOW, HIGH)))
        self.assertEqual(first, second)
        self.assertEqual(first[0], 1)


class SyntheticApiTests(unittest.TestCase):
    def descriptor(self, scalar, lower, upper, label="SYNTHETIC-unit"):
        return synthetic_api.make_challenge(label, scalar, lower, upper)

    def test_known_answers_pass_but_never_as_production(self):
        cases = [(k, lo, hi) for k, lo, hi, _ in PUBLISHED_ADDRESSES]
        cases += [(LOW, LOW, HIGH), (HIGH, LOW, HIGH), (prim.N - 1, 1, prim.N - 1),
                  (112233445566778899, 2 ** 56, 2 ** 57 - 1)]
        for scalar, lower, upper in cases:
            descriptor = self.descriptor(scalar, lower, upper)
            report = synthetic_api.check_synthetic_candidate(be32(scalar), descriptor)
            self.assertEqual(set(report["checks"].values()), {True})
            self.assertTrue(report["candidate_verified"])
            self.assertFalse(report["production_candidate_verified"])
            self.assertEqual(report["mode"], "SYNTHETIC")
            self.assertEqual(report["synthetic_notice"], cc_core.SYNTHETIC_NOTICE)
            self.assertNotEqual(report["manifest_sha256"], PRODUCTION_MANIFEST_SHA256)
        for scalar, lower, upper, address in PUBLISHED_ADDRESSES:
            self.assertEqual(self.descriptor(scalar, lower, upper)["p2pkh_address"], address)
        self.assertEqual(self.descriptor(1, 1, 1)["compressed_public_key"],
                         "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    def test_both_boundaries(self):
        lower, upper = 2 ** 40, 2 ** 41 - 1
        for scalar, inside in ((lower - 1, False), (lower, True), (upper, True), (upper + 1, False)):
            report = synthetic_api.check_synthetic_candidate(
                be32(scalar), self.descriptor(scalar, lower, upper))
            self.assertEqual(report["checks"], {
                "descriptor_exact_32_bytes": True, "scalar_valid": True,
                "scalar_in_interval": inside, "public_key_match": True,
                "p2pkh_address_match": True})
            self.assertEqual(report["candidate_verified"], inside)

    def test_wrong_candidates_and_endianness(self):
        scalar = synthetic_scalar("wrong", 2 ** 40, 2 ** 41 - 1)
        descriptor = self.descriptor(scalar, 2 ** 40, 2 ** 41 - 1)
        good = be32(scalar)
        self.assertTrue(synthetic_api.check_synthetic_candidate(good, descriptor)["candidate_verified"])
        self.assertTrue(synthetic_api.check_synthetic_candidate(bytearray(good), descriptor)["candidate_verified"])
        for candidate in (good[::-1], scalar.to_bytes(32, "little"), be32(scalar + 1), be32(scalar - 1),
                          be32(prim.N - scalar), be32(scalar ^ (1 << 255)), good[:31], good + b"\x00",
                          good[1:] + b"\x00", be32(0), be32(prim.N), be32(prim.N + scalar)):
            report = synthetic_api.check_synthetic_candidate(candidate, descriptor)
            self.assertFalse(report["candidate_verified"])
            self.assertFalse(report["checks"]["public_key_match"])
            self.assertFalse(report["checks"]["p2pkh_address_match"])

    def test_address_mismatch_is_reported_separately(self):
        scalar = synthetic_scalar("addr", 2 ** 40, 2 ** 41 - 1)
        descriptor = self.descriptor(scalar, 2 ** 40, 2 ** 41 - 1)
        descriptor["p2pkh_address"] = PUBLISHED_ADDRESSES[0][3]
        report = synthetic_api.check_synthetic_candidate(be32(scalar), descriptor)
        self.assertTrue(report["checks"]["public_key_match"])
        self.assertFalse(report["checks"]["p2pkh_address_match"])
        self.assertFalse(report["candidate_verified"])

    def expect_refusal(self, descriptor, code):
        with self.assertRaises(cc_core.Refusal) as caught:
            synthetic_api.check_synthetic_candidate(be32(5), descriptor)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), "refused")

    def test_descriptor_truncation_and_malformation(self):
        base = self.descriptor(5, 4, 7)
        for key in synthetic_api.DESCRIPTOR_KEYS:
            cut = dict(base)
            del cut[key]
            self.expect_refusal(cut, "challenge_descriptor_malformed")
            wrong_type = dict(base)
            wrong_type[key] = 7
            self.expect_refusal(wrong_type, "challenge_descriptor_malformed")
        self.expect_refusal(dict(base, extra="x"), "challenge_descriptor_malformed")
        self.expect_refusal(None, "challenge_descriptor_malformed")
        self.expect_refusal([base], "challenge_descriptor_malformed")
        key_hex = base["compressed_public_key"]
        for bad in (key_hex[:-2], key_hex[:-1], key_hex + "00", "", key_hex.upper(), key_hex[2:]):
            self.expect_refusal(dict(base, compressed_public_key=bad), "challenge_public_key_invalid")
        for name in ("interval_lower_hex", "interval_upper_hex"):
            for bad in (base[name][:-1], base[name][2:], base[name] + "0", "", "0x" + base[name][2:]):
                self.expect_refusal(dict(base, **{name: bad}), "challenge_interval_invalid")
        address = base["p2pkh_address"]
        for bad in (address[:-1], address[1:], address + "1", ""):
            self.expect_refusal(dict(base, p2pkh_address=bad), "challenge_address_invalid")

    def test_invalid_points_intervals_and_labels(self):
        base = self.descriptor(5, 4, 7)
        gx = "%064x" % prim.GX
        for bad in ("02" + "%064x" % 5, "02" + "00" * 32, "04" + gx, "00" + gx,
                    "02" + "%064x" % prim.P, "03" + "ff" * 32):
            self.expect_refusal(dict(base, compressed_public_key=bad), "challenge_public_key_invalid")
        for lower, upper in ((0, 7), (8, 7), (4, prim.N), (prim.N, prim.N), (0, 0)):
            self.expect_refusal(dict(base, interval_lower_hex="%064x" % lower,
                                     interval_upper_hex="%064x" % upper), "challenge_interval_invalid")
        for label in ("unit", "synthetic-x", "SYNTHETIC-", "SYNTHETIC-a b", "PRODUCTION",
                      "bitcoin-puzzle-140", "SYNTHETIC-" + "a" * 49):
            self.expect_refusal(dict(base, label=label), "challenge_label_invalid")

    def test_production_target_refused(self):
        base = self.descriptor(5, 4, 7)
        key = cc_core.PRODUCTION_PUBLIC_KEY_HEX
        production = dict(base, compressed_public_key=key, p2pkh_address=cc_core.PRODUCTION_ADDRESS,
                          interval_lower_hex="%064x" % LOW, interval_upper_hex="%064x" % HIGH)
        self.expect_refusal(production, "production_target_refused")
        self.expect_refusal(dict(production, interval_lower_hex="%064x" % 1), "production_target_refused")
        self.expect_refusal(dict(base, compressed_public_key=key), "production_target_refused")
        self.expect_refusal(dict(base, compressed_public_key="02" + key[2:]), "production_target_refused")
        self.expect_refusal(dict(base, p2pkh_address=cc_core.PRODUCTION_ADDRESS), "production_target_refused")
        with self.assertRaises(cc_core.Refusal):
            cc_core.synthetic_target("SYNTHETIC-x", bytes.fromhex(key), base["p2pkh_address"], 1, 2)

    def test_fd_api_exact_length(self):
        scalar = synthetic_scalar("fd", 2 ** 40, 2 ** 41 - 1)
        descriptor = self.descriptor(scalar, 2 ** 40, 2 ** 41 - 1)
        for payload, expected in ((be32(scalar), True), (be32(scalar)[:31], False),
                                  (be32(scalar) + b"\x00", False), (b"", False)):
            read_end, write_end = os.pipe()
            os.write(write_end, payload)
            os.close(write_end)
            report = synthetic_api.check_synthetic_candidate_fd(read_end, descriptor)
            self.assertEqual(report["candidate_verified"], expected)
            self.assertEqual(report["checks"]["descriptor_exact_32_bytes"], len(payload) == 32)
            with self.assertRaises(OSError):
                os.fstat(read_end)  # the descriptor was closed by the reader


class NoLeakCommandTests(unittest.TestCase):
    """stdout, stderr and exit paths never carry a synthetic secret sentinel."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.secret = SENTINEL_FULL
        scalar = int.from_bytes(cls.secret, "big")
        cls.descriptor = synthetic_api.make_challenge("SYNTHETIC-sentinel", scalar, 2 ** 255, prim.N - 1)
        cls.challenge_path = os.path.join(cls.tmp.name, "challenge.json")
        with open(cls.challenge_path, "w") as handle:
            json.dump(cls.descriptor, handle)
        cls.forms = {SENTINEL_FULL: forbidden_forms(SENTINEL_FULL),
                     SENTINEL_IN_RANGE: forbidden_forms(SENTINEL_IN_RANGE)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def assert_clean(self, secret, *streams):
        blob = b"\n".join(streams)
        for form in self.forms[secret]:
            self.assertNotIn(form, blob)
        self.assertNotIn(b"Traceback", blob)
        self.assertNotIn(b"Error", blob)
        self.assertNotIn(b"Exception", blob)

    def synthetic(self, payload=None, chunks=None, path=None, stdout=None):
        return run_cli(SYNTHETIC_CLI, ["--challenge-file", path or self.challenge_path,
                                       "--candidate-fd", "{fd}"], payload=payload, chunks=chunks,
                       stdout=stdout)

    def test_sentinel_forms_detect_a_leak(self):
        secret = self.secret
        for leak in (secret.hex(), "0x" + secret.hex().upper(), repr(secret), wif(secret, True),
                     str(int.from_bytes(secret, "big")), "k=%x" % int.from_bytes(secret, "big"),
                     secret.hex()[20:40], repr(list(secret)), repr(bytearray(secret))):
            blob = ("prefix " + leak + " suffix").encode("latin-1", "backslashreplace")
            self.assertTrue(any(form in blob for form in self.forms[secret]), leak[:6])
        self.assertTrue(any(form in b"xx" + secret + b"yy" for form in self.forms[secret]))

    def test_matching_synthetic_candidate(self):
        code, out, err = self.synthetic(payload=self.secret)
        self.assertEqual((code, err), (0, b""))
        report = json.loads(out)
        self.assertEqual(set(report), REPORT_KEYS | {"synthetic_notice"})
        self.assertTrue(report["candidate_verified"])
        self.assertFalse(report["production_candidate_verified"])
        self.assertEqual(report["mode"], "SYNTHETIC")
        self.assert_clean(self.secret, out, err)
        chunked = self.synthetic(chunks=[self.secret[:16], self.secret[16:]])
        self.assertEqual(chunked, (code, out, err))
        candidate_path = os.path.join(self.tmp.name, "candidate.bin")
        with open(candidate_path, "wb") as handle:
            handle.write(self.secret)
        with open(candidate_path, "rb") as handle:
            proc = subprocess.run([sys.executable, "-I", "-B", SYNTHETIC_CLI, "--challenge-file",
                                   self.challenge_path, "--candidate-fd", str(handle.fileno())],
                                  pass_fds=(handle.fileno(),), capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (code, out, err))

    def test_non_matching_truncated_and_overlong_candidates(self):
        secret = self.secret
        payloads = (secret[::-1], secret[:31], secret[1:], secret + b"\n", secret * 2, secret[:1],
                    secret.hex().encode(), b"")
        for payload in payloads:
            code, out, err = self.synthetic(payload=payload)
            self.assertEqual((code, err), (1, b""))
            self.assertFalse(json.loads(out)["candidate_verified"])
            self.assert_clean(secret, out, err)
            code, out, err = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=payload)
            self.assertEqual((code, err), (1, b""))
            self.assertFalse(json.loads(out)["candidate_verified"])
            self.assert_clean(secret, out, err)

    def test_production_command_with_in_range_sentinel(self):
        secret = SENTINEL_IN_RANGE
        code, out, err = run_cli(PRODUCTION_CLI, ["--candidate-fd", "{fd}"], payload=secret)
        self.assertEqual((code, err), (1, b""))
        report = json.loads(out)
        self.assertEqual(report["checks"], {
            "descriptor_exact_32_bytes": True, "scalar_valid": True, "scalar_in_interval": True,
            "public_key_match": False, "p2pkh_address_match": False})
        self.assert_clean(secret, out, err)

    def test_secret_misplaced_on_command_line_is_not_echoed(self):
        secret = self.secret
        hexed = secret.hex()
        for script in (PRODUCTION_CLI, SYNTHETIC_CLI):
            for args in ([hexed], ["--candidate-fd", hexed], ["--candidate-fd=" + hexed],
                         ["--candidate", hexed], ["--" + hexed], ["--candidate-fd", "{fd}", hexed],
                         ["--challenge-file", hexed, "--candidate-fd", "{fd}"],
                         ["--candidate-fd", str(int.from_bytes(secret, "big"))],
                         [wif(secret, True)]):
                code, out, err = run_cli(script, args, payload=secret)
                self.assertEqual(code, 2, args[0][:16])
                self.assertEqual(set(json.loads(out)), ERROR_KEYS)
                self.assert_clean(secret, out, err)

    def test_challenge_file_errors(self):
        text = json.dumps(self.descriptor)
        variants = {"truncated.json": text[:len(text) // 2], "empty.json": "",
                    "array.json": "[" + text + "]", "huge.json": text + " " * 5000,
                    "binary.json": "ÿþ"}
        for name, content in variants.items():
            path = os.path.join(self.tmp.name, name)
            with open(path, "w", encoding="latin-1") as handle:
                handle.write(content)
            code, out, err = self.synthetic(payload=self.secret, path=path)
            self.assertEqual((code, json.loads(out)["error"]), (2, "challenge_descriptor_malformed"))
            self.assert_clean(self.secret, out, err)
        code, out, err = self.synthetic(payload=self.secret, path=os.path.join(self.tmp.name, "absent"))
        self.assertEqual((code, json.loads(out)["error"]), (2, "challenge_file_unreadable"))
        production = dict(self.descriptor, compressed_public_key=cc_core.PRODUCTION_PUBLIC_KEY_HEX,
                          p2pkh_address=cc_core.PRODUCTION_ADDRESS)
        path = os.path.join(self.tmp.name, "production.json")
        with open(path, "w") as handle:
            json.dump(production, handle)
        code, out, err = self.synthetic(payload=self.secret, path=path)
        self.assertEqual((code, json.loads(out)["error"]), (2, "production_target_refused"))
        self.assert_clean(self.secret, out, err)

    def test_injected_exceptions_carry_nothing_out(self):
        secret_expr = ("__import__('hashlib').sha256(b'candidate-check SYNTHETIC SECRET SENTINEL "
                       "in-range').digest()")
        template = (
            "import os, candidate_check, cc_core, cc_primitives\n"
            "digest = {secret}\n"
            "secret = ((2**139) + int.from_bytes(digest, 'big') % (2**139)).to_bytes(32, 'big')\n"
            "def boom(*args, **kwargs):\n"
            "    raise {exc}('leak ' + secret.hex() + ' ' + str(int.from_bytes(secret, 'big')))\n"
            "{patch} = boom\n"
            "r, w = os.pipe(); os.write(w, secret); os.close(w)\n"
            "candidate_check.main(['--candidate-fd', str(r)])\n"
            "print('main returned ' + secret.hex())\n")
        cases = (("cc_primitives.multiply_checked", "RuntimeError"),
                 ("cc_primitives.multiply_jacobian", "ValueError"),
                 ("cc_primitives.ripemd160", "ZeroDivisionError"),
                 ("cc_core.evaluate", "RuntimeError"),
                 ("cc_core.evaluate", "KeyboardInterrupt"),
                 ("cc_core.evaluate", "SystemExit"),
                 ("cc_core.evaluate", "MemoryError"),
                 ("cc_core.build_report", "RuntimeError"),
                 ("cc_core.source_hashes", "OSError"),
                 ("cc_core.canonical_json", "RuntimeError"),
                 ("os.read", "OSError"))
        self.assertEqual(be32(synthetic_scalar("in-range", LOW, HIGH)), SENTINEL_IN_RANGE)
        for patch, exc in cases:
            code, out, err = run_harness(template.format(secret=secret_expr, exc=exc, patch=patch))
            expected = 2 if patch == "os.read" else 3
            self.assertEqual(code, expected, (patch, exc))
            self.assertEqual(err, b"" if expected == 3 else (candidate_check.USAGE + "\n").encode())
            self.assert_clean(SENTINEL_IN_RANGE, out, err)
            self.assertNotIn(b"main returned", out)
            self.assertNotIn(b"leak", out + err)
            if out:
                report = json.loads(out)
                self.assertEqual(set(report), ERROR_KEYS)
                self.assertFalse(report["candidate_verified"])
            if patch != "cc_core.canonical_json":
                self.assertIn(json.loads(out)["error"],
                              ("internal_error", "self_test_failed", "candidate_descriptor_unreadable"))

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_unwritable_stdout_fails_closed(self):
        with open("/dev/full", "wb") as full:
            code, out, err = self.synthetic(payload=self.secret, stdout=full)
        self.assertEqual(code, 3)
        self.assert_clean(self.secret, out, err)


class PackagingTests(unittest.TestCase):
    ALLOWED_IMPORTS = {"hashlib", "hmac", "json", "os", "re", "sys", "resource",
                       "cc_core", "cc_primitives"}

    def test_sources_are_standard_library_only_and_independent(self):
        for name in cc_core.SOURCE_FILES:
            with open(os.path.join(COMPONENT_DIR, name), "r", encoding="ascii") as handle:
                text = handle.read()
            tree = ast.parse(text)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imported.add((node.module or "").split(".")[0])
            self.assertLessEqual(imported, self.ALLOWED_IMPORTS, name)
            for banned in ("os.environ", "environb", "getenv", "expanduser", "print(", "input(",
                           "breakpoint", "__debug__", "repr(", "format("):
                self.assertFalse(banned in text, (name, banned))
        with open(os.path.join(COMPONENT_DIR, "candidate_check.py"), "r", encoding="ascii") as handle:
            self.assertNotIn("synthetic_api", handle.read().replace("synthetic_api.py", ""))

    def test_sha256sums_matches_files(self):
        listing = os.path.join(COMPONENT_DIR, "SHA256SUMS")
        with open(listing, "r", encoding="ascii") as handle:
            lines = [line.rstrip("\n") for line in handle if line.strip()]
        named = {}
        for line in lines:
            digest, name = line.split("  ", 1)
            named[name] = digest
        for name in cc_core.SOURCE_FILES + ("README.md", "tests/test_candidate_check.py"):
            self.assertIn(name, named)
        for name, digest in named.items():
            with open(os.path.join(COMPONENT_DIR, name), "rb") as handle:
                self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), digest, name)

    def test_readme_pins_current_public_hashes(self):
        with open(os.path.join(COMPONENT_DIR, "README.md"), "r", encoding="utf-8") as handle:
            readme = handle.read()
        self.assertIn("`manifest_sha256` | `%s`" % PRODUCTION_MANIFEST_SHA256, readme)
        bundle = cc_core.source_bundle_sha256(cc_core.source_hashes())
        self.assertIn("`source_bundle_sha256` | `%s`" % bundle, readme)
        lines = "".join("%s  %s\n" % (digest, name)
                        for name, digest in sorted(cc_core.source_hashes().items()))
        self.assertEqual(hashlib.sha256(lines.encode()).hexdigest(), bundle)


if __name__ == "__main__":
    unittest.main()
