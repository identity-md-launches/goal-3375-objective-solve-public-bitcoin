import copy
import hashlib
import json
import math
from pathlib import Path
import random
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
from kangaroo.engine import Engine, distinguished, jump_table, validate_record, verified_collision
from kangaroo.manifest import (ADDRESS, LOWER, PRODUCTION, RECIPIENT, UPPER, decimal, digest,
                              p2pkh, synthetic_manifest, validate_manifest, validate_recipient)
from kangaroo.secp256k1 import G, N, P, Operations, add, decode, encode, multiply, negate, reference_multiply


def challenge(width=4096, position="seeded", seed="trial-v1", lower=LOWER):
    return synthetic_manifest(lower, width, position, seed)


class CurveTests(unittest.TestCase):
    def test_sec2_generator_and_known_double(self):
        self.assertEqual(encode(G).hex(), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        self.assertEqual(encode(multiply(2)).hex(), "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        self.assertEqual(p2pkh(encode(G)), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")

    def test_group_laws_and_independent_arithmetic(self):
        generator = random.Random(140)
        for value in [0, 1, 2, 3, 1 << 139, N - 1] + [generator.randrange(1, N) for _ in range(20)]:
            with self.subTest(index=value.bit_length()):
                self.assertEqual(multiply(value), reference_multiply(value))
                self.assertIsNone(add(multiply(value), negate(multiply(value))))
        self.assertIsNone(multiply(N))
        self.assertEqual(multiply(-1), negate(G))
        self.assertEqual(multiply(N + 7), multiply(7))

    def test_invalid_and_noncanonical_points(self):
        for value in (b"", b"\0" * 33, b"\x04" + bytes(32), b"\x02" + P.to_bytes(32, "big"),
                      b"\x02" + bytes(32)):
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                decode(value)
        for scalar in (1, 2, 139, N - 1):
            self.assertEqual(decode(encode(multiply(scalar))), multiply(scalar))

    def test_address_manifest_and_recipient(self):
        point, lower, upper = validate_manifest(PRODUCTION)
        self.assertEqual(p2pkh(encode(point)), ADDRESS)
        self.assertEqual((lower, upper), (1 << 139, (1 << 140) - 1))
        self.assertEqual(len(validate_recipient(RECIPIENT)), 32)
        self.assertEqual(digest(PRODUCTION), "81b6d1ba0c3cb55713d7056670f67eef4573a9f84f55320c207a5f847f556050")
        supplied = json.loads((Path(__file__).absolute().parents[1] / "production-manifest.json").read_bytes())
        self.assertEqual(supplied, PRODUCTION)
        for key, value in (("lower", str(lower + 1)), ("upper", str(upper - 1)),
                           ("address", "unrelated"), ("recipient", "unrelated"), ("mode", "synthetic")):
            altered = dict(PRODUCTION, **{key: value})
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_manifest(altered)

    def test_bad_recipient_checksum_network_padding_and_case(self):
        for address in (RECIPIENT[:-1] + "q", RECIPIENT.upper(), "tb" + RECIPIENT[2:],
                        RECIPIENT[:-3], "bc1qqqqqqqq", "bc1" + "!" * 60):
            with self.subTest(length=len(address)), self.assertRaises(ValueError):
                validate_recipient(address)

    def test_exact_decimal(self):
        self.assertEqual(decimal(str(-(1 << 300))), -(1 << 300))
        for value in (1, 1.0, True, "1.0", "1e40", "+1", "01", "-0", " 1", "1\n", "9" * 161):
            with self.assertRaises(ValueError):
                decimal(value)


class KangarooTests(unittest.TestCase):
    def solve(self, manifest, expected, **kwargs):
        engine = Engine(manifest, **kwargs)
        result = engine.run(100000, 5)
        self.assertEqual(result["reason"], "solved")
        self.assertEqual(engine.candidate_bytes(), expected.to_bytes(32, "big"))
        return engine

    def test_known_answers_endpoints_and_139_bit_lower_bound(self):
        for lower in (1, LOWER):
            for width in (1, 2, 3, 17, 257, 4096, 65536):
                for position in ("lower", "upper", "middle", "seeded"):
                    with self.subTest(lowerBits=lower.bit_length(), width=width, position=position):
                        manifest, known = challenge(width, position, lower=lower)
                        self.solve(manifest, known, max_records=50000)

    def test_multiple_seeds_generations_and_sparse_dps(self):
        for seed in ("trial-a", "trial-b", "trial-c"):
            for generation in (0, 1, 7):
                with self.subTest(seed=seed, generation=generation):
                    manifest, known = challenge(4096, seed=seed)
                    self.solve(manifest, known, seed=seed, worker_id="test-worker", generation=generation, dp_bits=3)

    def test_deterministic_jumps_and_worker_separation(self):
        manifest, _ = challenge()
        a = Engine(manifest, worker_id="worker-a")
        b = Engine(manifest, worker_id="worker-b")
        c = Engine(manifest, worker_id="worker-a", generation=1)
        self.assertEqual(a.jump_hash, b.jump_hash)
        self.assertEqual(b.jump_hash, c.jump_hash)
        self.assertNotEqual(a.walks, b.walks)
        self.assertNotEqual(a.walks, c.walks)
        lengths, _, first = jump_table(4096, "fixed-v1")
        self.assertEqual(first, jump_table(4096, "fixed-v1")[2])
        self.assertEqual(first, "0798fad8162a96807bf8f58aaaf4df0728c03385ae431fc37b68757894c906dd")
        self.assertEqual(lengths[:4], [1, 60, 43, 24])
        self.assertNotEqual(first, jump_table(4096, "other-v1")[2])
        self.assertEqual(math.gcd(*lengths), 1)
        self.assertTrue(all(type(v) is int and v > 0 for v in lengths))

    def test_order_boundary_and_infinity_walk(self):
        for position in ("lower", "upper", "middle"):
            manifest, known = challenge(257, position, lower=N - 257)
            self.solve(manifest, known)
        manifest, _ = challenge(2, "lower", lower=N - 2)
        engine = Engine(manifest)
        # A legitimate tame walk can pass through infinity when its distance is N.
        engine.walks["tame"] = {"point": None, "distance": N}
        state = engine.snapshot()
        restored = Engine.restore(state, manifest)
        engine.step()
        restored.step()
        self.assertEqual(engine.snapshot(), restored.snapshot())
        self.assertNotIn(None, [record["point"] for record in engine.export_records()])

    def test_budget_memory_failure_and_no_false_acceptance(self):
        manifest, _ = challenge()
        engine = Engine(manifest)
        self.assertEqual(engine.run(0, 1)["reason"], "step_limit")
        self.assertEqual(engine.run(100, 0)["reason"], "time_limit")
        self.assertEqual(engine.steps, 0)
        self.assertIsNone(engine.candidate_bytes())
        tiny = Engine(manifest, max_records=2)
        self.assertEqual(tiny.run(100, 1)["reason"], "memory_limit")
        self.assertLessEqual(len(tiny.table), 2)
        outside, _ = challenge(17, lower=1000)
        outside["publicKey"] = encode(multiply(999)).hex()  # Generated out-of-interval failure fixture.
        engine = Engine(outside)
        result = engine.run(500, 1)
        self.assertEqual(result["reason"], "step_limit")
        self.assertIsNone(engine.candidate_bytes())
        self.assertGreater(engine.counts["rejectedCollisions"], 0)

    def test_production_api_is_closed_without_authorization(self):
        with self.assertRaises(ValueError):
            Engine(PRODUCTION)

    def test_synthetic_cannot_use_real_target_or_large_width(self):
        manifest, _ = challenge()
        manifest["publicKey"] = PRODUCTION["publicKey"]
        with self.assertRaises(ValueError):
            Engine(manifest)
        with self.assertRaises(ValueError):
            challenge((1 << 24) + 1)

    def test_interrupt_resume_equivalence(self):
        manifest, _ = challenge(65536, "lower")
        uninterrupted = Engine(manifest, dp_bits=2)
        uninterrupted.run(100000, 5)
        for cut in (0, 1, 2, 17, 99, 333):
            with self.subTest(cut=cut):
                partial = Engine(manifest, dp_bits=2)
                partial.run(100000, 5, stopped=lambda: partial.steps >= cut)
                resumed = Engine.restore(json.loads(json.dumps(partial.snapshot())), manifest)
                resumed.run(100000, 5)
                self.assertEqual(uninterrupted.snapshot(), resumed.snapshot())
                self.assertEqual(uninterrupted.candidate_bytes(), resumed.candidate_bytes())

    def test_resume_solved_and_memory_limit(self):
        manifest, known = challenge(257, "lower")
        solved = self.solve(manifest, known)
        restored = Engine.restore(solved.snapshot(), manifest)
        self.assertEqual(restored.snapshot(), solved.snapshot())
        self.assertEqual(restored.candidate_bytes(), known.to_bytes(32, "big"))
        limited = Engine(manifest, max_records=2)
        limited.run(1000, 1)
        self.assertEqual(Engine.restore(limited.snapshot(), manifest).status, "memory_limit")

    def test_resume_rejects_corruption(self):
        manifest, _ = challenge()
        engine = Engine(manifest)
        engine.run(10, 1)
        state = engine.snapshot()
        mutations = [lambda s: s.update(jumpHash="0" * 64),
                     lambda s: s.update(nextHerd="wild"),
                     lambda s: s["walks"]["wild"].update(distance="123"),
                     lambda s: s["table"][0].update(distance="123"),
                     lambda s: s["table"].append(s["table"][0]),
                     lambda s: s.update(solution=[]),
                     lambda s: s["walkOperations"].update(additions=-1)]
        for mutate in mutations:
            bad = copy.deepcopy(state)
            mutate(bad)
            with self.assertRaises((ValueError, TypeError)):
                Engine.restore(bad, manifest)

    def test_signed_full_width_records_and_full_point_comparison(self):
        manifest, known = challenge(20, "middle", lower=1)
        engine = Engine(manifest)
        tame = engine.record("tame")
        wild = engine.record("wild")
        tame.update(point=encode(multiply(10)).hex(), distance="10")
        wild.update(point=encode(multiply(-10)).hex(), distance=str(-10 - known))
        self.assertEqual(tame["point"][2:], wild["point"][2:])
        self.assertNotEqual(tame["point"][:2], wild["point"][:2])
        self.assertIsNone(verified_collision(tame, wild, manifest, engine.jump_hash))
        wild.update(point=tame["point"], distance=str(10 - known))
        self.assertEqual(verified_collision(tame, wild, manifest, engine.jump_hash), known)
        tame["distance"] = str(10 + 3 * N)
        wild["distance"] = str(10 - known - 7 * N)
        self.assertEqual(verified_collision(tame, wild, manifest, engine.jump_hash), known)
        self.assertIsNone(verified_collision(tame, tame, manifest, engine.jump_hash))
        for change in ({"jumpHash": "f" * 64}, {"manifestHash": "f" * 64}, {"distance": "1.0"},
                       {"generation": True}, {"point": tame["point"].upper()}):
            with self.assertRaises(ValueError):
                validate_record(dict(tame, **change), manifest, engine.jump_hash)

    def test_dp_export_contract(self):
        manifest, _ = challenge()
        engine = Engine(manifest, worker_id="export-worker", generation=4)
        engine.run(50, 1)
        for record in engine.export_records():
            self.assertEqual(record["schema"], "walk-dp@1")
            self.assertEqual(record["workerId"], "export-worker")
            self.assertEqual(record["generation"], 4)
            point, _ = validate_record(record, manifest, engine.jump_hash)
            self.assertTrue(distinguished(point, 0))
            self.assertIsInstance(record["distance"], str)


if __name__ == "__main__":
    unittest.main()
