#!/usr/bin/env python3
"""Offline integration checks. All generated scalars are synthetic; never print them."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'private-search'), str(ROOT / 'candidate-check')]
from kangaroo.engine import Engine, density_plan, distinguished, validate_record, verified_collision
from kangaroo.manifest import LOWER, synthetic_manifest
from kangaroo.secp256k1 import N, encode, multiply, negate
import synthetic_api

spec = importlib.util.spec_from_file_location('independent_oracle', ROOT / 'secp-oracle/oracle.py')
oracle_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle_module)

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vendor = ROOT / 'secp-oracle/vendor/secp256k1'
        for line in (ROOT / 'secp-oracle/vendor.sha256').read_text().splitlines():
            expected, name = line.split('  ', 1)
            assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == expected
        raw = (ROOT / 'private-search/oracle-fixtures.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == 'b0975d21d420910aeb2b27ce0a01761e4b1213a91d1d538a5d09e663b038545b'
        fixtures = json.loads(raw)
        assert fixtures['sourceCommit'] == oracle_module.REVISION
        class FixtureOracle:
            def point(self, scalar):
                return bytes.fromhex(fixtures['points'][str(scalar)]), None
        cls.oracle = FixtureOracle()
        cls.native = None
        if os.environ.get('PRIVATE_SEARCH_ORACLE_SO'):
            cls.native = oracle_module.Oracle(Path(os.environ['PRIVATE_SEARCH_ORACLE_SO']))
            for scalar, expected in fixtures['points'].items():
                assert cls.native.point(int(scalar))[0].hex() == expected
            cls.oracle = cls.native
        print('oracle backend: ' + ('native libsecp256k1' if cls.native else 'pinned native-generated fixtures; live backend not run'), flush=True)

    @classmethod
    def tearDownClass(cls):
        if cls.native:
            cls.native.lib.oracle_close(cls.native.ctx)

    def test_oracle_and_candidate_boundary(self):
        for width in (1, 2, 3, 17, 65):
            for position in ('lower', 'upper', 'middle'):
                manifest, known = synthetic_manifest(LOWER + 1000, width, position, 'integration-v1')
                self.assertEqual(bytes.fromhex(manifest['publicKey']), self.oracle.point(known)[0])
                engine = Engine(manifest, seed='integration-v1', max_records=1000)
                self.assertEqual(engine.run(10000, 5)['reason'], 'solved')
                candidate = engine.candidate_bytes()
                descriptor = synthetic_api.make_challenge('SYNTHETIC-integration', known, LOWER + 1000, LOWER + 999 + width)
                self.assertTrue(synthetic_api.check_synthetic_candidate(candidate, descriptor)['candidate_verified'])
                for data, expected in ((candidate, True), (candidate[:-1], False), (candidate + b'\x00', False)):
                    rd, wr = os.pipe()
                    os.write(wr, data)
                    os.close(wr)
                    report = synthetic_api.check_synthetic_candidate_fd(rd, descriptor)
                    self.assertEqual(report['candidate_verified'], expected)
                    self.assertFalse(report['production_candidate_verified'])

    def test_distance_equations_parity_and_namespace(self):
        manifest, known = synthetic_manifest(LOWER, 17, 'middle', 'integration-v1')
        engine = Engine(manifest, seed='integration-v1')
        for distance in (1 << 63, -(1 << 64), 1 << 127, -(1 << 128), 1 << 255, -(1 << 256)):
            for herd in ('tame', 'wild'):
                scalar = (distance + (known if herd == 'wild' else 0)) % N
                record = engine.record(herd)
                record.update(point=self.oracle.point(scalar)[0].hex(), distance=str(distance))
                point, actual = validate_record(record, manifest, engine.jump_hash)
                self.assertEqual(actual, distance)
                self.assertEqual(encode(point), self.oracle.point(scalar)[0])
        tame, wild = engine.record('tame'), engine.record('wild')
        point = self.oracle.point(7)[0]
        tame.update(point=point.hex(), distance=str(7 + N))
        wild.update(point=point.hex(), distance=str(7 - known - N))
        self.assertEqual(verified_collision(tame, wild, manifest, engine.jump_hash), known)
        wild['point'] = encode(negate(multiply(7))).hex()
        wild['distance'] = str(-7 - known)
        self.assertIsNone(verified_collision(tame, wild, manifest, engine.jump_hash))
        with self.assertRaises(ValueError):
            validate_record(tame, manifest, '0'*64)

    def test_saturation_resume_and_interrupt(self):
        manifest, _ = synthetic_manifest(LOWER, 65536, 'lower', 'integration-v1')
        full = Engine(manifest, seed='integration-v1', max_records=3000)
        limited = Engine(manifest, seed='integration-v1', max_records=2)
        self.assertEqual(limited.run(1000, 5)['reason'], 'memory_limit')
        before = limited.steps
        state = json.loads(json.dumps(limited.snapshot()))
        limited = Engine.restore(state, manifest)
        self.assertEqual(limited.run(10, 5)['reason'], 'memory_limit')
        self.assertEqual(limited.steps, before)
        with self.assertRaises(ValueError):
            limited.increase_capacity(2)
        with self.assertRaises(ValueError):
            limited.increase_capacity(100001)
        self.assertEqual(limited.snapshot(), state)
        limited.increase_capacity(3000)
        full.run(before, 5)
        self.assertEqual(limited.snapshot(), full.snapshot())
        limited.run(10000, 5, stopped=lambda: limited.steps >= before + 17)
        limited = Engine.restore(json.loads(json.dumps(limited.snapshot())), manifest)
        full.run(17, 5)
        self.assertEqual(limited.snapshot(), full.snapshot())
        limited.run(10000, 5)
        full.run(10000, 5)
        self.assertEqual(limited.snapshot(), full.snapshot())
        self.assertEqual(limited.status, 'solved')

    def test_cli_resume_after_capacity_increase(self):
        with tempfile.TemporaryDirectory(prefix='cli-capacity-', dir=ROOT / 'test/scratch') as directory:
            state_dir = str(Path(directory) / 'state')
            base = [sys.executable, '-I', '-B', str(ROOT / 'private-search/run.py'),
                    '--private-dir', state_dir, '--seed', 'integration-v1', '--synthetic-width', '65536',
                    '--synthetic-position', 'lower', '--dp-bits', '0', '--max-seconds', '5', '--max-steps', '5000']
            first = subprocess.run(base + ['--max-records', '2'], capture_output=True, check=False)
            self.assertEqual(first.returncode, 3)
            self.assertEqual(json.loads(first.stdout)['status'], 'memory_limit')
            second = subprocess.run(base + ['--max-records', '3000', '--resume'], capture_output=True, check=False)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(json.loads(second.stdout)['status'], 'solved')

    def test_full_width_plan_and_serialization(self):
        plan = density_plan(1 << 139, 10000)
        self.assertGreater(plan['dpBits'], 32)
        self.assertLessEqual(int(plan['expectedRecordsNumerator']), plan['targetRecords'] * int(plan['expectedRecordsDenominator']))
        manifest, known = synthetic_manifest(LOWER, 17, 'middle', 'integration-v1')
        # Mock only the manifest validator to exercise 139-bit initialization with
        # a generated synthetic public point. No production target or walks run.
        full_width = dict(manifest, upper=str(LOWER + (1 << 139) - 1))
        with patch('kangaroo.engine.validate_manifest', return_value=(multiply(known), LOWER, LOWER + (1 << 139) - 1)):
            engine = Engine(full_width, seed='integration-v1', dp_bits=plan['dpBits'])
            state = json.loads(json.dumps(engine.snapshot()))
            restored = Engine.restore(state, full_width)
            self.assertEqual(restored.snapshot(), state)
            self.assertEqual(engine.steps, 0)
        with self.assertRaises(ValueError):
            Engine(manifest, dp_bits=257)


def main():
    (ROOT / 'test/scratch').mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    for suite in ('private-search/tests', 'candidate-check/tests'):
        print('Running ' + suite, flush=True)
        subprocess.run([sys.executable, '-I', '-B', '-m', 'unittest', 'discover', '-s', str(ROOT / suite), '-q'], check=True, cwd=ROOT)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Integration))
    print('synthetic integration wall_seconds=%.3f process_peak_rss_kib=%d' %
          (time.monotonic() - start, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), flush=True)
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(main())
