#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic tests for the toy interval discrete-log benchmark.

Run with either:
    python3 -m unittest -v test_toy_dlog
    python3 test_toy_dlog.py

Standard library only (unittest). No network, no RNG, no wall-clock dependence.
"""

import unittest

import toy_dlog as td


class TestGroup(unittest.TestCase):
    def test_group_constants_valid(self):
        # Should not raise; re-verifies the pinned group.
        td.verify_group()

    def test_order_fits_16_bits(self):
        self.assertLess(td.N, 1 << 16)
        self.assertEqual(td.N.bit_length(), 16)

    def test_generator_has_full_order(self):
        # G**N == 1 and G**d != 1 for the only proper divisor chain (N prime).
        self.assertEqual(pow(td.G, td.N, td.P), 1)
        self.assertNotEqual(td.G % td.P, 1)

    def test_gmul_counts(self):
        td.GroupOps.reset()
        _ = td.gmul(5, 7)
        self.assertEqual(td.GroupOps.mul, 1)

    def test_gpow_matches_builtin(self):
        for e in (0, 1, 2, 100, td.N - 1):
            self.assertEqual(td.gpow(td.G, e), pow(td.G, e, td.P))


class TestFixtures(unittest.TestCase):
    def test_fixture_count_and_kinds(self):
        kinds = {f.kind for f in td.FIXTURES}
        self.assertIn("endpoint-low", kinds)
        self.assertIn("endpoint-high", kinds)
        self.assertIn("interior", kinds)
        self.assertGreaterEqual(len(td.FIXTURES), 5)

    def test_endpoints_present(self):
        lo = td.get_fixture("endpoint-low")
        hi = td.get_fixture("endpoint-high")
        self.assertEqual(lo.x, lo.a)
        self.assertEqual(hi.x, hi.b)

    def test_all_x_in_interval_and_consistent_h(self):
        for f in td.FIXTURES:
            self.assertTrue(f.a <= f.x <= f.b, f.name)
            self.assertEqual(f.h, pow(td.G, f.x, td.P), f.name)

    def test_interior_strictly_interior(self):
        for f in td.FIXTURES:
            if f.kind == "interior":
                self.assertTrue(f.a < f.x < f.b, f.name)

    def test_reproduce_is_deterministic(self):
        # Reproducing by name must yield the identical secret -- the resume path.
        for f in td.FIXTURES:
            again = td.reproduce_fixture(f.name)
            self.assertEqual(again.x, f.x, f.name)
            self.assertEqual(again.h, f.h, f.name)

    def test_derivation_is_pure_function_of_name(self):
        x1 = td._derive_interior_x("interior-alpha", td.FIX_A, td.FIX_B)
        x2 = td._derive_interior_x("interior-alpha", td.FIX_A, td.FIX_B)
        self.assertEqual(x1, x2)


class TestMethods(unittest.TestCase):
    def test_bsgs_solves_every_fixture(self):
        for f in td.FIXTURES:
            r = td.solve("bsgs", f)
            self.assertTrue(r.success, f.name)
            self.assertEqual(r.recovered, f.x, f.name)

    def test_kangaroo_solves_every_fixture(self):
        for f in td.FIXTURES:
            r = td.solve("kangaroo", f)
            self.assertTrue(r.success, f.name)
            self.assertEqual(r.recovered, f.x, f.name)

    def test_both_methods_same_instances(self):
        # The two methods must be fed identical (h, a, b).
        for f in td.FIXTURES:
            rb = td.solve("bsgs", f)
            rk = td.solve("kangaroo", f)
            self.assertEqual(rb.expected, rk.expected, f.name)
            self.assertEqual(rb.expected, f.x, f.name)

    def test_measurements_recorded(self):
        for f in td.FIXTURES:
            for m in td.METHODS:
                r = td.solve(m, f)
                self.assertGreater(r.group_ops, 0, (m, f.name))
                self.assertGreater(r.termination_limit, 0, (m, f.name))
                self.assertGreaterEqual(r.elapsed_s, 0.0, (m, f.name))
                self.assertGreater(r.peak_mem_bytes, 0, (m, f.name))

    def test_op_counts_are_deterministic(self):
        # Re-running a trial yields identical op count (determinism of search).
        f = td.get_fixture("interior-alpha")
        r1 = td.solve("kangaroo", f)
        r2 = td.solve("kangaroo", f)
        self.assertEqual(r1.group_ops, r2.group_ops)
        self.assertEqual(r1.recovered, r2.recovered)

    def test_search_stays_within_termination_limit(self):
        # Reported group ops must not exceed the declared termination limit by
        # more than the fixed setup transform (BSGS counts one extra transform).
        for f in td.FIXTURES:
            for m in td.METHODS:
                r = td.solve(m, f)
                self.assertLessEqual(r.group_ops, r.termination_limit + 2,
                                     (m, f.name))

    def test_wrong_target_is_not_falsely_solved(self):
        # Feed H for x outside the claimed interval -> methods must not claim x.
        f = td.get_fixture("interior-alpha")
        bogus_x = f.b + 500  # outside [a, b]
        bogus_h = pow(td.G, bogus_x, td.P)
        bogus = td.Fixture(name="bogus", a=f.a, b=f.b, kind="interior",
                           x=bogus_x, h=bogus_h)
        for m in td.METHODS:
            r = td.solve(m, bogus)
            # recovered, if any, must satisfy the interval and the equation;
            # it cannot equal the out-of-range bogus_x.
            if r.recovered is not None:
                self.assertTrue(f.a <= r.recovered <= f.b)
                self.assertNotEqual(r.recovered, bogus_x)


if __name__ == "__main__":
    unittest.main(verbosity=2)
