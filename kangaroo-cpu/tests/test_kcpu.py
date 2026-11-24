"""Standalone tests: python3 -I -m unittest discover -s kangaroo-cpu/tests -v
Set KCPU_BINARY=/path/to/build/kangaroo to also run the bounded synthetic integration tests."""
import hashlib, json, os, sys, unittest
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import kcpu, gen_fixtures

FX = json.load(open(os.path.join(HERE, "fixtures", "fixtures.json")))
P140 = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"


class Pure(unittest.TestCase):
    def test_generator_point(self):
        self.assertEqual(kcpu.compress(kcpu.mul(1)), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        self.assertIsNone(kcpu.mul(kcpu.N))

    def test_fixtures_deterministic(self):
        self.assertEqual(gen_fixtures.build(), FX)

    def test_fixtures_self_consistent(self):
        for c in FX["cases"]:
            self.assertTrue(c["label"].startswith("SYNTHETIC-"))
            self.assertTrue(kcpu.verify_answer(c, c["synthetic_key"]), c["label"])
            s, e, k = (int(c[x], 16) for x in ("start", "end", "synthetic_key"))
            self.assertEqual(e - s, 2**c["width_bits"] - 1)
            self.assertEqual(k, {"start": s, "end": e, "start1": s + 1, "end1": e - 1}.get(c["where"], k))
            kcpu.check_target(s, e, c["pubkey"])

    def test_verify_rejects_wrong(self):
        c = FX["cases"][0]; k = int(c["synthetic_key"], 16)
        self.assertFalse(kcpu.verify_answer(c, "%x" % (k + 1)))
        self.assertFalse(kcpu.verify_answer(c, "%x" % (int(c["end"], 16) + 1)))

    def test_refuse_140(self):
        for pk in (P140, FX["cases"][0]["pubkey"]):
            with self.assertRaises(kcpu.Refused):
                kcpu.check_target(2**139, 2**140 - 1, pk)
        with self.assertRaises(kcpu.Refused):
            kcpu.check_target(2**10, 2**10 + 5, P140)

    def test_width_limit(self):
        pk = FX["cases"][0]["pubkey"]
        kcpu.check_target(1, 1 + 2**125 - 1, pk)
        with self.assertRaises(kcpu.Refused):
            kcpu.check_target(1, 1 + 2**125, pk)

    def test_run_job_refuses_before_exec(self):
        bad = dict(FX["cases"][0], pubkey=P140)
        with self.assertRaises(kcpu.Refused):
            kcpu.run_job("/nonexistent", bad)
        bad = dict(FX["cases"][0], label="REAL-x")
        with self.assertRaises(kcpu.Refused):
            kcpu.run_job("/nonexistent", bad)

    def test_provenance_hashes(self):
        p = json.load(open(os.path.join(HERE, "PROVENANCE.json")))
        for rel, h in p["upstream_files_sha256"].items():
            self.assertEqual(hashlib.sha256(open(os.path.join(HERE, "upstream", rel), "rb").read()).hexdigest(), h, rel)
        for rel, h in p["patches_sha256"].items():
            self.assertEqual(hashlib.sha256(open(os.path.join(HERE, "patches", rel), "rb").read()).hexdigest(), h, rel)
        vb = p["vendored_binary"]
        self.assertEqual(hashlib.sha256(open(os.path.join(HERE, vb["path"]), "rb").read()).hexdigest(), vb["sha256"])
        self.assertIn("GNU GENERAL PUBLIC LICENSE", open(os.path.join(HERE, "upstream", "LICENSE.txt")).read())


@unittest.skipUnless(os.environ.get("KCPU_BINARY"), "KCPU_BINARY not set")
class Integration(unittest.TestCase):
    def run_case(self, label, **kw):
        c = next(x for x in FX["cases"] if x["label"] == label)
        return kcpu.run_job(os.environ["KCPU_BINARY"], c, **kw)

    def test_solves_and_verifies(self):
        for lab in ("SYNTHETIC-w32-random", "SYNTHETIC-w36-end-endpoint",
                    "SYNTHETIC-w20-narrow-high-offset-near-n", "SYNTHETIC-w24-narrow-high-offset-end-endpoint"):
            r = self.run_case(lab, max_step=8.0, timeout=120)
            self.assertTrue(r["verified"], r); self.assertGreater(r["session_group_ops"], 0)

    def test_start_endpoint_resolved(self):
        # Formerly failed upstream (K - start.G = point at infinity); patch 0003 resolves it with 0 walk ops.
        for lab in ("SYNTHETIC-w28-high-offset-2^255", "SYNTHETIC-w36-start-endpoint", "SYNTHETIC-w0-singleton"):
            r = self.run_case(lab, max_step=2.0, timeout=120)
            self.assertTrue(r["verified"], r); self.assertTrue(r["endpoint_resolved"], r)
            self.assertEqual(r["session_group_ops"], 0)
