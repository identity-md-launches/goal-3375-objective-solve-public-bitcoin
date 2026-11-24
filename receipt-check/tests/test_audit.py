"""Deterministic tests. ALL DATA IS SYNTHETIC (fake txids, made-up values)."""
import copy, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit

A, B, C = "aa" * 32, "bb" * 32, "cc" * 32
PRIZE = audit.p2pkh_script_from_address(audit.PRIZE_ADDRESS)
DEST = audit.p2tr_script_from_address(audit.RECIPIENT)


def good():
    return {
        "tx": {"txid": C, "vin": [{"txid": A, "vout": 0}, {"txid": B, "vout": 1}],
               "vout": [{"value_sats": 299_000, "script_hex": DEST}]},
        "prevouts": [
            {"txid": A, "vout": 0, "value_sats": 100_000, "script_hex": PRIZE, "authenticated": True},
            {"txid": B, "vout": 1, "value_sats": 200_000, "script_hex": PRIZE, "authenticated": True}],
        "snapshot": {"address": audit.PRIZE_ADDRESS,
                     "outpoints": [{"txid": A, "vout": 0}, {"txid": B, "vout": 1}]}}


class T(unittest.TestCase):
    def fails(self, d, text):
        r = audit.audit(d)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertTrue(any(text in e for e in r["errors"]), r["errors"])
        return r

    def test_pass(self):
        r = audit.audit(good())
        self.assertEqual((r["verdict"], r["input_sum_sats"], r["paid_sats"], r["fee_sats"]),
                         ("PASS", 300_000, 299_000, 1_000))
        self.assertIn("NOT ESTABLISHED", r["confirmation"])

    def test_scripts(self):
        self.assertTrue(PRIZE.startswith("76a914") and len(PRIZE) == 50)
        self.assertTrue(DEST.startswith("5120") and len(DEST) == 68)

    def test_missing_input(self):
        d = good(); d["tx"]["vin"].pop(); self.fails(d, "missing from inputs")

    def test_extra_input(self):
        d = good(); d["tx"]["vin"].append({"txid": C, "vout": 0})
        d["prevouts"].append({"txid": C, "vout": 0, "value_sats": 5, "script_hex": PRIZE, "authenticated": True})
        self.fails(d, "extra input")

    def test_duplicate_input(self):
        d = good(); d["tx"]["vin"].append({"txid": A, "vout": 0}); self.fails(d, "duplicate input")

    def test_missing_prevout(self):
        d = good(); d["prevouts"].pop(); r = self.fails(d, "missing prevout"); self.assertIsNone(r["fee_sats"])

    def test_missing_value(self):
        d = good(); del d["prevouts"][0]["value_sats"]; self.fails(d, "invalid prevout value")

    def test_bad_value_types(self):
        for v in (True, "5", -1, 0, 1.5):
            d = good(); d["prevouts"][0]["value_sats"] = v; self.fails(d, "invalid prevout value")

    def test_unauthenticated(self):
        d = good(); d["prevouts"][1]["authenticated"] = False; self.fails(d, "not marked authenticated")

    def test_inconsistent_script(self):
        d = good(); d["prevouts"][0]["script_hex"] = DEST; self.fails(d, "inconsistent")

    def test_extra_output(self):
        d = good(); d["tx"]["vout"].append({"value_sats": 100, "script_hex": PRIZE}); self.fails(d, "exactly one output")

    def test_two_recipient_outputs(self):
        d = good(); d["tx"]["vout"].append(copy.deepcopy(d["tx"]["vout"][0])); self.fails(d, "exactly one output")

    def test_wrong_recipient(self):
        d = good(); d["tx"]["vout"][0]["script_hex"] = "5120" + "11" * 32; self.fails(d, "paying recipient")

    def test_nonpositive_payment(self):
        for v in (0, -5):
            d = good(); d["tx"]["vout"][0]["value_sats"] = v; self.fails(d, "nonpositive")

    def test_negative_fee(self):
        d = good(); d["tx"]["vout"][0]["value_sats"] = 300_001; self.fails(d, "negative fee")

    def test_wrong_snapshot_address(self):
        d = good(); d["snapshot"]["address"] = audit.RECIPIENT; self.fails(d, "snapshot address")

    def test_bad_checksum(self):
        with self.assertRaises(ValueError):
            audit.p2tr_script_from_address(audit.RECIPIENT[:-1] + "q")
        with self.assertRaises(ValueError):
            audit.p2pkh_script_from_address(audit.PRIZE_ADDRESS[:-1] + "p")

    def test_garbage(self):
        self.assertEqual(audit.audit([])["verdict"], "FAIL")
        self.assertEqual(audit.audit({"tx": {}, "prevouts": [], "snapshot": {}})["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
