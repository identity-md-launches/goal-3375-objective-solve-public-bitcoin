"""Deterministic tests; no bitcoind needed. All data SYNTHETIC."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import regtest_payment as rp

SPK = "5120" + "11" * 32

def tx(txid="aa" * 32, vout=0, spk_type="witness_v1_taproot", spk=SPK, value="0.49999000", nout=1):
    return {"vin": [{"txid": txid, "vout": vout}],
            "vout": [{"value": value, "scriptPubKey": {"type": spk_type, "hex": spk}}] * nout}

class T(unittest.TestCase):
    def test_amounts(self):
        self.assertEqual(rp.btc_to_sats("0.5"), 50_000_000)
        self.assertEqual(rp.sats_to_btc(49_999_000), "0.49999000")
        self.assertRaises(ValueError, rp.btc_to_sats, "0.000000001")
    def test_regtest_guard(self):
        rp.assert_regtest_chain({"chain": "regtest"})
        for c in ("main", "test", "signet", None):
            self.assertRaises(RuntimeError, rp.assert_regtest_chain, {"chain": c})
    def test_check_ok(self):
        self.assertEqual(rp.check_spend(tx(), "aa"*32, 0, "pubkeyhash", SPK, 50_000_000, 49_999_000), [])
    def test_check_failures(self):
        self.assertTrue(rp.check_spend(tx(vout=1), "aa"*32, 0, "pubkeyhash", SPK, 50_000_000, 49_999_000))
        self.assertTrue(rp.check_spend(tx(spk_type="witness_v0_keyhash"), "aa"*32, 0, "pubkeyhash", SPK, 50_000_000, 49_999_000))
        self.assertTrue(rp.check_spend(tx(nout=2), "aa"*32, 0, "pubkeyhash", SPK, 50_000_000, 49_999_000))
        self.assertTrue(rp.check_spend(tx(), "aa"*32, 0, "witness_v0_keyhash", SPK, 50_000_000, 49_999_000))
        self.assertTrue(rp.check_spend(tx(value="0.5"), "aa"*32, 0, "pubkeyhash", SPK, 50_000_000, 49_999_000))
    def test_receipt(self):
        r = {"synthetic": True, "network": "regtest", "txid": "t", "blockhash": "b", "height": 103,
             "depth": 1, "input_sats": 10, "paid_sats": 9, "fee_sats": 1}
        self.assertEqual(rp.validate_receipt(r), [])
        self.assertTrue(rp.validate_receipt(dict(r, network="main")))
        self.assertTrue(rp.validate_receipt(dict(r, fee_sats=2)))
        self.assertTrue(rp.validate_receipt(dict(r, note="wif here")))

if __name__ == "__main__":
    unittest.main()
