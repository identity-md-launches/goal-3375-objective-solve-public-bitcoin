"""Offline tests using generated, labeled transactions only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import audit

FIXTURE = HERE / "synthetic_pass.json"
REGTEST_FIXTURE = HERE / "regtest_synthetic_pass.json"
LEGACY = HERE.parents[1] / "regtest-payment" / "receipt.json"
SOURCE = "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac"
DEST = "512046bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f"


def good():
    return json.loads(FIXTURE.read_text())


def raw_id(raw):
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()


def spend(doc, keys=None, outputs=((299_000, DEST),)):
    if keys is None:
        keys = [(out["txid"], out["vout"]) for out in doc["snapshot"]["outpoints"]]
    raw = "02000000" + bytes([len(keys)]).hex()
    for txid, index in keys:
        raw += bytes.fromhex(txid)[::-1].hex() + index.to_bytes(4, "little").hex() + "00ffffffff"
    raw += bytes([len(outputs)]).hex()
    for value, script in outputs:
        raw += value.to_bytes(8, "little").hex() + bytes([len(script) // 2]).hex() + script
    raw += "00000000"
    doc["tx"] = {"txid": raw_id(raw), "raw_hex": raw}


class ReceiptTests(unittest.TestCase):
    def rejects(self, doc, message, mode="synthetic"):
        result = audit.audit(doc, mode)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn(message, result["errors"][0])

    def test_known_answer(self):
        result = audit.audit(good(), "synthetic")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["max_fee_sats"], 100_000)
        self.assertEqual(result["txid"], "2b270ba76ebd54a49589fb7611c1f1f0f7205c8ac544586612b9e8d731004c80")
        self.assertEqual([result[k] for k in ("input_sum_sats", "paid_sats", "fee_sats")],
                         [300_000, 299_000, 1_000])
        self.assertEqual(result["unspent_status"], "NOT ESTABLISHED")
        self.assertEqual(result["confirmation"], "NOT ESTABLISHED")

    def test_witness_parent_hash(self):
        parent = good()["prevouts"][0]
        actual, _, outputs = audit.parse_transaction(parent["raw_hex"])
        self.assertEqual(actual, "4cbd9972cc51070ecc9301e22bd01fb19f9708dd86b14770c197668463ab773a")
        self.assertNotEqual(actual, raw_id(parent["raw_hex"]))
        self.assertEqual(outputs, [(100_000, SOURCE), (500, "51"), (200_000, SOURCE)])

    def test_scripts_and_checksums(self):
        for fn, address, script in (
            (audit.p2pkh_script_from_address, audit.PRIZE_ADDRESS, SOURCE),
            (audit.p2tr_script_from_address, audit.RECIPIENT, DEST),
        ):
            self.assertEqual(fn(address), script)
            with self.assertRaises(ValueError):
                fn(address[:-1] + "q")

    def test_network_and_labels(self):
        self.rejects(good(), "synthetic label", "mainnet")
        self.rejects(good(), "network", "regtest")
        for label in (False, "true", 1):
            with self.subTest(label=label):
                doc = good()
                doc["synthetic"] = label
                self.rejects(doc, "synthetic label")
        for key in ("recipient", "address"):
            doc = good()
            target = doc if key == "recipient" else doc["snapshot"]
            target[key] = "substitution"
            self.rejects(doc, "wrong fixed")

    def test_versioned_regtest_known_answer(self):
        doc = json.loads(REGTEST_FIXTURE.read_text())
        result = audit.audit(doc, "regtest")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["txid"], "0f9ea4b65c18bba209664dd4c229fdd7fd8c48629597bddbd87c30328bf4a7f9")
        self.assertEqual(result["fee_sats"], 1_000)
        self.rejects(doc, "network", "mainnet")
        doc["recipient"] = audit.RECIPIENT
        self.rejects(doc, "Taproot address", "regtest")
        doc["recipient"] = json.loads(REGTEST_FIXTURE.read_text())["recipient"]
        doc["snapshot"]["address"] = audit.PRIZE_ADDRESS
        self.rejects(doc, "Base58Check", "regtest")

    def test_regtest_receipt_is_insufficient(self):
        doc = json.loads(LEGACY.read_text())
        self.rejects(doc, "expected object fields", "mainnet")
        result = audit.audit(doc, "regtest")
        self.assertEqual(result["verdict"], "INSUFFICIENT")
        self.assertEqual(result["confirmation"], "NOT ESTABLISHED")
        self.assertIn("lacks raw spend", result["errors"][0])

    def test_boolean_claims_and_unversioned_receipts(self):
        for label in ("authenticated", "confirmed", "unspent", "fixture"):
            doc = good()
            doc[label] = True
            self.rejects(doc, "expected object fields")
        self.rejects({"tx": {}, "prevouts": [], "snapshot": {}}, "expected object fields")

    def test_mismatched_raw_txids(self):
        for target in ("parent", "spend"):
            doc = good()
            record = doc["tx"] if target == "spend" else doc["prevouts"][0]
            record["txid"] = "a" * 64
            self.rejects(doc, "raw txid mismatch")
        doc = good()
        doc["prevouts"][0]["txid"] = raw_id(doc["prevouts"][0]["raw_hex"])
        self.rejects(doc, "raw txid mismatch")

    def test_duplicate_input_and_snapshot(self):
        doc = good()
        point = doc["snapshot"]["outpoints"][0]
        spend(doc, [(point["txid"], point["vout"])] * 2)
        self.rejects(doc, "duplicate input")
        doc["snapshot"]["outpoints"].append(point)
        self.rejects(doc, "duplicate snapshot")

    def test_input_set_missing_and_extra(self):
        points = good()["snapshot"]["outpoints"]
        keys = [(p["txid"], p["vout"]) for p in points]
        for inputs in (keys[:1], keys + [("33" * 32, 0)], [keys[0], (keys[1][0], 1)]):
            doc = good()
            spend(doc, inputs)
            self.rejects(doc, "input set differs")

    def test_funding_set_missing_duplicate_and_extra(self):
        doc = good()
        doc["prevouts"] = []
        self.rejects(doc, "funding transaction set")
        doc = good()
        doc["prevouts"] *= 2
        self.rejects(doc, "duplicate funding")
        doc = good()
        doc["prevouts"].append(doc["tx"])
        self.rejects(doc, "funding transaction set")

    def test_indexed_amount_and_script(self):
        doc = good()
        point = doc["snapshot"]["outpoints"][1]
        point["vout"] = 3
        spend(doc)
        self.rejects(doc, "index out of range")
        point["vout"] = 1
        spend(doc)
        self.rejects(doc, "amount differs")
        point["value_sats"] = 500
        self.rejects(doc, "script differs")

    def test_claimed_value_and_index_types(self):
        for value in (True, -1, 1.0, "100000", 0, audit.MAX_SATS + 1):
            doc = good()
            doc["snapshot"]["outpoints"][0]["value_sats"] = value
            self.rejects(doc, "invalid snapshot amount")
        for index in (True, -1, 2**32, 0.0):
            doc = good()
            doc["snapshot"]["outpoints"][0]["vout"] = index
            self.rejects(doc, "invalid output index")

    def test_output_and_fee_policy(self):
        for outputs, message in (
            (((299_000, DEST), (1, "51")), "exactly one output"),
            (((299_000, DEST), (1, DEST)), "exactly one output"),
            (((299_000, SOURCE),), "recipient script"),
            (((300_001, DEST),), "negative fee"),
            (((199_999, DEST),), "excessive fee"),
            (((0, DEST),), "nonpositive payment"),
            (((2**64 - 1, DEST),), "money range"),
        ):
            with self.subTest(outputs=outputs):
                doc = good()
                spend(doc, outputs=outputs)
                self.rejects(doc, message)
        doc = good()
        for paid, fee in ((200_000, 100_000), (300_000, 0)):
            spend(doc, outputs=((paid, DEST),))
            self.assertEqual(audit.audit(doc, "synthetic")["fee_sats"], fee)

    def test_malformed_wire(self):
        spend_raw = good()["tx"]["raw_hex"]
        parent = good()["prevouts"][0]["raw_hex"]
        for raw, message in (
            (spend_raw + "00", "trailing"),
            (spend_raw[:-2], "truncated"),
            (" " + spend_raw, "invalid raw"),
            (spend_raw.upper(), "invalid raw"),
            (spend_raw[:8] + "fd0200" + spend_raw[10:], "noncanonical CompactSize"),
            (spend_raw[:8] + "fe00000100" + spend_raw[10:], "exceeds remaining"),
            (parent[:10] + "03" + parent[12:], "marker/flags"),
            (parent[:-14] + "00" + parent[-8:], "superfluous witness"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                audit.parse_transaction(raw)

    def test_generated_fee_cap_boundaries(self):
        for cap in (0, 999, 100_000, 100_001):
            for fee in (cap, cap + 1):
                with self.subTest(cap=cap, fee=fee):
                    doc = good()
                    spend(doc, outputs=((300_000 - fee, DEST),))
                    result = audit.audit(doc, "synthetic", max_fee_sats=cap)
                    self.assertEqual(result["max_fee_sats"], cap)
                    self.assertEqual(result["fee_sats"], fee)
                    self.assertEqual(result["verdict"], "PASS" if fee == cap else "FAIL")
                    self.assertEqual(result["errors"], [] if fee == cap else ["excessive fee"])

    def test_receipt_cannot_override_caller_cap(self):
        doc = good()
        spend(doc, outputs=((199_999, DEST),))
        baseline = audit.audit(doc, "synthetic")
        self.assertEqual(baseline["verdict"], "FAIL")
        self.assertEqual(baseline["fee_sats"], 100_001)
        self.assertEqual(baseline["max_fee_sats"], 100_000)
        doc["max_fee_sats"] = 200_000
        result = audit.audit(doc, "synthetic", max_fee_sats=100_000)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["max_fee_sats"], 100_000)
        self.assertIn("expected object fields", result["errors"][0])

    def test_invalid_api_caps(self):
        for cap in (True, False, -1, 1000.0, "1000", None):
            with self.subTest(cap=cap):
                result = audit.audit(good(), "synthetic", max_fee_sats=cap)
                self.assertEqual(result["verdict"], "FAIL")
                self.assertIn("must be a nonnegative integer", result["errors"][0])

    def test_cli_fee_policy(self):
        cmd = [sys.executable, "-B", str(HERE.parent / "audit.py"), "--mode", "regtest"]
        for cap, code, verdict in (("999", 1, "FAIL"), ("1000", 0, "PASS"),
                                   ("100001", 0, "PASS"), ("0", 1, "FAIL")):
            with self.subTest(cap=cap):
                result = subprocess.run(cmd + ["--max-fee-sats", cap, str(REGTEST_FIXTURE)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["verdict"], verdict)
                self.assertEqual(report["max_fee_sats"], int(cap))
                self.assertEqual(report["fee_sats"], 1000)
        for cap in ("", "-1", "-0", "+1", "1.0", "1e3", "1_000", " 1", "1 ", "١", "true"):
            with self.subTest(cap=cap):
                result = subprocess.run(cmd + ["--max-fee-sats=" + cap, str(REGTEST_FIXTURE)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("nonnegative integer", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_strict_json(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
            json.loads('{"txid":1,"txid":2}', object_pairs_hook=audit.unique_json_object)
        with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
            json.loads('{"fee":NaN}', parse_constant=audit.reject_constant)

    def test_cli(self):
        cmd = [sys.executable, "-B", str(HERE.parent / "audit.py")]
        for options, path, code, verdict in (
            (["--mode", "synthetic"], FIXTURE, 0, "PASS"),
            ([], FIXTURE, 1, "FAIL"),
            (["--mode", "regtest"], LEGACY, 1, "INSUFFICIENT"),
        ):
            result = subprocess.run(cmd + options + [str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(json.loads(result.stdout)["verdict"], verdict)
        result = subprocess.run(cmd + [str(HERE / "absent.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
