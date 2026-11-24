"""Offline tests for prize_state.py. No network. Run:
    python3 -I -m unittest discover -s prize-state -p 'test_*.py' -v
Uses the committed live bundle as the fixture and mutates COPIES of it.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prize_state as ps  # noqa: E402

FIXTURE = os.path.join(HERE, "evidence", "live-20261124")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.b = os.path.join(self.tmp, "b")
        shutil.copytree(FIXTURE, self.b)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def man(self):
        return json.load(open(os.path.join(self.b, "manifest.json")))

    def save(self, m):
        open(os.path.join(self.b, "manifest.json"), "w").write(ps.canon(m))

    def rec(self, m, prov, key):
        for r in m["rounds"][-1]["providers"][prov]["requests"]:
            if r["key"] == key:
                return r
        raise KeyError(key)

    def body(self, prov, key):
        return open(os.path.join(self.b, self.rec(self.man(), prov, key)["file"]), "rb").read()

    def set_body(self, prov, key, data, add=False):
        m = self.man()
        reqs = m["rounds"][-1]["providers"][prov]["requests"]
        if add:
            r = dict(reqs[0], key=key, file="raw/added/%s/%s.body" % (prov, hashlib.sha256(key.encode()).hexdigest()[:12]))
            reqs.append(r)
        else:
            r = self.rec(m, prov, key)
        p = os.path.join(self.b, r["file"])
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(data)
        r["sha256"], r["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
        self.save(m)

    def final(self):
        return ps.derive(self.b)["rounds"][-1]


class TestPrimitives(unittest.TestCase):
    def test_script(self):
        # independent source: every index vout labelled with the address carries exactly this script
        man = json.load(open(os.path.join(FIXTURE, "manifest.json")))
        seen = set()
        for prov in ("blockstream", "mempool"):
            for r in man["rounds"][-1]["providers"][prov]["requests"]:
                if r["key"].startswith("chain_page_"):
                    for t in json.load(open(os.path.join(FIXTURE, r["file"]))):
                        for o in t["vout"]:
                            if o.get("scriptpubkey_address") == ps.ADDRESS:
                                seen.add(o["scriptpubkey"])
        self.assertEqual(seen, {ps.SCRIPT})
        self.assertEqual(ps.SCRIPT, "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac")

    def test_bad_checksum(self):
        with self.assertRaises(ps.Fail):
            ps.p2pkh_script(ps.ADDRESS[:-1] + ("p" if ps.ADDRESS[-1] != "p" else "q"))

    def test_parse_rejects_trailing_and_truncated(self):
        hx = open(os.path.join(FIXTURE, [r for r in json.load(open(os.path.join(FIXTURE, "manifest.json")))
                                         ["rounds"][-1]["providers"]["blockstream"]["requests"]
                                         if r["key"].startswith("hex:")][0]["file"])).read().strip()
        ps.parse_tx(hx)
        for bad in (hx + "00", hx[:-2], hx + "0"):
            with self.assertRaises(ps.Fail):
                ps.parse_tx(bad)

    def test_need_int_rejects_float_bool(self):
        for v in (1.0, True, "1", None, -1):
            with self.assertRaises(ps.Fail):
                ps.need_int(v, "x")


class TestBundle(Base):
    def test_fixture_verifies_and_amounts(self):
        self.assertTrue(ps.verify(self.b))
        s = json.load(open(os.path.join(self.b, "summary.json")))
        r = s["result"]
        self.assertEqual(r["agreement"], "AGREE")
        self.assertIsInstance(r["confirmed_unspent_sats"], int)
        self.assertEqual(r["outpoints"], sorted(set(r["outpoints"])))
        ci = ps.claim_input(self.b)
        self.assertEqual(ci["total_sats"], sum(u["value_sats"] for u in ci["utxos"]))
        self.assertEqual(len(ci["utxos"]), r["utxo_count"])

    def test_flip_raw_byte_detected(self):
        p = os.path.join(self.b, self.rec(self.man(), "mempool", "utxo")["file"])
        d = bytearray(open(p, "rb").read())
        d[5] ^= 1
        open(p, "wb").write(bytes(d))
        with self.assertRaises(ps.Fail):
            ps.verify(self.b)

    def test_edit_summary_detected(self):
        p = os.path.join(self.b, "summary.json")
        s = json.load(open(p))
        s["result"]["confirmed_unspent_sats"] += 1
        open(p, "w").write(ps.canon(s))
        ps.finish  # SHA256SUMS now stale too; also rebuild sums to isolate re-derivation check
        lines = [l for l in open(os.path.join(self.b, "SHA256SUMS")).read().splitlines() if not l.endswith("  summary.json")]
        lines.append("%s  summary.json" % ps.file_sha(p))
        open(os.path.join(self.b, "SHA256SUMS"), "w").write("\n".join(sorted(lines, key=lambda l: l[66:])) + "\n")
        with self.assertRaisesRegex(ps.Fail, "re-derivation"):
            ps.verify(self.b)

    def test_unlisted_file_detected(self):
        open(os.path.join(self.b, "extra.txt"), "w").write("x")
        with self.assertRaisesRegex(ps.Fail, "unlisted"):
            ps.verify(self.b)

    def test_tampered_raw_tx_value_breaks_txid(self):
        utxo = json.loads(self.body("blockstream", "utxo"))[0]
        key = "hex:" + utxo["txid"]
        hx = self.body("blockstream", key).decode().strip()
        tx = ps.parse_tx(hx)
        spk = tx["vout"][utxo["vout"]]["scriptpubkey"]
        old = utxo["value"].to_bytes(8, "little").hex() + "%02x" % (len(spk) // 2) + spk
        new = (utxo["value"] + 1).to_bytes(8, "little").hex() + "%02x" % (len(spk) // 2) + spk
        self.assertEqual(hx.count(old), 1)
        self.set_body("blockstream", key, hx.replace(old, new).encode())
        f = self.final()
        self.assertEqual(f["providers"]["blockstream"]["status"], "INVALID")
        self.assertIn("recomputed txid", f["providers"]["blockstream"]["error"])
        self.assertEqual(f["agreement"], "UNAVAILABLE")

    def test_index_value_differs_from_raw(self):
        page = json.loads(self.body("mempool", "chain_page_00"))
        tid, vo = page[0]["txid"], 0
        page[0]["vout"][vo]["value"] += 1
        self.set_body("mempool", "chain_page_00", json.dumps(page).encode())
        f = self.final()
        self.assertEqual(f["providers"]["mempool"]["status"], "INVALID")
        self.assertIn("index value/script differs", f["providers"]["mempool"]["error"])

    def test_float_amount_rejected(self):
        page = json.loads(self.body("mempool", "chain_page_00"))
        page[0]["vout"][0]["value"] = float(page[0]["vout"][0]["value"])
        self.set_body("mempool", "chain_page_00", json.dumps(page).encode())
        self.assertIn("not an integer", self.final()["providers"]["mempool"]["error"])

    def test_provider_unavailable_is_explicit(self):
        m = self.man()
        m["rounds"][-1]["providers"]["mempool"]["error"] = "URLError: simulated outage"
        self.save(m)
        f = self.final()
        self.assertEqual(f["providers"]["mempool"]["status"], "UNAVAILABLE")
        self.assertEqual(f["agreement"], "UNAVAILABLE")
        self.assertIsNone(f["anchor"])

    def test_provider_utxo_endpoint_disagreement_flagged(self):
        u = json.loads(self.body("mempool", "utxo"))
        self.set_body("mempool", "utxo", json.dumps(u[1:]).encode())
        f = self.final()
        self.assertEqual(f["providers"]["mempool"]["status"], "INCONSISTENT")
        self.assertEqual(f["agreement"], "AGREE_WITH_ISSUES")

    def test_derived_state_disagreement(self):
        # mempool says one output is spent by a (synthetic) confirmed tx; blockstream says unspent
        self._spend("mempool", confirmed=True)
        f = self.final()
        self.assertEqual(f["agreement"], "DISAGREE", f["providers"]["mempool"])

    def test_tip_moved_needs_repeat(self):
        h = int(self.body("blockstream", "tip_after_height")) + 1
        self.set_body("blockstream", "tip_after_height", str(h).encode())
        f = self.final()
        self.assertEqual(f["agreement"], "NO_COMMON_TIP")
        self.assertTrue(f["needs_repeat"])

    def test_pending_spend_reported_and_claim_refused(self):
        for p in ("blockstream", "mempool"):
            self._spend(p, confirmed=False)
        ps.finish(self.b)
        s = json.load(open(os.path.join(self.b, "summary.json")))
        r = s["result"]
        self.assertEqual(r["agreement"], "AGREE")
        self.assertEqual(len(r["pending_spends"]), 1)
        self.assertEqual(r["spendable_sats_excluding_pending_spends"],
                         r["confirmed_unspent_sats"] - r["pending_spends"][0]["value_sats"])
        ps.verify(self.b)
        with self.assertRaisesRegex(ps.Fail, "pending spends"):
            ps.claim_input(self.b)

    def test_spend_not_referencing_outpoint_rejected(self):
        u = json.loads(self.body("blockstream", "utxo"))[0]
        other = [k for k in (r["key"] for r in self.man()["rounds"][-1]["providers"]["blockstream"]["requests"])
                 if k.startswith("hex:") and k[4:] != u["txid"]][0][4:]
        outs = json.loads(self.body("blockstream", "outspends:" + u["txid"]))
        outs[u["vout"]] = {"spent": True, "txid": other, "vin": 0, "status": {"confirmed": True}}
        self.set_body("blockstream", "outspends:" + u["txid"], json.dumps(outs).encode())
        self.assertIn("does not reference", self.final()["providers"]["blockstream"]["error"])

    def _spend(self, prov, confirmed):
        u = sorted(json.loads(self.body(prov, "utxo")), key=lambda x: (x["txid"], x["vout"]))[0]
        tx = (b"\x02\x00\x00\x00" + b"\x01" + bytes.fromhex(u["txid"])[::-1] + u["vout"].to_bytes(4, "little")
              + b"\x00" + b"\xff\xff\xff\xff" + b"\x01" + (u["value"] - 500).to_bytes(8, "little")
              + b"\x16\x00\x14" + b"\x11" * 20 + b"\x00\x00\x00\x00")
        sp = ps.dsha(tx)[::-1].hex()
        self.set_body(prov, "hex:" + sp, tx.hex().encode(), add=True)
        tip = int(self.body(prov, "tip_after_height"))
        st = {"confirmed": True, "block_height": tip, "block_hash": self.body(prov, "tip_after_hash").decode().strip()} \
            if confirmed else {"confirmed": False}
        self.set_body(prov, "status:" + sp, json.dumps(st).encode(), add=True)
        outs = json.loads(self.body(prov, "outspends:" + u["txid"]))
        outs[u["vout"]] = {"spent": True, "txid": sp, "vin": 0, "status": st}
        self.set_body(prov, "outspends:" + u["txid"], json.dumps(outs).encode())
        rest = [x for x in json.loads(self.body(prov, "utxo")) if (x["txid"], x["vout"]) != (u["txid"], u["vout"])]
        self.set_body(prov, "utxo", json.dumps(rest).encode())


if __name__ == "__main__":
    unittest.main()
