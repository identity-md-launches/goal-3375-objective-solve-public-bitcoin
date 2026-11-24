"""Offline tests. The mock signer emits a synthetic script, never a real signature."""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
from io import StringIO
import os
import unittest
from unittest.mock import patch

from bitcoin import ClaimError, compact, little, parse_tx, public_key, recipient_script, vector
from claim import Claim, Core, HIGH, LOW, RECIPIENT, SOURCE, main, sats

CANDIDATE = (1).to_bytes(32, "big")
TIP = "ab" * 32
BLOCK = "cd" * 32
SYNTHETIC_DER = bytes.fromhex("300602010102010101")


def make_tx(inputs, outputs, witness=False):
    return (little(2, 4) + (b"\0\x01" if witness else b"") + compact(len(inputs))
            + b"".join(bytes.fromhex(txid)[::-1] + little(index, 4) + vector(script)
                       + little(sequence, 4) for txid, index, script, sequence in inputs)
            + compact(len(outputs))
            + b"".join(little(amount, 8) + vector(script) for amount, script in outputs)
            + (b"\x01\x01\xff" * len(inputs) if witness else b"") + little(0, 4))


def btc_value(satoshis):
    return Decimal(satoshis) / 100_000_000


class MockNode:
    def __init__(self):
        self.claim = Claim(self, synthetic=True)
        self.calls = []
        self.raw = {}
        self.unspents = []
        self.mempool_txids = []
        self.sequence = 12
        self.dead = set()
        self.mutate = lambda inputs, outputs: (inputs, outputs)
        self.complete = True
        self.estimate = {"feerate": Decimal("0.00002000")}
        self.accept = True
        self.move_after_accept = False
        self.bad_fee = False
        self.depth = 0
        self.active_block = BLOCK
        self.in_block = True
        self.signed = None
        self.chain = "regtest"
        self.add_fund(120_000)
        self.add_fund(80_000, pending=True, witness=True)

    def add_fund(self, amount, pending=False, witness=False):
        parent = make_tx([("aa" * 32, len(self.raw), b"", 0xFFFFFFFF)],
                         [(amount, self.claim.source_script)], witness)
        txid = parse_tx(parent).txid
        self.raw[txid] = parent.hex()
        if pending:
            self.mempool_txids.append(txid)
        else:
            self.unspents.append({"txid": txid, "vout": 0, "amount": btc_value(amount)})
        return txid

    def spend_in_mempool(self, txid, vout):
        # A mempool transaction spending the given source outpoint elsewhere.
        spend = make_tx([(txid, vout, b"", 0xFFFFFFFF)], [(1, b"\x51")])
        sid = parse_tx(spend).txid
        self.raw[sid] = spend.hex()
        self.mempool_txids.append(sid)
        return sid

    def __call__(self, method, *params):
        self.calls.append(method)
        if method == "getblockchaininfo":
            return {"chain": self.chain, "initialblockdownload": False, "blocks": 120, "headers": 120}
        if method == "getindexinfo":
            return {"txindex": {"synced": True}}
        if method == "getbestblockhash":
            return TIP
        if method == "scantxoutset":
            return {"success": True, "bestblock": TIP, "unspents": self.unspents}
        if method == "getrawmempool":
            return {"txids": list(self.mempool_txids), "mempool_sequence": self.sequence}
        if method == "gettxout":
            txid, index, include_mempool = params
            assert include_mempool is True
            if txid in self.dead:
                return None
            amount, script = parse_tx(bytes.fromhex(self.raw[txid])).outputs[index]
            return {"bestblock": TIP, "scriptPubKey": {"hex": script.hex()},
                    "coinbase": False, "confirmations": 0, "value": btc_value(amount)}
        if method == "getrawtransaction":
            if params[1]:
                return {"hex": self.signed.hex(), "blockhash": BLOCK, "confirmations": self.depth}
            return self.raw[params[0]]
        if method == "estimatesmartfee":
            return self.estimate
        if method == "getmempoolinfo":
            return {"mempoolminfee": Decimal("0.00001"), "minrelaytxfee": Decimal("0.00001")}
        if method == "signrawtransactionwithkey":
            unsigned, _, prevouts, sighash = params
            assert sighash == "ALL"
            tx = parse_tx(bytes.fromhex(unsigned))
            assert len(prevouts) == len(tx.inputs)
            script = vector(SYNTHETIC_DER) + vector(self.claim.pubkey)
            inputs = [(txid, index, script, seq) for txid, index, _, seq in tx.inputs]
            self.signed = make_tx(*self.mutate(inputs, list(tx.outputs)))
            return {"complete": self.complete, "hex": self.signed.hex()}
        if method == "testmempoolaccept":
            tx = parse_tx(bytes.fromhex(params[0][0]))
            total = sum(parse_tx(bytes.fromhex(self.raw[parent])).outputs[index][0]
                        for parent, index, _, _ in tx.inputs)
            fee = total - tx.outputs[0][0] + self.bad_fee
            if self.move_after_accept:
                self.sequence += 1
            return [{"allowed": self.accept, "txid": tx.txid, "vsize": tx.vsize,
                     "fees": {"base": btc_value(fee)}}]
        if method == "sendrawtransaction":
            assert params[2] == "0"
            return parse_tx(bytes.fromhex(params[0])).txid
        if method == "getblock":
            return {"hash": BLOCK, "height": 120, "confirmations": self.depth,
                    "tx": [parse_tx(self.signed).txid] if self.in_block else []}
        if method == "getblockhash":
            return self.active_block
        raise AssertionError(method)


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.node = MockNode()
        self.claim = self.node.claim

    def prepare(self, cap=2000, broadcast=False, regtest_rate=None):
        return self.claim.prepare(CANDIDATE, cap, 6, regtest_rate, broadcast)

    def reject(self, message, **kwargs):
        with self.assertRaisesRegex(ClaimError, message):
            self.prepare(broadcast=True, **kwargs)
        self.assertNotIn("sendrawtransaction", self.node.calls)

    def test_public_constants_and_candidate_validation(self):
        prod = Claim(None)
        self.assertEqual(prod.source, SOURCE)
        self.assertEqual(prod.source_script.hex(), "76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac")
        self.assertEqual(prod.output_script[:2], b"\x51\x20")
        # The regtest recipient must encode the identical 32-byte payout program
        # as the fixed mainnet recipient, so the synthetic path exercises it.
        program = "46bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f"
        self.assertEqual(prod.output_script.hex(), "5120" + program)
        self.assertEqual(self.claim.output_script, prod.output_script)
        self.assertEqual(public_key(2).hex(),
                         "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        with self.assertRaisesRegex(ClaimError, "checksum"):
            recipient_script(RECIPIENT[:-1] + "q")
        with self.assertRaisesRegex(ClaimError, "network"):
            recipient_script(self.claim.recipient)
        for size in (31, 33):
            with self.assertRaisesRegex(ClaimError, "exactly"):
                self.claim.check_candidate(bytes(size))
        with self.assertRaisesRegex(ClaimError, "interval"):
            self.claim.check_candidate((2).to_bytes(32, "big"))
        for scalar in (LOW - 1, HIGH + 1):
            with self.assertRaisesRegex(ClaimError, "interval"):
                prod.check_candidate(scalar.to_bytes(32, "big"))
        with patch("claim.public_key", return_value=public_key(2)):
            for scalar in (LOW, HIGH):
                with self.assertRaisesRegex(ClaimError, "mismatch"):
                    prod.check_candidate(scalar.to_bytes(32, "big"))
        self.claim.check_candidate(CANDIDATE)

    def test_prepare_default_spends_confirmed_and_pending_once(self):
        self.claim.check_node()
        receipt = self.prepare()
        self.assertEqual(receipt["status"], "prepared")
        self.assertEqual(receipt["inputSats"], 200_000)
        self.assertEqual(receipt["inputs"], 2)
        self.assertEqual(receipt["feeSats"], receipt["vsize"] * 2)
        self.assertEqual(receipt["paymentSats"] + receipt["feeSats"], 200_000)
        self.assertEqual(self.node.calls.count("scantxoutset"), 2)
        # Per snapshot: one mempool-receive tx fetch plus two raw-prevout fetches.
        self.assertEqual(self.node.calls.count("getrawtransaction"), 6)
        self.assertNotIn("sendrawtransaction", self.node.calls)

    def test_broadcast_pending_then_active_chain_verification(self):
        with redirect_stdout(StringIO()) as output:
            receipt = self.prepare(broadcast=True)
        self.assertIn("broadcast_attempt", output.getvalue())
        self.assertEqual(receipt["status"], "broadcast_pending")
        self.assertEqual(self.node.calls[-1], "sendrawtransaction")
        with self.assertRaisesRegex(ClaimError, "insufficient"):
            self.claim.verify(receipt["txid"], 2000, 1)
        self.node.depth = 2
        self.node.in_block = False
        with self.assertRaisesRegex(ClaimError, "missing from reported block"):
            self.claim.verify(receipt["txid"], 2000, 2)
        self.node.in_block = True
        self.node.active_block = TIP
        with self.assertRaisesRegex(ClaimError, "active chain changed"):
            self.claim.verify(receipt["txid"], 2000, 2)
        self.node.active_block = BLOCK
        verified = self.claim.verify(receipt["txid"], 2000, 2)
        self.assertEqual(verified["status"], "confirmed")
        self.assertEqual(verified["paymentSats"], receipt["paymentSats"])

    def test_wrong_network(self):
        self.node.chain = "main"
        with self.assertRaisesRegex(ClaimError, "unexpected Bitcoin Core network"):
            self.claim.check_node()
        self.assertEqual(self.node.calls, ["getblockchaininfo"])

    def test_missing_funds(self):
        self.node.unspents.clear()
        self.node.mempool_txids.clear()
        self.reject("no spendable")

    def test_spent_output_excluded(self):
        self.node.spend_in_mempool(self.node.unspents[0]["txid"], 0)
        self.assertEqual(self.prepare()["inputSats"], 80_000)

    def test_stale_unspent(self):
        self.node.dead.add(self.node.unspents[0]["txid"])
        self.reject("UTXO changed")

    def test_wrong_raw_prevout(self):
        first, second = self.node.raw
        self.node.raw[first] = self.node.raw[second]
        self.reject("prevout identity")

    def test_prevout_accounting_disagreement(self):
        self.node.unspents[0]["amount"] += Decimal("0.00000001")
        self.reject("inconsistent prevout value")

    def test_duplicate_discovery(self):
        self.node.unspents *= 2
        self.reject("duplicate discovered")

    def test_no_node_fee_estimate(self):
        self.node.estimate = {"errors": ["insufficient data"]}
        self.reject("no fee estimate")
        self.assertEqual(self.prepare(regtest_rate=2000)["status"], "prepared")

    def test_fee_cap(self):
        self.reject("exceeds cap", cap=50)

    def test_incomplete_signature(self):
        self.node.complete = False
        self.reject("did not fully sign")

    def test_changed_outputs(self):
        for mutate in (lambda outs: [(outs[0][0], b"\x51")],
                       lambda outs: [(outs[0][0] - 1, outs[0][1]), (1, b"\x51")]):
            with self.subTest(mutate=mutate):
                self.node.mutate = lambda inputs, outputs: (inputs, mutate(outputs))
                self.reject("one output")

    def test_changed_inputs(self):
        for mutate in (lambda ins: ins[:1], lambda ins: [ins[0], ins[0]],
                       lambda ins: [*ins, ("fe" * 32, 0, ins[0][2], 0xFFFFFFFF)]):
            with self.subTest(mutate=mutate):
                self.node.mutate = lambda inputs, outputs: (mutate(inputs), outputs)
                self.reject("differ from selected")

    def test_missing_or_wrong_signature(self):
        for script in (b"", vector(SYNTHETIC_DER[:-1] + b"\x81") + vector(self.claim.pubkey)):
            with self.subTest(script=script):
                self.node.mutate = lambda inputs, outputs: (
                    [(txid, index, script, seq) for txid, index, _, seq in inputs], outputs)
                self.reject("P2PKH signature")

    def test_mempool_rejection_and_accounting(self):
        self.node.accept = False
        self.reject("mempool acceptance")
        self.node.accept = True
        self.node.bad_fee = True
        self.reject("transaction accounting")

    def test_node_state_changes_after_acceptance(self):
        self.node.move_after_accept = True
        self.reject("chain or mempool moved")

    def test_integer_amount_and_witness_prevout(self):
        with self.assertRaisesRegex(ClaimError, "invalid BTC amount"):
            sats(Decimal("0.000000001"))
        raw = bytes.fromhex(self.node.raw[self.node.mempool_txids[0]])
        tx = parse_tx(raw)
        self.assertTrue(tx.witness)
        self.assertLess(tx.vsize, len(raw))
        with self.assertRaises(ClaimError):
            parse_tx(raw + b"\0")


class PrivacyTests(unittest.TestCase):
    def test_rpc_redacts_errors_and_disallows_external_endpoints(self):
        for url in ("http://outside.invalid:8332", "http://localhost:8332",
                    "http://user:pass@127.0.0.1:8332", "http://127.0.0.1:8332/?secret"):
            with self.assertRaisesRegex(ClaimError, "explicit loopback"):
                Core(url, b"user:password")
        conn = Core("http://127.0.0.1:8332", b"user:password")
        with patch("claim.http.client.HTTPConnection") as constructor:
            mocked = constructor.return_value
            mocked.request.side_effect = RuntimeError("secret from RPC")
            with self.assertRaisesRegex(ClaimError, r"^RPC failed \(signrawtransactionwithkey\); details withheld$"):
                conn("signrawtransactionwithkey")
            mocked.close.assert_called_once()

    def test_cli_closes_private_fds_even_on_rejection(self):
        auth, auth_write = os.pipe()
        candidate, candidate_write = os.pipe()
        with os.fdopen(auth_write, "wb") as stream:
            stream.write(b"user:password")
        with os.fdopen(candidate_write, "wb") as stream:
            stream.write(b"synthetic malformed candidate")
        argv = ["regtest.py", "--rpc-url", "http://127.0.0.1:18443", "--rpc-auth-fd", str(auth),
                "--max-fee-sats", "2000", "claim", "--candidate-fd", str(candidate),
                "--fee-target", "6"]
        with patch("sys.argv", argv), redirect_stderr(StringIO()) as error:
            self.assertEqual(main(synthetic=True), 1)
        self.assertNotIn("malformed candidate", error.getvalue())
        for fd in (auth, candidate):
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
