#!/usr/bin/env python3
"""Generate a public, synthetic receipt with the landed private-claim CLI.

Only scalar 1 on a fresh, disconnected regtest node is used. The node's cookie
and the candidate travel to the claim CLI through inherited pipes, not argv.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for directory in (HERE, ROOT / "private-claim", ROOT / "receipt-check"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import audit
from bitcoin import ClaimError, parse_tx
from check_core import run_cli, node_port
from claim import Claim, Core
import regtest_payment as rp
import verify_receipt as vr


class IntegrationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise IntegrationError(message)


def sats(value):
    return rp.btc_to_sats(value)


def public_record(node, txid, blockhash):
    raw = node.cli("getrawtransaction", txid, "false", blockhash)
    require(parse_tx(bytes.fromhex(raw)).txid == txid, "raw funding identity changed")
    return {"txid": txid, "raw_hex": raw}


def chain_evidence(node, receipt, source_tip, funding_block, sweep_block, admission, cli_claim, cli_verify):
    """Capture the containing blocks and a stable two-deep active-chain anchor."""
    header = node.cli("getblockheader", sweep_block)
    tip = node.cli("getblockchaininfo")
    require(tip["chain"] == "regtest" and header["confirmations"] >= 2,
            "sweep lacks active-chain depth")
    require(node.cli("getblockhash", str(header["height"])) == sweep_block,
            "sweep block left active chain")
    require(node.cli("getbestblockhash") == tip["bestblockhash"], "tip moved during capture")
    return {
        "schema": "regtest-claim-evidence/v1", "receipt_sha256": hashlib.sha256(
            (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest(),
        "source_tip_before_spend": source_tip, "funding_blockhash": funding_block,
        "funding_block_raw": node.cli("getblock", funding_block, "0"),
        "sweep_blockhash": sweep_block, "sweep_block_raw": node.cli("getblock", sweep_block, "0"),
        "sweep_height": header["height"], "depth": header["confirmations"],
        "active_tip": tip["bestblockhash"], "active_height": tip["blocks"],
        "active_tip_header_raw": node.cli("getblockheader", tip["bestblockhash"], "false"),
        "mempool_admission": admission, "claim_cli": cli_claim, "verify_cli": cli_verify,
        "objectiveStatus": "INCOMPLETE", "synthetic": True,
    }


def verify_chain(receipt, evidence):
    """Independent byte and header consistency; Core supplies script/chain validity."""
    result = audit.audit(receipt, "regtest")
    require(result["byte_integrity"] == "PASS", "receipt byte policy failed: " + str(result["errors"]))
    require(audit.audit(receipt, "mainnet")["verdict"] == "FAIL", "regtest passed mainnet mode")
    require(evidence["schema"] == "regtest-claim-evidence/v1" and evidence["synthetic"] is True
            and evidence["objectiveStatus"] == "INCOMPLETE", "evidence label mismatch")
    digest = hashlib.sha256((json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    require(evidence["receipt_sha256"] == digest, "receipt evidence hash mismatch")
    funding, funding_txs = vr.block(evidence["funding_block_raw"])
    containing, spend_txs = vr.block(evidence["sweep_block_raw"])
    tip = vr.header_info(bytes.fromhex(evidence["active_tip_header_raw"]))
    require(funding["hash"] == evidence["funding_blockhash"] == evidence["source_tip_before_spend"],
            "funding anchor mismatch")
    require(containing["hash"] == evidence["sweep_blockhash"] and
            containing["previous"] == funding["hash"], "spend block linkage mismatch")
    require(tip["hash"] == evidence["active_tip"] and tip["previous"] == containing["hash"],
            "active tip linkage mismatch")
    require(evidence["depth"] == 2 and evidence["active_height"] == evidence["sweep_height"] + 1,
            "anchor depth mismatch")
    funding_ids = {p["txid"] for p in receipt["prevouts"]}
    require(funding_ids <= {tx["txid"] for tx in funding_txs}, "funding block membership mismatch")
    require(any(tx["raw"] == receipt["tx"]["raw_hex"] for tx in spend_txs),
            "spend block membership mismatch")
    claim = evidence["claim_cli"]
    verified = evidence["verify_cli"]
    require(claim["status"] == "broadcast_pending" and verified["status"] == "confirmed"
            and claim["txid"] == verified["txid"] == receipt["tx"]["txid"],
            "claim CLI status mismatch")
    require(claim["inputs"] == verified["inputs"] == len(receipt["snapshot"]["outpoints"]) == 7,
            "claim input inventory mismatch")
    require(result["input_sum_sats"] == claim["inputSats"] == verified["inputSats"]
            and result["paid_sats"] == claim["paymentSats"] == verified["paymentSats"]
            and result["fee_sats"] == claim["feeSats"] == verified["feeSats"],
            "claim accounting mismatch")
    raw = parse_tx(bytes.fromhex(receipt["tx"]["raw_hex"]))
    require(raw.vsize == claim["vsize"] == verified["vsize"], "signed vsize mismatch")
    require(0 < result["fee_sats"] <= 5000 and result["fee_sats"] * 1000 >= 2000 * raw.vsize,
            "fee cap or signed feerate mismatch")
    admission = evidence["mempool_admission"]
    require(admission["txid"] == raw.txid and admission["vsize"] == raw.vsize,
            "mempool admission mismatch")
    require(admission["fee_sats"] == result["fee_sats"], "mempool fee mismatch")
    require(verified["blockHash"] == evidence["sweep_blockhash"]
            and verified["confirmations"] == evidence["depth"], "verification depth mismatch")
    return result


def generate(work_root=None, hold_at=None, ready=None):
    started = time.monotonic()
    synthetic = Claim(None, synthetic=True)
    require(Claim(None).output_script == synthetic.output_script == bytes.fromhex(rp.SCRIPT),
            "mainnet and regtest payout programs differ")
    with rp.runtime() as binaries, tempfile.TemporaryDirectory(prefix="claim-receipt-", dir=work_root) as datadir:
        node = rp.Node(binaries, datadir)
        try:
            node.start()
            network = node.cli("getnetworkinfo")
            require(not network["networkactive"] and network["connections"] == 0,
                    "disposable node networking enabled")
            node.cli("createwallet", "miner")
            mine = node.cli("getnewaddress", "", "bech32", wallet="miner")
            node.cli("generatetoaddress", "101", mine)
            funded = [node.cli("sendtoaddress", synthetic.source, "0.5", wallet="miner")
                      for _ in range(7)]
            require(len(set(funded)) == 7, "funding transaction identities repeated")
            funding_block = node.cli("generatetoaddress", "1", mine)[0]
            funding = [public_record(node, txid, funding_block) for txid in funded]
            scan = node.cli("scantxoutset", "start", json.dumps([synthetic.descriptor]))
            require(scan["success"] is True and scan["bestblock"] == funding_block,
                    "pre-spend UTXO scan unavailable")
            snapshot = []
            for row in scan["unspents"]:
                point = row["txid"], row["vout"]
                require(point[0] in funded, "unexpected source funding")
                live = node.cli("gettxout", point[0], str(point[1]), "true")
                require(live is not None and live["bestblock"] == funding_block
                        and live["scriptPubKey"]["hex"] == synthetic.source_script.hex()
                        and sats(live["value"]) == sats(row["amount"]),
                        "pre-spend inventory changed")
                snapshot.append({"txid": point[0], "vout": point[1],
                                 "value_sats": sats(row["amount"])})
            require(len(snapshot) == 7 and {p["txid"] for p in snapshot} == set(funded),
                    "seven-valued-outpoint inventory incomplete")
            if hold_at == "funded":
                require(ready is not None, "hold requires a ready file")
                Path(ready).write_text(json.dumps({"node_pid": node.proc.pid, "datadir": datadir}))
                while True:
                    signal.pause()
            receipt = {"schema": audit.VERSION, "network": "regtest", "synthetic": True,
                       "recipient": synthetic.recipient,
                       "snapshot": {"address": synthetic.source, "outpoints": snapshot},
                       "prevouts": funding}
            url = "http://127.0.0.1:" + str(node_port(node))
            cookie = (Path(datadir) / "fixture.cookie").read_bytes()
            candidate = (1).to_bytes(32, "big")
            # A structurally intact, corrupted DER signature must fail against
            # real Core policy before the valid claim is broadcast.
            backend = Core(url, cookie)
            class BadSignature:
                def __init__(self):
                    self.calls = []
                def __call__(self, method, *args):
                    self.calls.append(method)
                    value = backend(method, *args)
                    if method == "signrawtransactionwithkey":
                        raw = bytearray.fromhex(value["hex"])
                        raw[52] ^= 1  # inside the first DER integer, preserving pushes
                        value["hex"] = raw.hex()
                    return value
            bad = BadSignature()
            try:
                Claim(bad, synthetic=True).prepare(candidate, 5000, 6, 2000, True)
            except ClaimError as exc:
                require("mempool acceptance" in str(exc), "signature rejected for a different reason")
            else:
                raise IntegrationError("Core accepted corrupted signature")
            require("testmempoolaccept" in bad.calls and "sendrawtransaction" not in bad.calls,
                    "corrupt signature reached broadcast")
            claim_args = ["claim", "--candidate-fd", "{cand}", "--fee-target", "6",
                          "--synthetic-fee-sat-per-kvb", "2000", "--broadcast"]
            rc, output, error = run_cli(str(ROOT / "private-claim/regtest.py"), url, cookie,
                                        5000, claim_args, candidate)
            require(rc == 0, "private claim CLI failed: " + error[-150:])
            lines = output.strip().splitlines()
            require(len(lines) == 2, "claim CLI did not report attempt and pending status")
            attempt, claim = [json.loads(line) for line in lines]
            require(attempt["status"] == "broadcast_attempt" and
                    attempt["txid"] == claim["txid"], "broadcast announcement mismatch")
            txid = claim["txid"]
            require(txid in node.cli("getrawmempool"), "claim did not enter mempool")
            rc, _, error = run_cli(str(ROOT / "private-claim/regtest.py"), url, cookie, 5000,
                                   ["claim", "--candidate-fd", "{cand}", "--fee-target", "6",
                                    "--synthetic-fee-sat-per-kvb", "2000"], candidate)
            require(rc == 1 and "no spendable prize funds" in error,
                    "pending spend was not excluded from inventory")
            raw = node.cli("getrawtransaction", txid, "false")
            receipt["tx"] = {"txid": txid, "raw_hex": raw}
            before = audit.audit(receipt, "regtest")
            require(before["verdict"] == "PASS", "receipt byte policy failed before mining")
            entry = node.cli("getmempoolentry", txid)
            admission = {"txid": txid, "vsize": entry["vsize"],
                         "fee_sats": sats(entry["fees"]["base"])}
            require(admission["fee_sats"] == before["fee_sats"], "mempool fee differs")
            sweep_block = node.cli("generatetoaddress", "1", mine)[0]
            node.cli("generatetoaddress", "1", mine)
            rc, output, error = run_cli(str(ROOT / "private-claim/regtest.py"), url, cookie,
                                        5000, ["verify", "--txid", txid, "--confirmations", "2"])
            require(rc == 0, "private verify CLI failed: " + error[-150:])
            verified = json.loads(output.strip())
            evidence = chain_evidence(node, receipt, funding_block, funding_block,
                                      sweep_block, admission, claim, verified)
            require(node.cli("getbestblockhash") == evidence["active_tip"],
                    "active tip changed after capture")
            verify_chain(receipt, evidence)
            # Exercise actual active-chain rollback and restoration. A receipt
            # remains historical evidence only after the original tip returns.
            node.cli("invalidateblock", sweep_block)
            rc, _, error = run_cli(str(ROOT / "private-claim/regtest.py"), url, cookie,
                                   5000, ["verify", "--txid", txid, "--confirmations", "2"])
            require(rc == 1 and "insufficient active-chain confirmations" in error,
                    "reorged spend incorrectly verified")
            node.cli("reconsiderblock", sweep_block)
            require(node.cli("getbestblockhash") == evidence["active_tip"],
                    "original active tip did not return after reorg")
            restored = node.cli("getrawtransaction", txid, "true", sweep_block)
            require(restored.get("blockhash") == sweep_block
                    and restored.get("confirmations", 0) >= 2,
                    "restored active-chain spend did not verify")
        finally:
            node.close()
    evidence["disposable_secrets_removed"] = True
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
    evidence["max_rss_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return receipt, evidence


def write_json(path, payload):
    Path(path).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--hold-at", choices=["funded"], help=argparse.SUPPRESS)
    parser.add_argument("--ready", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--work-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        public, proof = generate(args.work_root, args.hold_at, args.ready)
    except KeyboardInterrupt:
        print("Synthetic claim receipt interrupted; disposable node cleaned", file=sys.stderr)
        sys.exit(130)
    write_json(args.receipt, public)
    write_json(args.evidence, proof)
    print(json.dumps({"receiptSha256": proof["receipt_sha256"], "txid": public["tx"]["txid"],
                      "inputSats": proof["claim_cli"]["inputSats"],
                      "paidSats": proof["claim_cli"]["paymentSats"],
                      "feeSats": proof["claim_cli"]["feeSats"], "depth": proof["depth"],
                      "elapsedSeconds": proof["elapsed_seconds"], "maxRssKb": proof["max_rss_kb"]}))
