#!/usr/bin/env python3
"""Replay public payment and UTXO evidence on a disposable Bitcoin Core regtest."""

import json
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / name) for name in ("receipt-check", "regtest-payment")]

import audit
import regtest_payment as fixture


def tip(node):
    info = node.cli("getblockchaininfo")
    fixture.assert_regtest_chain(info)
    return {"blockHash": info["bestblockhash"], "height": info["blocks"]}


def empty_mempool(node):
    pool = node.cli("getrawmempool", "false", "true")
    audit.require(pool["txids"] == [], "inventory requires an empty mempool")
    return {"txids": [], "sequence": pool["mempool_sequence"]}


def scan_inventory(node, source):
    """Capture chainstate independently of wallet records and spend bytes."""
    script = audit.p2pkh_script_from_address(source, version=111)
    anchor = tip(node)
    mempool = empty_mempool(node)
    scan = node.cli("scantxoutset", "start", json.dumps([f"raw({script})"]))
    audit.require(scan["success"] is True and scan["bestblock"] == anchor["blockHash"]
                  and scan["height"] == anchor["height"], "scan anchor changed")
    rows = []
    for output in scan["unspents"]:
        txid, vout = audit.outpoint(output)
        value = fixture.btc_to_sats(output["amount"])
        live = node.cli("gettxout", txid, str(vout), "true")
        audit.require(output["scriptPubKey"] == script and live is not None
                      and live["bestblock"] == anchor["blockHash"]
                      and live["scriptPubKey"]["hex"] == script
                      and fixture.btc_to_sats(live["value"]) == value,
                      "scan output differs from mempool-aware gettxout")
        rows.append({"txid": txid, "vout": vout, "value_sats": value})
    rows.sort(key=audit.outpoint)
    total = sum(row["value_sats"] for row in rows)
    audit.require(len({audit.outpoint(row) for row in rows}) == len(rows)
                  and total == fixture.btc_to_sats(scan["total_amount"]),
                  "scan count or amount mismatch")
    audit.require(empty_mempool(node) == mempool and tip(node) == anchor,
                  "tip or mempool changed during inventory capture")
    return {"rpc": "scantxoutset", "anchor": anchor, "sourceScript": script,
            "mempool": mempool, "outpoints": rows, "totalSats": total}


def observe(node, receipt, block_hash, independent_scan, presented_snapshot):
    """Read-only verdict. The independent scan is supplied by the live fixture."""
    byte_check = audit.audit(receipt, "regtest")
    txid = receipt["tx"]["txid"]
    active_tip = tip(node)
    header = node.cli("getblockheader", block_hash)
    block = node.cli("getblock", block_hash, "2")
    matches = [tx for tx in block["tx"] if tx["txid"] == txid]
    included = (len(matches) == 1 and matches[0]["hex"] == receipt["tx"]["raw_hex"])
    height = header["height"]
    active = height <= active_tip["height"] and node.cli("getblockhash", str(height)) == block_hash
    depth = active_tip["height"] - height + 1 if active else 0
    audit.require(header["confirmations"] == (depth if active else -1),
                  "Core header depth differs from active chain")
    recipient = receipt["recipient"] == fixture.DESTINATION
    confirmed = byte_check["verdict"] == "PASS" and recipient and included and active

    covered = "unknown"
    scan_matches = None
    anchor_active = None
    unspent_at_snapshot = []
    unmatched_inputs = []
    if independent_scan is not None:
        anchor = independent_scan["anchor"]
        anchor_active = (anchor["height"] <= active_tip["height"]
                         and node.cli("getblockhash", str(anchor["height"])) == anchor["blockHash"])
        scan_matches = (presented_snapshot == independent_scan
                        if presented_snapshot is not None else None)
        source = audit.p2pkh_script_from_address(receipt["snapshot"]["address"], version=111)
        if (scan_matches and anchor_active and anchor["height"] < height
                and independent_scan["sourceScript"] == source and byte_check["verdict"] == "PASS"):
            expected = {audit.outpoint(row): row for row in independent_scan["outpoints"]}
            spent = {audit.outpoint(row): row for row in receipt["snapshot"]["outpoints"]}
            unspent_at_snapshot = [expected[key] for key in sorted(expected.keys() - spent.keys())]
            unmatched_inputs = [spent[key] for key in sorted(spent) if spent[key] != expected.get(key)]
            covered = not unspent_at_snapshot and not unmatched_inputs

    in_mempool = txid in node.cli("getrawmempool")
    audit.require(tip(node) == active_tip, "active tip changed during verdict")
    return {
        "paymentConfirmed": confirmed, "inventoryCovered": covered,
        "byteIntegrity": byte_check["verdict"], "recipientScript": fixture.SCRIPT,
        "txid": txid, "paymentBlock": {"blockHash": block_hash, "height": height,
                                      "containsExactTransaction": included, "active": active,
                                      "depth": depth},
        "activeTip": active_tip, "inMempool": in_mempool,
        "snapshotMatchesScan": scan_matches, "snapshotAnchorActive": anchor_active,
        "inventorySats": independent_scan["totalSats"] if independent_scan else None,
        "presentedInventorySats": presented_snapshot["totalSats"] if presented_snapshot else None,
        "inputSats": byte_check.get("input_sum_sats"), "paidSats": byte_check.get("paid_sats"),
        "feeSats": byte_check.get("fee_sats"),
        "omittedInventoryOutpoints": unspent_at_snapshot,
        "omittedInventorySats": (sum(row["value_sats"] for row in unspent_at_snapshot)
                                 if covered != "unknown" else None),
        "unmatchedInputs": unmatched_inputs,
    }


def prepare_payment(node, mine, count):
    source = node.cli("getnewaddress", "", "legacy", wallet="src")
    amounts = [fixture.FUND_SATS + offset for offset in range(7)]
    parents = [node.cli("sendtoaddress", source, fixture.sats_to_btc(amount), wallet="miner")
               for amount in amounts]
    funding_block = node.cli("generatetoaddress", "1", mine)[0]
    snapshot = scan_inventory(node, source)
    audit.require(snapshot["anchor"]["blockHash"] == funding_block
                  and sorted(row["value_sats"] for row in snapshot["outpoints"]) == amounts
                  and {row["txid"] for row in snapshot["outpoints"]} == set(parents),
                  "fixture funding differs from independent scan")
    # Construct the spend from wallet observations, separately from the scan.
    wallet_rows = node.cli("listunspent", "1", "9999999", json.dumps([source]), wallet="src")
    wallet_rows.sort(key=lambda row: row["amount"])
    picked = [{"txid": row["txid"], "vout": row["vout"],
               "value_sats": fixture.btc_to_sats(row["amount"])} for row in wallet_rows[:count]]
    audit.require(len(wallet_rows) == 7 and len(picked) == count, "unexpected fixture wallet inventory")
    inputs = [{"txid": row["txid"], "vout": row["vout"]} for row in picked]
    total = sum(row["value_sats"] for row in picked)
    fee = fixture.DEFAULT_FEE_SATS
    unsigned = node.cli("createrawtransaction", json.dumps(inputs),
                        json.dumps([{fixture.DESTINATION: fixture.sats_to_btc(total - fee)}]))
    signed = node.cli("signrawtransactionwithwallet", unsigned, wallet="src")
    audit.require(signed["complete"], "fixture signing incomplete")
    raw = signed["hex"]
    txid, _, _ = audit.parse_transaction(raw)
    receipt = {
        "schema": audit.VERSION, "network": "regtest", "synthetic": True,
        "recipient": fixture.DESTINATION, "snapshot": {"address": source, "outpoints": picked},
        "tx": {"txid": txid, "raw_hex": raw},
        "prevouts": [{"txid": parent, "raw_hex": node.cli("getrawtransaction", parent, "false", funding_block)}
                     for parent in sorted({row["txid"] for row in picked})],
    }
    audit.require(audit.audit(receipt, "regtest")["verdict"] == "PASS", "fixture byte audit failed")
    admission = node.cli("testmempoolaccept", json.dumps([raw]))[0]
    audit.require(admission["allowed"] and fixture.btc_to_sats(admission["fees"]["base"]) == fee,
                  "fixture admission or fee mismatch")
    audit.require(tip(node) == snapshot["anchor"] and empty_mempool(node) == snapshot["mempool"],
                  "pre-spend snapshot no longer current at broadcast")
    audit.require(node.cli("sendrawtransaction", raw) == txid, "fixture broadcast identity mismatch")
    block_hash = node.cli("generatetoaddress", "2", mine)[0]
    return source, receipt, block_hash, snapshot


def run(node):
    network = node.cli("getnetworkinfo")
    audit.require(network["version"] == 280100 and network["networkactive"] is False
                  and network["connections"] == 0, "unexpected runtime or network state")
    audit.require(audit.p2tr_script_from_address(audit.RECIPIENT) == fixture.SCRIPT
                  == node.cli("validateaddress", fixture.DESTINATION)["scriptPubKey"],
                  "recipient program mismatch")
    for wallet in ("miner", "src"):
        node.cli("createwallet", wallet)
    mine = node.cli("getnewaddress", "", "bech32", wallet="miner")
    node.cli("generatetoaddress", "101", mine)

    cases = {}
    _, receipt, block, partial = prepare_payment(node, mine, 3)
    cases["confirmedPartial"] = observe(node, receipt, block, partial, partial)
    cases["missingSnapshot"] = observe(node, receipt, block, None, None)
    # The narrowed snapshot covers exactly what v1 audited, omitting every
    # unspent output that would make the coverage claim false.
    narrowed = dict(partial, outpoints=sorted(receipt["snapshot"]["outpoints"], key=audit.outpoint))
    narrowed["totalSats"] = sum(row["value_sats"] for row in narrowed["outpoints"])
    cases["narrowedSnapshot"] = observe(node, receipt, block, partial, narrowed)

    source, receipt, block, complete = prepare_payment(node, mine, 7)
    cases["confirmedComplete"] = observe(node, receipt, block, complete, complete)

    deposit_sats = 12_345_678
    deposit = node.cli("sendtoaddress", source, fixture.sats_to_btc(deposit_sats), wallet="miner")
    deposit_block = node.cli("generatetoaddress", "1", mine)[0]
    later = scan_inventory(node, source)
    audit.require(later["anchor"]["blockHash"] == deposit_block and later["totalSats"] == deposit_sats
                  and [row["txid"] for row in later["outpoints"]] == [deposit],
                  "later deposit absent from fresh scan")
    cases["laterDeposit"] = observe(node, receipt, block, complete, complete)

    node.cli("invalidateblock", block)
    cases["paymentRollback"] = observe(node, receipt, block, complete, complete)
    node.cli("invalidateblock", complete["anchor"]["blockHash"])
    cases["snapshotRollback"] = observe(node, receipt, block, complete, complete)

    expectations = {
        "confirmedPartial": (True, False, 2, 150_000_003, 200_000_018),
        "confirmedComplete": (True, True, 2, 350_000_021, 0),
        "missingSnapshot": (True, "unknown", 2, 150_000_003, None),
        "narrowedSnapshot": (True, "unknown", 2, 150_000_003, None),
        "laterDeposit": (True, True, 3, 350_000_021, 0),
        "paymentRollback": (False, True, 0, 350_000_021, 0),
        "snapshotRollback": (False, "unknown", 0, 350_000_021, None),
    }
    for name, (confirmed, covered, depth, total, omitted) in expectations.items():
        result = cases[name]
        audit.require(result["paymentConfirmed"] is confirmed and result["inventoryCovered"] == covered
                      and result["paymentBlock"]["depth"] == depth and result["inputSats"] == total
                      and result["omittedInventorySats"] == omitted and result["unmatchedInputs"] == []
                      and result["feeSats"] == fixture.DEFAULT_FEE_SATS
                      and result["paidSats"] == total - fixture.DEFAULT_FEE_SATS,
                      f"{name}: unexpected verdict, depth or totals")
    audit.require(cases["narrowedSnapshot"]["snapshotMatchesScan"] is False
                  and cases["paymentRollback"]["activeTip"] == complete["anchor"]
                  and cases["paymentRollback"]["inMempool"] is True
                  and cases["snapshotRollback"]["snapshotAnchorActive"] is False,
                  "unexpected snapshot or rollback provenance")
    return {"coreVersion": network["subversion"], "networkActive": network["networkactive"],
            "peerConnections": network["connections"], "cases": cases,
            "scans": {"partial": partial, "complete": complete, "laterDeposit": later},
            "rejectedSnapshot": narrowed}


def main():
    started = time.monotonic()
    with fixture.runtime() as binaries, tempfile.TemporaryDirectory(prefix="inventory-regtest-") as datadir:
        node = fixture.Node(binaries, datadir)
        try:
            node.start()
            evidence = run(node)
        finally:
            node.close()
    print(json.dumps({"component": "inventory-verdict", "objectiveStatus": "INCOMPLETE",
                      "evidence": evidence,
                      "measurements": {"elapsedSeconds": round(time.monotonic() - started, 3)}},
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
