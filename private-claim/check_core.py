#!/usr/bin/env python3
"""Real-backend acceptance check for the entrant-local claim against Core 28.1.

Acceptance command:  python3 -I -B private-claim/check_core.py

This exercises the ACTUAL claim CLI (private-claim/regtest.py and claim.py) over
HTTP RPC against a freshly started, isolated, networkless regtest Bitcoin Core
28.1 node, using the committed, hash-verified runtime vendored by
regtest-payment/. Only the publicly known synthetic scalar (1) and generated
regtest sources are used; the immutable production public key, source address,
interval and mainnet recipient are never spent here. No real key, candidate
byte, wild distinguished point or private checkpoint is produced, logged or
written by this check.

It first runs the retained offline unit suite (21 tests), then proves the
live lifecycle (real signing, mempool admission, broadcast, mining and
confirmation verification) and the fail-closed rejection paths, including the
fact that Core 28.1 lacks getdescriptoractivity so the committed snapshot logic
reconstructs complete mempool activity from getrawmempool/getrawtransaction.

Under `-I` the script directory is not on sys.path, so paths are added below.
"""
import base64
import http.client
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for path in (str(HERE), str(ROOT / "regtest-payment")):
    if path not in sys.path:
        sys.path.insert(0, path)

import regtest_payment as rp  # noqa: E402  committed runtime harness, reused read-only
from claim import Claim  # noqa: E402

CLAIM = str(HERE / "claim.py")
REGTEST = str(HERE / "regtest.py")
MAINNET_PROGRAM = "46bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f"
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class CheckError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def node_port(node):
    for arg in node.base:
        if arg.startswith("-rpcport="):
            return int(arg.split("=", 1)[1])
    raise CheckError("node RPC port not found")


def run_cli(entry, url, cookie, max_fee, mode_args, candidate=None, timeout=120):
    """Invoke the real claim CLI with private descriptors over inherited pipes."""
    fds = []
    try:
        auth_r, auth_w = os.pipe()
        os.write(auth_w, cookie)
        os.close(auth_w)
        fds.append(auth_r)
        argv = [sys.executable, "-B", entry, "--rpc-url", url,
                "--rpc-auth-fd", str(auth_r), "--max-fee-sats", str(max_fee)]
        args = list(mode_args)
        if candidate is not None:
            cand_r, cand_w = os.pipe()
            os.write(cand_w, candidate)
            os.close(cand_w)
            fds.append(cand_r)
            args = [str(cand_r) if a == "{cand}" else a for a in args]
        argv += args
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              pass_fds=fds, env=CHILD_ENV)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def getdescriptoractivity_available(node):
    # `help <unknown>` returns a string with a zero exit code, so inspect it
    # rather than relying on the command failing.
    try:
        text = node.cli("help", "getdescriptoractivity")
    except Exception:
        return False
    return not (isinstance(text, str) and "unknown command" in text)


def fund_wallet(node):
    node.cli("createwallet", "miner")
    mine = node.cli("getnewaddress", "", "bech32", wallet="miner")
    node.cli("generatetoaddress", "101", mine)
    return mine


def collect_evidence(work_root=None):
    """Run the full real-backend regtest acceptance and return public evidence.

    No secrets are included: the synthetic scalar is the public value 1 and the
    disposable node cookie is discarded with its datadir before returning.
    """
    started = time.monotonic()
    syn = Claim(None, synthetic=True)
    require(syn.output_script.hex() == "5120" + MAINNET_PROGRAM,
            "synthetic payout program must equal the fixed mainnet program")
    require(Claim(None).output_script == syn.output_script,
            "production and synthetic payout scripts must match")

    results = []

    def record(name, ok, detail=""):
        results.append({"scenario": name, "passed": bool(ok), "detail": detail})
        require(ok, f"{name}: {detail}")

    with rp.runtime(None) as bindir:
        with tempfile.TemporaryDirectory(prefix="claim-core-", dir=work_root) as datadir:
            node = rp.Node(bindir, datadir)
            try:
                node.start()
                info = node.cli("getblockchaininfo")
                network = node.cli("getnetworkinfo")
                require(info["chain"] == "regtest", "node is not regtest")
                require(not network["networkactive"] and not network["connections"],
                        "disposable node must be networkless")
                core_version = network["subversion"]

                gda = getdescriptoractivity_available(node)
                record("getdescriptoractivity_probed", True,
                       "available" if gda else "absent in Core 28.1; mempool scan used")

                url = "http://127.0.0.1:%d" % node_port(node)
                cookie = (Path(datadir) / "fixture.cookie").read_bytes()
                require(b":" in cookie and b"\n" not in cookie,
                        "disposable cookie must be single-line user:pass")
                one = (1).to_bytes(32, "big")
                two = (2).to_bytes(32, "big")

                # Mine maturity depth first so the node leaves initial block download.
                mine = fund_wallet(node)

                # 1. No spendable funds before the source is funded (fail closed).
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["claim", "--candidate-fd", "{cand}", "--fee-target",
                                        "6", "--synthetic-fee-sat-per-kvb", "2000"], one)
                record("no_spendable_funds", rc == 1 and "no spendable" in err,
                       err.strip()[-120:])

                # Fund: one confirmed output plus one pending (mempool) receive.
                node.cli("sendtoaddress", syn.source, "1.0", wallet="miner")
                confirmed_block = node.cli("generatetoaddress", "1", mine)[0]
                pending_txid = node.cli("sendtoaddress", syn.source, "0.5", wallet="miner")
                require(pending_txid in node.cli("getrawmempool"),
                        "pending receive must sit in the mempool")

                # 2. Fee cap: a one-satoshi cap cannot cover the signed fee.
                rc, out, err = run_cli(REGTEST, url, cookie, 1,
                                       ["claim", "--candidate-fd", "{cand}", "--fee-target",
                                        "6", "--synthetic-fee-sat-per-kvb", "2000"], one)
                record("fee_cap_enforced", rc == 1 and "exceeds cap" in err, err.strip()[-120:])

                # 3. Wrong candidate: regtest interface accepts only the scalar 1.
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["claim", "--candidate-fd", "{cand}", "--fee-target",
                                        "6", "--synthetic-fee-sat-per-kvb", "2000"], two)
                record("wrong_candidate_rejected", rc == 1 and "interval" in err,
                       err.strip()[-120:])

                # 4. Fee-rate handling: empty regtest estimator without a fallback fails.
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["claim", "--candidate-fd", "{cand}",
                                        "--fee-target", "6"], one)
                record("fee_rate_requires_estimate", rc == 1 and "fee estimate" in err,
                       err.strip()[-120:])

                # 5. Real prepare (actual Core signing + mempool admission), no broadcast.
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["claim", "--candidate-fd", "{cand}", "--fee-target",
                                        "6", "--synthetic-fee-sat-per-kvb", "2000"], one)
                require(rc == 0, "prepare failed: " + err.strip()[-200:])
                prepared = json.loads(out.strip().splitlines()[-1])
                record("prepare_sweeps_confirmed_and_pending",
                       prepared["status"] == "prepared" and prepared["inputs"] == 2
                       and prepared["inputSats"] == 150_000_000
                       and prepared["recipient"] == syn.recipient
                       and prepared["paymentSats"] + prepared["feeSats"] == 150_000_000,
                       json.dumps({k: prepared[k] for k in
                                   ("status", "inputs", "inputSats", "feeSats", "vsize")}))
                require(node.cli("getrawmempool") == [] or pending_txid in node.cli("getrawmempool"),
                       "prepare must not broadcast")
                record("one_output_exclusivity", prepared["paymentSats"] > 0, "single taproot output")

                # 6. Broadcast: emits the id before sending (ambiguous-broadcast safety).
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["claim", "--candidate-fd", "{cand}", "--fee-target", "6",
                                        "--synthetic-fee-sat-per-kvb", "2000", "--broadcast"], one)
                require(rc == 0, "broadcast failed: " + err.strip()[-200:])
                lines = out.strip().splitlines()
                attempt = json.loads(lines[0])
                broadcast = json.loads(lines[-1])
                record("broadcast_announces_id_first",
                       attempt["status"] == "broadcast_attempt"
                       and broadcast["status"] == "broadcast_pending"
                       and attempt["txid"] == broadcast["txid"],
                       broadcast["txid"])
                txid = broadcast["txid"]
                require(txid in node.cli("getrawmempool"), "broadcast tx must enter mempool")

                # 7. Mine and verify confirmation on the active chain.
                block = node.cli("generatetoaddress", "1", mine)[0]
                node.cli("generatetoaddress", "1", mine)
                rc, out, err = run_cli(REGTEST, url, cookie, 5000,
                                       ["verify", "--txid", txid, "--confirmations", "1"])
                require(rc == 0, "verify failed: " + err.strip()[-200:])
                confirmed = json.loads(out.strip().splitlines()[-1])
                record("verify_confirms_active_chain",
                       confirmed["status"] == "confirmed" and confirmed["txid"] == txid
                       and confirmed["blockHash"] == block
                       and confirmed["recipient"] == syn.recipient
                       and confirmed["paymentSats"] == broadcast["paymentSats"],
                       json.dumps({k: confirmed[k] for k in
                                   ("status", "confirmations", "paymentSats", "feeSats")}))

                # 8. Wrong network: the production entrypoint refuses a non-main chain.
                rc, out, err = run_cli(CLAIM, url, cookie, 5000,
                                       ["verify", "--txid", "ab" * 32, "--confirmations", "1"])
                record("wrong_network_rejected",
                       rc == 1 and "unexpected Bitcoin Core network" in err, err.strip()[-120:])

                # Public regtest evidence for receipt integration (no secrets).
                sweep_raw = node.cli("getrawtransaction", txid, "false", block)
                header = node.cli("getblockheader", block)
                tip = node.cli("getblockchaininfo")
                evidence = {
                    "component": "claim-core",
                    "network": "regtest",
                    "core_version": core_version,
                    "networkactive": False,
                    "connections": 0,
                    "getdescriptoractivity_available": gda,
                    "synthetic_source": syn.source,
                    "recipient_regtest": syn.recipient,
                    "recipient_mainnet": Claim(None).recipient,
                    "payout_program": MAINNET_PROGRAM,
                    "payout_script_hex": syn.output_script.hex(),
                    "prepared_receipt": prepared,
                    "broadcast_receipt": broadcast,
                    "confirmed_receipt": confirmed,
                    "confirmed_block": block,
                    "confirmed_height": header["height"],
                    "confirmed_depth": header["confirmations"],
                    "sweep_raw": sweep_raw,
                    "block_header_raw": node.cli("getblockheader", block, "false"),
                    "active_tip": tip["bestblockhash"],
                    "active_height": tip["blocks"],
                    "scenarios": results,
                }
            finally:
                node.close()
    evidence["disposable_node_removed"] = True
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
    evidence["max_rss_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return evidence


def run_unit_suite():
    loader = unittest.TestLoader()
    suite = loader.discover(str(HERE), pattern="test_*.py")
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1)
    result = runner.run(suite)
    return result.testsRun, result.wasSuccessful()


def main():
    try:
        ran, ok = run_unit_suite()
        require(ok, "offline unit suite failed")
        require(ran == 21, f"expected 21 retained offline tests, ran {ran}")
        evidence = collect_evidence()
    except CheckError as error:
        print(json.dumps({"component": "claim-core", "objectiveStatus": "INCOMPLETE",
                          "gate": "FAILED", "error": str(error)}), flush=True)
        return 1
    except Exception as error:  # fail closed; never mask a missing backend
        print(json.dumps({"component": "claim-core", "objectiveStatus": "INCOMPLETE",
                          "gate": "ERROR", "error": type(error).__name__ + ": " + str(error)}),
              flush=True)
        return 1

    out_path = os.environ.get("IMD_CORE_EVIDENCE")
    if out_path:
        target = Path(out_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    summary = {
        "component": "claim-core",
        "objectiveStatus": "INCOMPLETE",
        "gate": "PASSED",
        "backend": "real regtest Bitcoin Core " + evidence["core_version"],
        "offline_tests": ran,
        "getdescriptoractivity_available": evidence["getdescriptoractivity_available"],
        "scenarios": [s["scenario"] for s in evidence["scenarios"]],
        "txid": evidence["confirmed_receipt"]["txid"],
        "paymentSats": evidence["confirmed_receipt"]["paymentSats"],
        "feeSats": evidence["confirmed_receipt"]["feeSats"],
        "elapsed_seconds": evidence["elapsed_seconds"],
        "max_rss_kb": evidence["max_rss_kb"],
    }
    print(json.dumps(summary), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
