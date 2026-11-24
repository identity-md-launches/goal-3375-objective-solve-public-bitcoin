#!/usr/bin/env python3
"""Offline acceptance: landed private claim, real Core, and public receipt checks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for directory in (HERE, ROOT / "receipt-check"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import audit
import claim_receipt as cr
import verify_receipt as vr


class CheckError(Exception):
    pass


def require(ok, message):
    if not ok:
        raise CheckError(message)


def subprocess_gate(name, command):
    run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=150)
    require(run.returncode == 0, name + " failed (exit " + str(run.returncode) + "): "
            + (run.stderr + run.stdout)[-800:])
    return {"name": name, "exitCode": run.returncode, "tail": (run.stdout + run.stderr)[-200:]}


def changed_payment(receipt, amount):
    """Change signed raw output bytes, preserving syntax, to test byte policy."""
    doc = copy.deepcopy(receipt)
    reader = vr.Reader(bytes.fromhex(doc["tx"]["raw_hex"]))
    reader.take(4)
    for _ in range(reader.compact()):
        reader.take(32 + 4)
        reader.varbytes()
        reader.take(4)
    require(reader.compact() == 1, "unexpected source output count")
    position = reader.pos
    raw = bytearray.fromhex(doc["tx"]["raw_hex"])
    raw[position:position + 8] = amount.to_bytes(8, "little")
    doc["tx"]["raw_hex"] = raw.hex()
    doc["tx"]["txid"] = audit._sha256d(raw)[::-1].hex()
    return doc


def mutation_gate(receipt, evidence):
    def rejects(doc, message, mode="regtest"):
        answer = audit.audit(doc, mode)
        require(answer["verdict"] == "FAIL" and message in " ".join(answer["errors"]),
                "malformed " + message + " receipt was accepted")

    doc = copy.deepcopy(receipt)
    doc["snapshot"]["outpoints"][0]["value_sats"] += 1
    rejects(doc, "amount differs")
    doc = copy.deepcopy(receipt)
    doc["snapshot"]["outpoints"][0]["vout"] += 20
    rejects(doc, "input set differs")
    doc = copy.deepcopy(receipt)
    doc["network"] = "mainnet"
    rejects(doc, "network")
    rejects(receipt, "network", "mainnet")
    paid = evidence["claim_cli"]["inputSats"] - audit.MAX_FEE_SATS - 1
    rejects(changed_payment(receipt, paid), "excessive fee")
    doc = copy.deepcopy(receipt)
    doc["prevouts"] = []
    rejects(doc, "funding transaction set")
    doc = copy.deepcopy(receipt)
    doc["tx"]["raw_hex"] = doc["tx"]["raw_hex"][:-2] + "01"
    rejects(doc, "raw txid mismatch")
    proof = copy.deepcopy(evidence)
    proof["depth"] = 1
    try:
        cr.verify_chain(receipt, proof)
    except cr.IntegrationError:
        pass
    else:
        raise CheckError("tampered active-chain depth accepted")
    proof = copy.deepcopy(evidence)
    proof["receipt_sha256"] = "00" * 32
    try:
        cr.verify_chain(receipt, proof)
    except cr.IntegrationError:
        pass
    else:
        raise CheckError("tampered receipt digest accepted")
    return 9


def signal_gate(directory):
    results = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        work = directory / ("signal-" + str(sig))
        work.mkdir()
        receipt, evidence, ready = (work / name for name in ("receipt.json", "evidence.json", "ready.json"))
        command = [sys.executable, "-I", "-B", str(HERE / "claim_receipt.py"),
                   "--receipt", str(receipt), "--evidence", str(evidence),
                   "--work-root", str(work), "--hold-at", "funded", "--ready", str(ready)]
        proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 25
            while proc.poll() is None and not ready.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            require(ready.exists(), "receipt runner did not reach funded phase")
            state = json.loads(ready.read_text())
            require(Path(state["datadir"]).exists(), "disposable node absent before signal")
            proc.send_signal(sig)
            out, err = proc.communicate(timeout=20)
            require(proc.returncode == 130 and not receipt.exists() and not evidence.exists(),
                    "receipt runner published after signal: " + err[-120:])
            require(not Path(state["datadir"]).exists(), "disposable datadir survived signal")
            try:
                os.kill(state["node_pid"], 0)
            except ProcessLookupError:
                pass
            else:
                raise CheckError("Core process survived signal")
            require("candidate" not in out.lower(), "private material mentioned in signal output")
            results.append(int(sig))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    return results


def main():
    started = time.monotonic()
    gates = []
    for name, command in (
        ("runtime-hashes", [sys.executable, "-B", str(HERE / "verify_runtime.py")]),
        ("receipt-check-suite", [sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", "receipt-check/tests", "-v"]),
        ("regtest-payment-suite", [sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", "regtest-payment/tests", "-v"]),
        ("private-claim-suite", [sys.executable, "-I", "-B", str(ROOT / "private-claim/check_core.py")]),
    ):
        gates.append(subprocess_gate(name, command))
    with tempfile.TemporaryDirectory(prefix="claim-acceptance-") as tmp:
        directory = Path(tmp)
        receipt, evidence = cr.generate(directory)
        outcome = cr.verify_chain(receipt, evidence)
        require(outcome["byte_integrity"] == "PASS" and outcome["confirmation"] == "NOT ESTABLISHED"
                and outcome["unspent_status"] == "NOT ESTABLISHED", "byte policy conflated with chain evidence")
        mutation_count = mutation_gate(receipt, evidence)
        signals = signal_gate(directory)
    # The delivered receipt is a fixed public example. The live run above is
    # independent and ephemeral, so it cannot silently replace that evidence.
    delivered = json.loads((HERE / "claim_receipt.json").read_text())
    delivered_evidence = json.loads((HERE / "claim_evidence.json").read_text())
    cr.verify_chain(delivered, delivered_evidence)
    require(audit.audit(delivered, "mainnet")["verdict"] == "FAIL", "delivered regtest passed mainnet")
    summary = {"component": "receipt-integration", "objectiveStatus": "INCOMPLETE",
               "gate": "PASS", "backend": "Bitcoin Core 28.1 regtest",
               "gates": gates, "real_backend_synthetic": True, "regtest": True,
               "mock": False, "production": "NOT RUN", "mutations_rejected": mutation_count,
               "signals_cleaned": signals, "receipt_sha256": delivered_evidence["receipt_sha256"],
               "input_sats": delivered_evidence["claim_cli"]["inputSats"],
               "paid_sats": delivered_evidence["claim_cli"]["paymentSats"],
               "fee_sats": delivered_evidence["claim_cli"]["feeSats"],
               "depth": delivered_evidence["depth"],
               "elapsed_seconds": round(time.monotonic() - started, 3)}
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({"component": "receipt-integration", "gate": "FAIL",
                          "error": type(exc).__name__ + ": " + str(exc),
                          "objectiveStatus": "INCOMPLETE"}), file=sys.stderr)
        sys.exit(1)
