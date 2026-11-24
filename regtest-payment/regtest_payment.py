#!/usr/bin/env python3
"""Bitcoin Core regtest payment fixture (SYNTHETIC test data only).

Starts a fresh disposable regtest bitcoind (peer networking disabled), creates
run-only wallets, funds a legacy P2PKH output, spends it to one Taproot (P2TR)
destination less a fixed fee, signs inside the Core wallet, mines one block and
verifies input, output script, paid sats and fee from the tx and its prevout.
Writes a public JSON receipt (no keys, no wallet files).

Usage: regtest_payment.py --bindir DIR [--receipt PATH] [--fee-sats N]
Standard library only; needs local executables bitcoind and bitcoin-cli.
"""
import argparse, json, os, shutil, socket, subprocess, sys, tempfile, time
from decimal import Decimal

SAT = Decimal("100000000")
FUND_SATS = 50_000_000
DEFAULT_FEE_SATS = 1_000


def btc_to_sats(v):
    d = Decimal(str(v)) * SAT
    if d != d.to_integral_value():
        raise ValueError("sub-satoshi amount: %r" % v)
    return int(d)


def sats_to_btc(s):
    return format(Decimal(s) / SAT, ".8f")


def assert_regtest_chain(info):
    """Raise unless getblockchaininfo reports chain == regtest."""
    if not isinstance(info, dict) or info.get("chain") != "regtest":
        raise RuntimeError("REFUSING: node is not regtest (chain=%r)" %
                           (info.get("chain") if isinstance(info, dict) else info))


def check_spend(tx, prevout_txid, prevout_vout, prevout_spk_type, dest_spk_hex,
                in_sats, out_sats):
    """Verify decoded tx: one exact input, one P2TR output paying dest."""
    errs = []
    if len(tx["vin"]) != 1:
        errs.append("expected 1 input")
    else:
        vi = tx["vin"][0]
        if vi.get("txid") != prevout_txid or vi.get("vout") != prevout_vout:
            errs.append("input is not the funded prevout")
    if prevout_spk_type != "pubkeyhash":
        errs.append("prevout is not P2PKH: %s" % prevout_spk_type)
    if len(tx["vout"]) != 1:
        errs.append("expected exactly 1 output")
    else:
        spk = tx["vout"][0]["scriptPubKey"]
        if spk.get("type") != "witness_v1_taproot":
            errs.append("output is not taproot")
        if spk.get("hex") != dest_spk_hex:
            errs.append("output script mismatch")
        if btc_to_sats(tx["vout"][0]["value"]) != out_sats:
            errs.append("paid sats mismatch")
    if in_sats - out_sats <= 0:
        errs.append("non-positive fee")
    return errs


def validate_receipt(r):
    req = {"synthetic", "network", "txid", "blockhash", "height", "depth",
           "input_sats", "paid_sats", "fee_sats"}
    missing = req - set(r)
    if missing:
        return ["missing: %s" % sorted(missing)]
    errs = []
    if r["network"] != "regtest": errs.append("network not regtest")
    if r["synthetic"] is not True: errs.append("not labelled synthetic")
    if r["input_sats"] - r["paid_sats"] != r["fee_sats"]: errs.append("amounts inconsistent")
    if r["depth"] < 1: errs.append("unconfirmed")
    blob = json.dumps(r).lower()
    for bad in ("privkey", "wif", "xprv", "tprv", "seed", "wallet.dat"):
        if bad in blob: errs.append("private marker in receipt: " + bad)
    return errs


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Node:
    def __init__(self, bindir, datadir, port):
        self.bindir, self.datadir, self.port = bindir, datadir, port
        self.base = [os.path.join(bindir, "bitcoin-cli"), "-regtest",
                     "-datadir=" + datadir, "-rpcport=%d" % port]

    def cli(self, *args, wallet=None, check_chain=True):
        if check_chain and args[0] != "getblockchaininfo":
            assert_regtest_chain(self.cli("getblockchaininfo"))
        cmd = list(self.base) + (["-rpcwallet=" + wallet] if wallet else []) + list(args)
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode:
            raise RuntimeError("bitcoin-cli %s failed: %s" % (args[0], out.stderr.strip()))
        t = out.stdout.strip()
        try:
            return json.loads(t, parse_float=Decimal)
        except ValueError:
            return t


def run(bindir, receipt_path, fee_sats):
    datadir = tempfile.mkdtemp(prefix="regtest-payment-")
    port = free_port()
    d = [os.path.join(bindir, "bitcoind"), "-regtest", "-datadir=" + datadir,
         "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-networkactive=0",
         "-upnp=0", "-natpmp=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
         "-rpcport=%d" % port, "-fallbackfee=0.0001", "-txindex=1", "-daemon=0",
         "-printtoconsole=0"]
    proc = subprocess.Popen(d, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    n = Node(bindir, datadir, port)
    try:
        for _ in range(120):
            try:
                info = n.cli("getblockchaininfo"); break
            except RuntimeError:
                if proc.poll() is not None:
                    raise RuntimeError("bitcoind exited: " + proc.stderr.read().decode())
                time.sleep(0.5)
        else:
            raise RuntimeError("bitcoind RPC never came up")
        assert_regtest_chain(info)
        if info["blocks"] != 0:
            raise RuntimeError("datadir not fresh")
        ni = n.cli("getnetworkinfo")
        if ni.get("networkactive") or ni.get("connections"):
            raise RuntimeError("peer networking not disabled")
        for w in ("miner", "src", "dest"):
            n.cli("createwallet", w)
        mine_addr = n.cli("getnewaddress", "", "bech32", wallet="miner")
        n.cli("generatetoaddress", "101", mine_addr)
        p2pkh = n.cli("getnewaddress", "", "legacy", wallet="src")
        fund_txid = n.cli("sendtoaddress", p2pkh, sats_to_btc(FUND_SATS), wallet="miner")
        n.cli("generatetoaddress", "1", mine_addr)
        fund_tx = n.cli("getrawtransaction", fund_txid, "true")
        vout = next(o["n"] for o in fund_tx["vout"]
                    if o["scriptPubKey"].get("address") == p2pkh)
        prev = fund_tx["vout"][vout]
        in_sats = btc_to_sats(prev["value"])
        taproot = n.cli("getnewaddress", "", "bech32m", wallet="dest")
        dest_spk = n.cli("getaddressinfo", taproot, wallet="dest")["scriptPubKey"]
        out_sats = in_sats - fee_sats
        raw = n.cli("createrawtransaction",
                    json.dumps([{"txid": fund_txid, "vout": vout}]),
                    json.dumps([{taproot: sats_to_btc(out_sats)}]))
        signed = n.cli("signrawtransactionwithwallet", raw, wallet="src")
        if not signed.get("complete"):
            raise RuntimeError("signing incomplete")
        accept = n.cli("testmempoolaccept", json.dumps([signed["hex"]]))[0]
        if not accept.get("allowed"):
            raise RuntimeError("mempool reject: %s" % accept.get("reject-reason"))
        txid = n.cli("sendrawtransaction", signed["hex"])
        bh = n.cli("generatetoaddress", "1", mine_addr)[0]
        tx = n.cli("getrawtransaction", txid, "true", bh)
        errs = check_spend(tx, fund_txid, vout, prev["scriptPubKey"]["type"],
                           dest_spk, in_sats, out_sats)
        fee_core = btc_to_sats(n.cli("getrawtransaction", txid, "2", bh)["fee"])
        if fee_core != fee_sats: errs.append("core fee %d != %d" % (fee_core, fee_sats))
        if errs: raise RuntimeError("verification failed: %s" % errs)
        blk = n.cli("getblockheader", bh)
        receipt = {
            "synthetic": True,
            "note": "SYNTHETIC regtest fixture; disposable wallets; not mainnet",
            "network": n.cli("getblockchaininfo")["chain"],
            "core_version": ni.get("subversion"),
            "funding_txid": fund_txid, "funding_vout": vout,
            "funding_script_type": prev["scriptPubKey"]["type"],
            "txid": txid, "blockhash": bh, "height": blk["height"],
            "depth": blk["confirmations"],
            "destination_script_type": "witness_v1_taproot",
            "destination_script_hex": dest_spk,
            "input_sats": in_sats, "paid_sats": out_sats, "fee_sats": fee_sats,
            "vsize": tx["vsize"],
        }
        bad = validate_receipt(receipt)
        if bad: raise RuntimeError("receipt invalid: %s" % bad)
        with open(receipt_path, "w") as f:
            json.dump(receipt, f, indent=2); f.write("\n")
        print(json.dumps(receipt, indent=2))
        return 0
    finally:
        try: n.cli("stop", check_chain=False)
        except Exception: pass
        try: proc.wait(30)
        except Exception: proc.kill()
        shutil.rmtree(datadir, ignore_errors=True)  # wallets never leave tmp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bindir", required=True)
    ap.add_argument("--receipt", default="regtest-receipt.json")
    ap.add_argument("--fee-sats", type=int, default=DEFAULT_FEE_SATS)
    a = ap.parse_args()
    try:
        return run(a.bindir, a.receipt, a.fee_sats)
    except Exception as e:
        print("ERROR: %s" % e, file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
