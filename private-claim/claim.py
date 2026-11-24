"""Entrant-local claim workflow. Default operation prepares without broadcasting."""
import argparse
import base64
from decimal import Decimal, ROUND_CEILING
import http.client
import json
import os
import re
import resource
import sys
from urllib.parse import urlsplit

from bitcoin import (
    MAX_MONEY, ClaimError, base58check, check_scriptsig, p2pkh, parse_tx,
    public_key, recipient_script, require, unsigned_claim,
)

SOURCE = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
PUBKEY = bytes.fromhex("031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640")
RECIPIENT = "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx"
SYNTHETIC_RECIPIENT = "bcrt1pccz8l9zpa47k6vz9gphftsrumpw80rjt3nhnefat4symjhrsnmjsgkm3r6"
LOW, HIGH = 2**139, 2**140 - 1
COIN = 100_000_000
HEX_ID = re.compile(r"[0-9a-f]{64}")


def read_fd(fd, limit):
    require(fd >= 0, "invalid private descriptor")
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "private descriptor exceeds permitted length")
    return data


class Core:
    def __init__(self, endpoint, auth):
        url = urlsplit(endpoint)
        require(url.scheme == "http" and url.hostname in ("127.0.0.1", "::1")
                and url.port and url.netloc in (f"127.0.0.1:{url.port}", f"[::1]:{url.port}")
                and url.path in ("", "/") and not url.query and not url.fragment,
                "RPC must be an explicit loopback HTTP endpoint with a port")
        user, sep, password = auth.partition(b":")
        require(sep and user and password and all(33 <= b <= 126 for b in auth),
                "RPC auth FD must contain printable username:password without newline")
        self.host, self.port = url.hostname, url.port
        self.authorization = "Basic " + base64.b64encode(auth).decode("ascii")

    def __call__(self, method, *args):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=900)
        try:
            request = json.dumps({"jsonrpc": "2.0", "id": "claim", "method": method, "params": args})
            conn.request("POST", "/", request, {"Authorization": self.authorization,
                                               "Content-Type": "application/json"})
            response = conn.getresponse()
            require(response.status == 200, "RPC HTTP failure")
            reply = json.loads(response.read(), parse_float=Decimal)
            require(reply["id"] == "claim" and reply.get("error") is None, "RPC returned an error")
            return reply["result"]
        except Exception:
            # Core error messages and network errors may quote private request data.
            raise ClaimError(f"RPC failed ({method}); details withheld") from None
        finally:
            conn.close()


def sats(value):
    require(isinstance(value, (int, Decimal)) and not isinstance(value, bool),
            "expected numeric BTC value")
    amount = Decimal(value) * COIN
    require(amount.is_finite() and 0 <= amount <= MAX_MONEY
            and amount == amount.to_integral_value(), "invalid BTC amount")
    return int(amount)


def btc(n):
    return f"{n // COIN}.{n % COIN:08d}"


def outpoint(row):
    txid, index = row["txid"], row["vout"]
    require(HEX_ID.fullmatch(txid) and type(index) is int and 0 <= index < 0xFFFFFFFF,
            "invalid outpoint")
    return txid, index


class Claim:
    def __init__(self, rpc, synthetic=False):
        self.rpc = rpc
        self.synthetic = synthetic
        self.chain = "regtest" if synthetic else "main"
        self.pubkey = public_key(1) if synthetic else PUBKEY
        self.source_script = p2pkh(self.pubkey)
        self.source = base58check(bytes([111 if synthetic else 0]) + self.source_script[3:23])
        require(synthetic or self.source == SOURCE, "fixed public key and address mismatch")
        self.recipient = SYNTHETIC_RECIPIENT if synthetic else RECIPIENT
        self.output_script = recipient_script(self.recipient, "bcrt" if synthetic else "bc")
        self.descriptor = f"raw({self.source_script.hex()})"

    def check_node(self):
        status = self.rpc("getblockchaininfo")
        require(status["chain"] == self.chain, "unexpected Bitcoin Core network")
        require(status["initialblockdownload"] is False and status["blocks"] == status["headers"],
                "Bitcoin Core is still syncing")
        require(self.rpc("getindexinfo", "txindex").get("txindex", {}).get("synced") is True,
                "synced Bitcoin Core txindex required")

    def check_candidate(self, data):
        require(len(data) == 32, "candidate must contain exactly 32 bytes")
        scalar = int.from_bytes(data, "big")
        lower, upper = (1, 1) if self.synthetic else (LOW, HIGH)
        require(lower <= scalar <= upper, "candidate outside required interval")
        derived = public_key(scalar)
        version = bytes([111 if self.synthetic else 0])
        require(derived == self.pubkey
                and base58check(version + p2pkh(derived)[3:23]) == self.source,
                "candidate public key or source address mismatch")

    def raw_prevout(self, point):
        txid, index = point
        raw = parse_tx(bytes.fromhex(self.rpc("getrawtransaction", txid, False)))
        require(raw.txid == txid and index < len(raw.outputs), "raw prevout identity mismatch")
        amount, script = raw.outputs[index]
        require(script == self.source_script, "raw prevout script mismatch")
        return amount

    def snapshot(self):
        scan = self.rpc("scantxoutset", "start", [self.descriptor])
        require(scan["success"] is True, "confirmed UTXO scan unavailable")
        tip = scan["bestblock"]
        require(self.rpc("getbestblockhash") == tip, "chain moved during UTXO scan; retry")
        sequence = self.mempool_sequence()
        activity = self.rpc("getdescriptoractivity", [], [self.descriptor], True)["activity"]
        spent = {(row["prevout_txid"], row["prevout_vout"]) for row in activity
                 if row["type"] == "spend"}
        pending = [row for row in activity if row["type"] == "receive"]
        available = {}
        seen = set()
        for row in scan["unspents"] + pending:
            point = outpoint(row)
            require(point not in seen, "duplicate discovered outpoint")
            seen.add(point)
            if point in spent:
                continue
            live = self.rpc("gettxout", *point, True)
            require(live is not None and live["bestblock"] == tip, "prize UTXO changed; retry")
            require(live["scriptPubKey"]["hex"] == self.source_script.hex(),
                    "unspent output script mismatch")
            require(not live["coinbase"] or live["confirmations"] >= 100,
                    "immature prize output; retry after maturity")
            amount = self.raw_prevout(point)
            require(amount == sats(row["amount"]) == sats(live["value"]),
                    "inconsistent prevout value")
            available[point] = amount
        self.check_snapshot(tip, sequence)
        require(available and 0 < sum(available.values()) <= MAX_MONEY, "no spendable prize funds")
        return available, tip, sequence

    def mempool_sequence(self):
        return self.rpc("getrawmempool", False, True)["mempool_sequence"]

    def check_snapshot(self, tip, sequence):
        require(self.mempool_sequence() == sequence and self.rpc("getbestblockhash") == tip,
                "chain or mempool moved; retry")

    def fee_rate(self, target, regtest_rate):
        estimate = self.rpc("estimatesmartfee", target, "CONSERVATIVE")
        if "feerate" in estimate:
            estimated = sats(estimate["feerate"])
        else:
            require(self.synthetic and regtest_rate is not None,
                    "Bitcoin Core has no fee estimate for this target")
            estimated = regtest_rate
        require(estimated > 0, "invalid fee estimate")
        policy = self.rpc("getmempoolinfo")
        return max(estimated, sats(policy["mempoolminfee"]), sats(policy["minrelaytxfee"]))

    def checked_claim(self, tx, selected, cap):
        require(tx.version == 2 and tx.locktime == 0 and not tx.witness,
                "unexpected claim transaction header")
        points = [(txid, index) for txid, index, _, _ in tx.inputs]
        require(len(points) == len(selected) and set(points) == set(selected),
                "claim inputs differ from selected prize inputs")
        for _, _, script, sequence in tx.inputs:
            require(sequence == 0xFFFFFFFF, "unexpected input sequence")
            check_scriptsig(script, self.pubkey)
        require(len(tx.outputs) == 1 and tx.outputs[0][1] == self.output_script,
                "claim must pay one output to the fixed recipient")
        amount = tx.outputs[0][0]
        fee = sum(selected.values()) - amount
        require(amount > 0 and 0 < fee <= cap, "claim fee or payment violates entrant policy")
        return fee

    def prepare(self, candidate, cap, target, regtest_rate, broadcast):
        self.check_candidate(candidate)
        self.check_node()
        selected, _, _ = self.snapshot()
        total = sum(selected.values())
        rate = self.fee_rate(target, regtest_rate)
        points = sorted(selected)
        prevouts = [{"txid": txid, "vout": index, "scriptPubKey": self.source_script.hex(),
                     "amount": btc(selected[txid, index])} for txid, index in points]
        wif = base58check(bytes([239 if self.synthetic else 128]) + candidate + b"\x01")
        # Start at one satoshi and use the signed size to find the required fee.
        fee = 1
        for _ in range(8):
            require(fee <= cap and fee < total, "required fee exceeds cap or available funds")
            unsigned = unsigned_claim(points, total - fee, self.output_script)
            signed = self.rpc("signrawtransactionwithkey", unsigned, [wif], prevouts, "ALL")
            require(signed["complete"] is True, "Bitcoin Core did not fully sign")
            raw = signed["hex"]
            tx = parse_tx(bytes.fromhex(raw))
            require(self.checked_claim(tx, selected, cap) == fee
                    and tx.outputs[0][0] == total - fee, "signer changed payment or fee")
            required = (rate * tx.vsize + 999) // 1000
            if fee >= required:
                break
            fee = required
        else:
            raise ClaimError("could not settle the signed transaction fee")

        current, tip, sequence = self.snapshot()
        require(current == selected, "prize UTXO set changed; retry")
        require(fee * 1000 >= self.fee_rate(target, regtest_rate) * tx.vsize,
                "fee policy changed; retry")
        max_rate = btc((fee * 1000 + tx.vsize - 1) // tx.vsize)
        accepted, = self.rpc("testmempoolaccept", [raw], max_rate)
        require(accepted.get("allowed") is True and accepted["txid"] == tx.txid
                and accepted["vsize"] == tx.vsize and sats(accepted["fees"]["base"]) == fee,
                "mempool acceptance or transaction accounting failed")
        self.check_snapshot(tip, sequence)
        receipt = self.receipt(tx, selected, fee)
        if broadcast:
            # Print the expected ID first so an ambiguous transport failure
            # can be resolved by verification without resending.
            emit(dict(receipt, status="broadcast_attempt"))
            require(self.rpc("sendrawtransaction", raw, max_rate, "0") == tx.txid,
                    "unexpected broadcast transaction ID")
        return dict(receipt, status="broadcast_pending" if broadcast else "prepared")

    def receipt(self, tx, selected, fee):
        return {"chain": self.chain, "txid": tx.txid, "recipient": self.recipient,
                "inputs": len(selected), "inputSats": sum(selected.values()),
                "paymentSats": tx.outputs[0][0], "feeSats": fee, "vsize": tx.vsize}

    def verify(self, txid, cap, depth):
        self.check_node()
        result = self.rpc("getrawtransaction", txid, True)
        block = result.get("blockhash")
        require(block and result.get("confirmations", 0) >= depth,
                "transaction has insufficient active-chain confirmations")
        tx = parse_tx(bytes.fromhex(result["hex"]))
        require(tx.txid == txid, "confirmed transaction ID mismatch")
        points = {(parent, index) for parent, index, _, _ in tx.inputs}
        selected = {point: self.raw_prevout(point) for point in sorted(points)}
        fee = self.checked_claim(tx, selected, cap)
        tip = self.rpc("getbestblockhash")
        chain_block = self.rpc("getblock", block, 1)
        require(chain_block["hash"] == block and txid in chain_block["tx"],
                "transaction missing from reported block")
        require(chain_block["confirmations"] >= depth
                and self.rpc("getblockhash", chain_block["height"]) == block
                and self.rpc("getbestblockhash") == tip, "active chain changed or depth insufficient")
        return dict(self.receipt(tx, selected, fee), status="confirmed",
                    blockHash=block, confirmations=chain_block["confirmations"])


def positive(value):
    if not value.isascii() or not value.isdecimal() or int(value) <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return int(value)


def emit(receipt):
    print(json.dumps(receipt, sort_keys=True), flush=True)


def main(synthetic=False):
    parser = argparse.ArgumentParser(description="Synthetic regtest claim" if synthetic
                                     else "Entrant-local Bitcoin Puzzle #140 claim")
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--rpc-auth-fd", required=True, type=int)
    parser.add_argument("--max-fee-sats", required=True, type=positive)
    modes = parser.add_subparsers(dest="mode", required=True)
    claim_parser = modes.add_parser("claim")
    claim_parser.add_argument("--candidate-fd", required=True, type=int)
    claim_parser.add_argument("--fee-target", required=True, type=positive)
    claim_parser.add_argument("--broadcast", action="store_true")
    if synthetic:
        claim_parser.add_argument("--synthetic-fee-sat-per-kvb", type=positive)
    verify_parser = modes.add_parser("verify")
    verify_parser.add_argument("--txid", required=True)
    verify_parser.add_argument("--confirmations", required=True, type=positive)
    args = parser.parse_args()
    candidate_fd = getattr(args, "candidate_fd", None)
    fds = {args.rpc_auth_fd}
    if candidate_fd is not None:
        fds.add(candidate_fd)

    def consume(fd, limit):
        data = read_fd(fd, limit)
        fds.remove(fd)
        return data

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        require(candidate_fd != args.rpc_auth_fd, "RPC auth and candidate FDs must be distinct")
        require(all(fd >= 3 for fd in fds), "use dedicated private descriptors numbered 3 or higher")
        require(args.max_fee_sats < MAX_MONEY, "fee cap is out of range")
        if args.mode == "claim":
            require(2 <= args.fee_target <= 1008, "fee target must be between 2 and 1008")
        else:
            require(HEX_ID.fullmatch(args.txid), "invalid transaction ID")
        rpc = Core(args.rpc_url, consume(args.rpc_auth_fd, 4096))
        claim = Claim(rpc, synthetic)
        if args.mode == "claim":
            candidate = consume(candidate_fd, 32)
            emit(claim.prepare(candidate, args.max_fee_sats, args.fee_target,
                               getattr(args, "synthetic_fee_sat_per_kvb", None), args.broadcast))
        else:
            emit(claim.verify(args.txid, args.max_fee_sats, args.confirmations))
        return 0
    except ClaimError as error:
        print(f"Claim stopped. {error}", file=sys.stderr)
    except (Exception, KeyboardInterrupt):
        print("Claim stopped. Local or RPC data error; details withheld.", file=sys.stderr)
    finally:
        for fd in fds:
            if fd >= 3:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
