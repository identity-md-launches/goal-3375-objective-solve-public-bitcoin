#!/usr/bin/env python3
"""Offline Bitcoin payment auditor for public transaction bytes."""
import argparse
import json
import re
import sys

PRIZE_ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
RECIPIENT = "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_SATS = 21_000_000 * 100_000_000


def _sha256d(b):
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def p2pkh_script_from_address(addr, version=0):
    if not isinstance(addr, str) or not 26 <= len(addr) <= 35:
        raise ValueError("invalid P2PKH address length")
    n = 0
    for ch in addr:
        n = n * 58 + B58.index(ch)
    leading = len(addr) - len(addr.lstrip("1"))
    raw = bytes(leading) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 25 or raw[0] != version or _sha256d(raw[:21])[:4] != raw[21:]:
        raise ValueError("bad Base58Check P2PKH address")
    return "76a914" + raw[1:21].hex() + "88ac"


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _convertbits(data, frm, to):
    acc = bits = 0
    out = []
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if bits >= frm or ((acc << (to - bits)) & ((1 << to) - 1)):
        raise ValueError("bad padding")
    return out


def p2tr_script_from_address(addr, hrp="bc"):
    if not isinstance(addr, str) or len(addr) != len(hrp) + 60:
        raise ValueError("invalid Taproot address length")
    if addr != addr.lower() or not addr.startswith(hrp + "1p"):
        raise ValueError("invalid lowercase Taproot address for network")
    data = [BECH.index(c) for c in addr[len(hrp) + 1:]]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _polymod(expanded + data) != 0x2bc830a3:
        raise ValueError("bad Bech32m checksum")
    prog = bytes(_convertbits(data[1:-6], 5, 8))
    if len(prog) != 32:
        raise ValueError("bad program length")
    return "5120" + prog.hex()


VERSION = "receipt-check/v1"
MAX_FEE_SATS = 100_000
MAX_TX_WEIGHT = 4_000_000
NULL_OUTPOINT = ("00" * 32, 0xffffffff)


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, raw):
        self.raw = raw
        self.pos = 0

    def read(self, size):
        end = self.pos + size
        require(end <= len(self.raw), "truncated transaction")
        start, self.pos = self.pos, end
        return self.raw[start:end]

    def uint(self, size):
        return int.from_bytes(self.read(size), "little")

    def compact(self, minimum_bytes=1):
        tag = self.uint(1)
        if tag < 253:
            value = tag
        else:
            size, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 2**32)}[tag]
            value = self.uint(size)
            require(value >= minimum, "noncanonical CompactSize")
        require(value <= (len(self.raw) - self.pos) // minimum_bytes,
                "CompactSize exceeds remaining transaction bytes")
        return value

    def vector(self):
        return self.read(self.compact())


def parse_transaction(raw_hex):
    require(isinstance(raw_hex, str) and 0 < len(raw_hex) <= 2 * MAX_TX_WEIGHT
            and len(raw_hex) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", raw_hex),
            "invalid raw transaction hex")
    raw = bytes.fromhex(raw_hex)
    reader = Reader(raw)
    version = reader.read(4)
    witness = raw[4:5] == b"\x00"
    if witness:
        require(reader.read(2) == b"\x00\x01", "invalid SegWit marker/flags")
    body_start = reader.pos
    inputs = []
    for _ in range(reader.compact(41)):
        inputs.append((reader.read(32)[::-1].hex(), reader.uint(4)))
        script_sig = reader.vector()
        if inputs[-1] == NULL_OUTPOINT:
            require(2 <= len(script_sig) <= 100, "invalid coinbase script length")
        reader.read(4)
    require(inputs, "transaction has no inputs")
    require(len(inputs) == len(set(inputs)), "duplicate input")
    require(NULL_OUTPOINT not in inputs or len(inputs) == 1, "invalid null input")
    outputs = []
    for _ in range(reader.compact(9)):
        value = reader.uint(8)
        require(value <= MAX_SATS, "output value exceeds money range")
        outputs.append((value, reader.vector().hex()))
    require(outputs, "transaction has no outputs")
    require(sum(value for value, _ in outputs) <= MAX_SATS, "output sum exceeds money range")
    body_end = reader.pos
    if witness:
        nonempty = False
        for _ in inputs:
            items = reader.compact()
            nonempty |= items > 0
            for _ in range(items):
                reader.vector()
        require(nonempty, "superfluous witness serialization")
    locktime = reader.read(4)
    require(reader.pos == len(raw), "trailing transaction bytes")
    stripped = version + raw[body_start:body_end] + locktime
    require(len(stripped) * 3 + len(raw) <= MAX_TX_WEIGHT, "transaction exceeds weight limit")
    return _sha256d(stripped)[::-1].hex(), inputs, outputs


def fields(obj, *names):
    require(isinstance(obj, dict) and obj.keys() == set(names),
            "expected object fields: " + ", ".join(names))


def txid(value):
    require(isinstance(value, str) and HEX64.fullmatch(value), "invalid txid")
    return value


def outpoint(record):
    index = record["vout"]
    require(type(index) is int and 0 <= index <= 0xffffffff, "invalid output index")
    return txid(record["txid"]), index


def checked_transaction(record):
    claimed = txid(record["txid"])
    actual, inputs, outputs = parse_transaction(record["raw_hex"])
    require(actual == claimed, f"raw txid mismatch for {claimed}")
    return inputs, outputs


def check(doc, mode):
    if (mode == "regtest" and isinstance(doc, dict) and "schema" not in doc
            and doc.get("network") == "regtest" and doc.get("synthetic") is True):
        raise ValueError("insufficient evidence: legacy regtest receipt lacks raw spend, "
                         "raw funding and a valued snapshot; supply a regtest v1 receipt")
    fields(doc, "schema", "network", "synthetic", "recipient", "snapshot", "tx", "prevouts")
    require(doc["schema"] == VERSION, "unsupported receipt schema")
    require(doc["network"] == ("regtest" if mode == "regtest" else "mainnet"),
            "receipt network does not match audit mode")
    require(doc["synthetic"] is (mode != "mainnet"), "synthetic label does not match audit mode")

    snap = doc["snapshot"]
    fields(snap, "address", "outpoints")
    if mode == "regtest":
        source = p2pkh_script_from_address(snap["address"], version=111)
        dest = p2tr_script_from_address(doc["recipient"], hrp="bcrt")
    else:
        require(snap["address"] == PRIZE_ADDRESS, "wrong fixed snapshot address")
        require(doc["recipient"] == RECIPIENT, "wrong fixed recipient address")
        source = p2pkh_script_from_address(PRIZE_ADDRESS)
        dest = p2tr_script_from_address(RECIPIENT)

    require(isinstance(snap["outpoints"], list) and snap["outpoints"], "empty or invalid snapshot")
    expected = {}
    for record in snap["outpoints"]:
        fields(record, "txid", "vout", "value_sats")
        key = outpoint(record)
        value = record["value_sats"]
        require(key not in expected, "duplicate snapshot outpoint")
        require(type(value) is int and 0 < value <= MAX_SATS, "invalid snapshot amount")
        expected[key] = value

    fields(doc["tx"], "txid", "raw_hex")
    spent, outputs = checked_transaction(doc["tx"])
    require(NULL_OUTPOINT not in spent, "coinbase cannot be a payment")
    require(set(spent) == expected.keys(), "input set differs from snapshot")
    require(isinstance(doc["prevouts"], list), "invalid prevout transactions")
    funding = {}
    for record in doc["prevouts"]:
        fields(record, "txid", "raw_hex")
        _, funding_outputs = checked_transaction(record)
        require(record["txid"] not in funding, "duplicate funding transaction")
        funding[record["txid"]] = funding_outputs
    require(funding.keys() == {key[0] for key in spent}, "funding transaction set differs from inputs")
    total = 0
    for parent, index in spent:
        require(index < len(funding[parent]), "prevout index out of range")
        value, script = funding[parent][index]
        require(value == expected[parent, index], "indexed prevout amount differs from snapshot")
        require(script == source, "indexed prevout script differs from source")
        total += value
    require(total <= MAX_SATS, "input sum exceeds money range")
    require(len(outputs) == 1, "expected exactly one output")
    paid, script = outputs[0]
    require(script == dest, "output does not pay recipient script")
    require(paid > 0, "nonpositive payment")
    fee = total - paid
    require(fee >= 0, "negative fee")
    require(fee <= MAX_FEE_SATS, "excessive fee")
    return {"txid": doc["tx"]["txid"], "input_sum_sats": total, "paid_sats": paid, "fee_sats": fee}


def audit(doc, mode="mainnet"):
    result = {"mode": mode, "unspent_status": "NOT ESTABLISHED",
              "confirmation": "NOT ESTABLISHED", "byte_integrity": "FAIL",
              "verdict": "FAIL", "errors": []}
    try:
        require(mode in ("mainnet", "synthetic", "regtest"), "invalid audit mode")
        result.update(check(doc, mode))
    except ValueError as exc:
        result["errors"].append(str(exc))
        if str(exc).startswith("insufficient evidence:"):
            result["byte_integrity"] = result["verdict"] = "INSUFFICIENT"
    else:
        result["byte_integrity"] = result["verdict"] = "PASS"
    return result


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("mainnet", "synthetic", "regtest"), default="mainnet")
    parser.add_argument("receipt")
    args = parser.parse_args()
    try:
        with open(args.receipt, encoding="utf-8") as stream:
            doc = json.load(stream, object_pairs_hook=unique_json_object, parse_constant=reject_constant)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"cannot read receipt: {exc}", file=sys.stderr)
        return 2
    result = audit(doc, args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
