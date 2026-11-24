#!/usr/bin/env python3
"""Read-only offline payment auditor (public records only, stdlib only).

Input JSON (decoded public data):
  tx:       {"txid", "vin":[{"txid","vout"}], "vout":[{"value_sats","script_hex"}]}
  prevouts: [{"txid","vout","value_sats","script_hex","authenticated":true}]
  snapshot: {"address", "outpoints":[{"txid","vout"}]}
Exit 0 = PASS, 1 = FAIL, 2 = bad usage/input file.
Confirmation is never established here: it needs active-chain evidence.
"""
import json, sys, re

PRIZE_ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
RECIPIENT = "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_SATS = 21_000_000 * 100_000_000


def _sha256d(b):
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def p2pkh_script_from_address(addr):
    n = 0
    for ch in addr:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(25, "big")
    if raw[:1] != b"\x00" or _sha256d(raw[:21])[:4] != raw[21:]:
        raise ValueError("bad base58check/mainnet P2PKH address")
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


def p2tr_script_from_address(addr):
    if addr != addr.lower() or not addr.startswith("bc1"):
        raise ValueError("not lowercase mainnet bech32")
    data = [BECH.index(c) for c in addr[4:]]
    hrp = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    if _polymod(hrp + [BECH.index(addr[3])] + data) != 0x2bc830a3:
        raise ValueError("bad bech32m checksum")
    if addr[3] != "p":
        raise ValueError("not witness v1")
    prog = bytes(_convertbits(data[:-6], 5, 8))
    if len(prog) != 32:
        raise ValueError("bad program length")
    return "5120" + prog.hex()


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _is_hex(s):
    return isinstance(s, str) and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", s) is not None


def audit(doc):
    errors = []
    rep = {"input_sum_sats": None, "paid_sats": None, "fee_sats": None}

    def err(m):
        errors.append(m)

    try:
        dest = p2tr_script_from_address(RECIPIENT)
        prize = p2pkh_script_from_address(PRIZE_ADDRESS)
    except ValueError as e:
        return {"verdict": "FAIL", "errors": ["constant address invalid: %s" % e], **rep,
                "confirmation": "NOT ESTABLISHED"}
    tx, prevs, snap = (doc.get(k) if isinstance(doc, dict) else None for k in ("tx", "prevouts", "snapshot"))
    if not (isinstance(tx, dict) and isinstance(prevs, list) and isinstance(snap, dict)):
        return {"verdict": "FAIL", "errors": ["need tx object, prevouts list, snapshot object"], **rep,
                "confirmation": "NOT ESTABLISHED"}
    if snap.get("address") != PRIZE_ADDRESS:
        err("snapshot address is not the prize address")
    vin = tx.get("vin") if isinstance(tx.get("vin"), list) else []
    vout = tx.get("vout") if isinstance(tx.get("vout"), list) else []
    if not vin: err("tx has no inputs")
    if not vout: err("tx has no outputs")

    def key(o):
        if not isinstance(o, dict) or not isinstance(o.get("txid"), str) or not HEX64.match(o["txid"]) \
                or not _is_int(o.get("vout")) or o["vout"] < 0:
            return None
        return (o["txid"], o["vout"])

    # snapshot
    expected = []
    for o in snap.get("outpoints") if isinstance(snap.get("outpoints"), list) else []:
        k = key(o)
        if k is None: err("malformed snapshot outpoint")
        else: expected.append(k)
    if not expected: err("snapshot has no outpoints")
    if len(set(expected)) != len(expected): err("duplicate outpoint in snapshot")
    # inputs
    spent = []
    for o in vin:
        k = key(o)
        if k is None: err("malformed input outpoint")
        else: spent.append(k)
    dups = {k for k in spent if spent.count(k) > 1}
    for k in sorted(dups): err("duplicate input %s:%d" % k)
    for k in sorted(set(expected) - set(spent)): err("expected prize outpoint missing from inputs %s:%d" % k)
    for k in sorted(set(spent) - set(expected)): err("extra input not in prize snapshot %s:%d" % k)
    # prevouts
    pmap = {}
    for p in prevs:
        k = key(p)
        if k is None: err("malformed prevout record"); continue
        if k in pmap: err("duplicate prevout record %s:%d" % k); continue
        pmap[k] = p
    total = 0
    ok_sum = True
    for k in sorted(set(spent)):
        p = pmap.get(k)
        if p is None:
            err("missing prevout record %s:%d" % k); ok_sum = False; continue
        if p.get("authenticated") is not True:
            err("prevout %s:%d not marked authenticated" % k); ok_sum = False
        v = p.get("value_sats")
        if not _is_int(v) or v <= 0 or v > MAX_SATS:
            err("missing/invalid prevout value %s:%d" % k); ok_sum = False
        else:
            total += v
        if not _is_hex(p.get("script_hex")) or p["script_hex"] != prize:
            err("prevout script inconsistent with prize address %s:%d" % k); ok_sum = False
    # outputs
    pay = [o for o in vout if isinstance(o, dict) and o.get("script_hex") == dest]
    if len(vout) != 1: err("expected exactly one output, found %d" % len(vout))
    if len(pay) != 1: err("expected exactly one output paying recipient script, found %d" % len(pay))
    paid = None
    for o in vout:
        if not isinstance(o, dict) or not _is_int(o.get("value_sats")) or not _is_hex(o.get("script_hex")):
            err("malformed output")
            return _fin(errors, rep, ok_sum, total, None)
    if len(pay) == 1:
        paid = pay[0]["value_sats"]
        if paid <= 0: err("nonpositive payment")
    return _fin(errors, rep, ok_sum, total, paid)


def _fin(errors, rep, ok_sum, total, paid):
    if ok_sum and total > 0:
        rep["input_sum_sats"] = total
    if paid is not None:
        rep["paid_sats"] = paid
    if rep["input_sum_sats"] is not None and paid is not None:
        rep["fee_sats"] = total - paid
        if rep["fee_sats"] < 0:
            errors.append("outputs exceed inputs (negative fee)")
    return {"verdict": "FAIL" if errors else "PASS", "errors": errors, **rep,
            "confirmation": "NOT ESTABLISHED: requires active-chain evidence (block inclusion, depth, no reorg)"}


def main(argv):
    if len(argv) != 2:
        print("usage: audit.py RECORDS.json", file=sys.stderr); return 2
    try:
        with open(argv[1]) as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print("cannot read input: %s" % e, file=sys.stderr); return 2
    r = audit(doc)
    print(json.dumps(r, indent=2))
    return 0 if r["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
