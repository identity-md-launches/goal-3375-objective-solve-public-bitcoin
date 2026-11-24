"""Canonical manifests and local Bitcoin address checks (no chain queries)."""

import hashlib
import json
import re
from .secp256k1 import N, decode, encode, multiply

PUBLIC_KEY = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
RECIPIENT = "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx"
LOWER = 1 << 139
UPPER = (1 << 140) - 1
PRODUCTION = {
    "schema": "kangaroo-manifest@1", "network": "bitcoin-mainnet",
    "label": "bitcoin-puzzle-140", "mode": "real",
    "publicKey": PUBLIC_KEY, "address": ADDRESS,
    "lower": str(LOWER), "upper": str(UPPER), "recipient": RECIPIENT,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decimal(value):
    if type(value) is not str or len(value) > 160 or not re.fullmatch(r"0|-?[1-9][0-9]*", value):
        raise ValueError("noncanonical decimal")
    return int(value)


def identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("invalid identifier")
    return value


def p2pkh(public_key):
    payload = b"\0" + hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, digit = divmod(n, 58)
        out = alphabet[digit] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * zeros + out


def validate_recipient(address):
    """Validate the exact mainnet v1/32-byte Bech32m recipient."""
    if type(address) is not str or address != address.lower() or not 8 <= len(address) <= 90:
        raise ValueError("invalid recipient")
    hrp, separator, tail = address.rpartition("1")
    if separator != "1" or hrp != "bc" or len(tail) < 7:
        raise ValueError("invalid recipient")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    try:
        values = [alphabet.index(c) for c in tail]
    except ValueError:
        raise ValueError("invalid recipient") from None
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for value in expanded + values:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                checksum ^= generator
    if checksum != 0x2bc830a3 or values[0] != 1:
        raise ValueError("invalid recipient checksum or version")
    accumulator = bits = 0
    program = bytearray()
    for value in values[1:-6]:
        accumulator = ((accumulator << 5) | value) & 0xfff
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 255)
    if bits >= 5 or ((accumulator << (8 - bits)) & 255) or len(program) != 32:
        raise ValueError("invalid recipient padding or length")
    return bytes(program)


def validate_manifest(manifest):
    if type(manifest) is not dict or set(manifest) != set(PRODUCTION):
        raise ValueError("invalid manifest schema")
    if manifest["schema"] != "kangaroo-manifest@1":
        raise ValueError("invalid manifest schema")
    lo, hi = decimal(manifest["lower"]), decimal(manifest["upper"])
    if not 1 <= lo <= hi < N:
        raise ValueError("invalid inclusive interval")
    text = manifest["publicKey"]
    if type(text) is not str or not re.fullmatch(r"0[23][0-9a-f]{64}", text):
        raise ValueError("invalid public key")
    point = decode(bytes.fromhex(text))
    if manifest["mode"] == "real":
        if manifest != PRODUCTION or p2pkh(encode(point)) != ADDRESS:
            raise ValueError("production manifest mismatch")
        validate_recipient(RECIPIENT)
    elif manifest["mode"] == "synthetic":
        if (manifest["network"] != "synthetic" or manifest["address"] is not None
                or manifest["recipient"] is not None or not manifest["label"].startswith("synthetic-")):
            raise ValueError("invalid synthetic label")
        if text == PUBLIC_KEY or hi - lo + 1 > (1 << 24):
            raise ValueError("synthetic challenge not permitted")
    else:
        raise ValueError("invalid mode")
    return point, lo, hi


def synthetic_manifest(lower, width, position, seed, ops=None):
    """Only generated, explicitly labelled small-range challenges reach this path."""
    identifier(seed)
    if type(width) is not int or not 1 <= width <= (1 << 24):
        raise ValueError("synthetic width out of bounds")
    if type(lower) is not int or not 1 <= lower <= N - width:
        raise ValueError("synthetic lower bound out of bounds")
    if position == "lower":
        offset = 0
    elif position == "upper":
        offset = width - 1
    elif position == "middle":
        offset = width // 2
    elif position == "seeded":
        offset = int.from_bytes(hashlib.sha256(b"synthetic-key@1:" + seed.encode()).digest(), "big") % width
    else:
        raise ValueError("invalid synthetic position")
    known = lower + offset
    manifest = {
        "schema": "kangaroo-manifest@1", "network": "synthetic",
        "label": "synthetic-generated", "mode": "synthetic",
        "publicKey": encode(multiply(known, ops=ops)).hex(), "address": None,
        "lower": str(lower), "upper": str(lower + width - 1), "recipient": None,
    }
    validate_manifest(manifest)
    return manifest, known
