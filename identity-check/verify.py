#!/usr/bin/env python3
"""Offline validation of the fixed public manifest; no secret inputs or network I/O.

The CLI reads no files, stdin, environment variables, or network resources.
The library helpers accept public encodings only. See README.md for limitations.
"""

import hashlib
import json
import re
import sys

PUBLIC_KEY = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
CHALLENGE_ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
RECIPIENT = "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx"
FIELD = 2**256 - 2**32 - 977
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M = 0x2BC830A3


class InvalidPublicInput(ValueError):
    """A public encoding failed validation; messages never echo input."""


def compressed_point(sec_hex):
    """Decode strict compressed SEC and check the secp256k1 curve equation.

    The curve has cofactor 1, so every finite on-curve point is in its
    prime-order subgroup. Compressed SEC cannot encode the point at infinity.
    """
    if not isinstance(sec_hex, str) or re.fullmatch(r"[0-9a-fA-F]{66}", sec_hex) is None:
        raise InvalidPublicInput("compressed SEC must be exactly 33 hexadecimal bytes")
    sec = bytes.fromhex(sec_hex)
    if sec[0] not in (2, 3):
        raise InvalidPublicInput("compressed SEC prefix must be 02 or 03")
    x = int.from_bytes(sec[1:], "big")
    if x >= FIELD:
        raise InvalidPublicInput("SEC x coordinate is outside the field")
    rhs = (pow(x, 3, FIELD) + 7) % FIELD
    y = pow(rhs, (FIELD + 1) // 4, FIELD)
    if y * y % FIELD != rhs:
        raise InvalidPublicInput("SEC x coordinate has no curve point")
    if y % 2 != sec[0] % 2:
        y = (-y) % FIELD
    if y % 2 != sec[0] % 2:
        raise InvalidPublicInput("SEC y parity is impossible")
    return x, y


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def base58check_encode(payload):
    raw = payload + double_sha256(payload)[:4]
    number = int.from_bytes(raw, "big")
    result = ""
    while number:
        number, digit = divmod(number, 58)
        result = BASE58[digit] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def p2pkh_payload(address):
    """Return HASH160 only after mainnet P2PKH Base58Check validation."""
    if not isinstance(address, str) or not 26 <= len(address) <= 35:
        raise InvalidPublicInput("P2PKH address length is invalid")
    number = 0
    for char in address:
        if char not in BASE58:
            raise InvalidPublicInput("invalid Base58 character")
        number = number * 58 + BASE58.index(char)
    raw = (b"\0" * (len(address) - len(address.lstrip("1")))
           + number.to_bytes((number.bit_length() + 7) // 8, "big"))
    if len(raw) != 25:
        raise InvalidPublicInput("P2PKH decoded length must be 25 bytes")
    if double_sha256(raw[:-4])[:4] != raw[-4:]:
        raise InvalidPublicInput("Base58Check checksum mismatch")
    if raw[0] != 0:
        raise InvalidPublicInput("address is not mainnet P2PKH (version 00)")
    if base58check_encode(raw[:-4]) != address:
        raise InvalidPublicInput("noncanonical Base58Check encoding")
    return raw[1:21]


def derive_p2pkh(sec_hex):
    compressed_point(sec_hex)
    sha = hashlib.sha256(bytes.fromhex(sec_hex)).digest()
    try:
        digest = hashlib.new("ripemd160", sha).digest()
    except ValueError as exc:
        raise RuntimeError("Python hashlib RIPEMD-160 support is required") from exc
    return base58check_encode(b"\0" + digest), digest


def polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    state = 1
    for value in values:
        top = state >> 25
        state = ((state & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                state ^= generator
    return state


def decode_bech32m(address):
    """Decode generic Bech32m, including case, alphabet, and length checks."""
    if not isinstance(address, str) or not 8 <= len(address) <= 90:
        raise InvalidPublicInput("Bech32m length must be 8 through 90 characters")
    if any(not 33 <= ord(c) <= 126 for c in address):
        raise InvalidPublicInput("Bech32m characters must be printable ASCII")
    if address.lower() != address and address.upper() != address:
        raise InvalidPublicInput("Bech32m mixed case is forbidden")
    address = address.lower()
    separator = address.rfind("1")
    if separator < 1 or len(address) - separator - 1 < 6:
        raise InvalidPublicInput("Bech32m separator or checksum length is invalid")
    hrp = address[:separator]
    tail = address[separator + 1:]
    if any(c not in BECH32 for c in tail):
        raise InvalidPublicInput("invalid Bech32m data character")
    values = [BECH32.index(c) for c in tail]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if polymod(expanded + values) != BECH32M:
        raise InvalidPublicInput("Bech32m checksum mismatch")
    return hrp, values[:-6]


def recipient_program(address):
    """Require mainnet Bech32m, witness v1, exactly 32 bytes, strict padding."""
    hrp, data = decode_bech32m(address)
    if hrp != "bc":
        raise InvalidPublicInput("recipient must use mainnet HRP bc")
    if not data or data[0] != 1:
        raise InvalidPublicInput("recipient must use witness version 1")
    accumulator = bits = 0
    program = bytearray()
    for value in data[1:]:
        accumulator = ((accumulator << 5) | value) & 0xFFF
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 255)
    if bits >= 5 or ((accumulator << (8 - bits)) & 255):
        raise InvalidPublicInput("noncanonical witness program padding")
    if len(program) != 32:
        raise InvalidPublicInput("recipient witness program must be 32 bytes")
    return bytes(program)


def p2pkh_script(digest):
    if len(digest) != 20:
        raise InvalidPublicInput("P2PKH HASH160 must be 20 bytes")
    return "76a914" + digest.hex() + "88ac"


def verify_manifest(public_key=PUBLIC_KEY, challenge_address=CHALLENGE_ADDRESS,
                    recipient=RECIPIENT):
    """Validate public fields independently; CLI always uses the fixed defaults."""
    checks = {}
    scripts = {"challenge_p2pkh": None, "derived_key_p2pkh": None,
               "recipient_witness_v1": None}

    def check(name, operation):
        try:
            value = operation()
        except (InvalidPublicInput, RuntimeError) as exc:
            checks[name] = {"status": "FAIL", "detail": str(exc)}
            return None
        checks[name] = {"status": "PASS"}
        return value

    point = check("compressed_sec_point", lambda: compressed_point(public_key))
    digest = check("challenge_mainnet_p2pkh", lambda: p2pkh_payload(challenge_address))
    if digest is not None:
        scripts["challenge_p2pkh"] = p2pkh_script(digest)
    derived_address = None
    if point is not None:
        derived = check("public_key_hash160", lambda: derive_p2pkh(public_key))
        if derived is not None:
            derived_address, key_digest = derived
            scripts["derived_key_p2pkh"] = p2pkh_script(key_digest)
    else:
        checks["public_key_hash160"] = {"status": "SKIP", "detail": "invalid SEC point"}
    if derived_address is None or digest is None:
        checks["public_key_address_match"] = {"status": "SKIP", "detail": "prerequisite failed"}
    else:
        checks["public_key_address_match"] = {
            "status": "PASS" if derived_address == challenge_address else "FAIL"}
    program = check("recipient_mainnet_bech32m_v1_32", lambda: recipient_program(recipient))
    if program is not None:
        scripts["recipient_witness_v1"] = "5120" + program.hex()
    lower, upper = 2**139, 2**140 - 1
    checks["interval_scalar_bounds"] = {
        "status": "PASS" if 1 <= lower <= upper < ORDER else "FAIL",
        "detail": "bounds only; private-key membership is not established"}
    return {
        "schema_version": 1,
        "manifest": {"compressed_public_key": public_key,
                     "challenge_address": challenge_address, "recipient": recipient},
        "checks": checks,
        "overall": "PASS" if all(c["status"] == "PASS" for c in checks.values()) else "FAIL",
        "derived_mainnet_p2pkh_address": derived_address,
        "scripts_hex": scripts,
        "interval": {"lower_inclusive_hex": hex(lower), "upper_inclusive_hex": hex(upper),
                     "candidate_count_decimal": str(upper - lower + 1)},
        "not_verified": ["public challenge provenance", "private-key interval membership",
                         "current UTXOs or spendable prize", "recipient control",
                         "private-key recovery", "prize payment"],
        "goal_status": "INCOMPLETE",
    }


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args == ["--help"]:
        print("Usage: python3 verify.py\nVerify the fixed public manifest offline; emits JSON.")
        return 0
    if args:
        # Do not echo unknown arguments: this interface accepts no input secrets.
        print("No inputs accepted; use no arguments or --help.", file=sys.stderr)
        return 2
    report = verify_manifest()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
