"""Minimal Bitcoin encodings for verifying a single-purpose claim."""
from dataclasses import dataclass
import hashlib
from io import BytesIO

MAX_MONEY = 21_000_000 * 100_000_000
P = 2**256 - 2**32 - 977
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class ClaimError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ClaimError(message)


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# RIPEMD-160 constants (per the reference specification).
_RMD_R = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
_RMD_RP = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
_RMD_S = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
_RMD_SP = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
_RMD_K = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_KP = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _ripemd160_pure(message):
    """Self-contained RIPEMD-160 used when the platform OpenSSL omits it."""
    def rol(value, count):
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    def mix(round_index, x, y, z):
        if round_index < 16:
            return x ^ y ^ z
        if round_index < 32:
            return (x & y) | (~x & 0xFFFFFFFF & z)
        if round_index < 48:
            return (x | (~y & 0xFFFFFFFF)) ^ z
        if round_index < 64:
            return (x & z) | (y & (~z & 0xFFFFFFFF))
        return x ^ (y | (~z & 0xFFFFFFFF))

    bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = message + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += bit_length.to_bytes(8, "little")
    h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    for offset in range(0, len(padded), 64):
        words = [int.from_bytes(padded[offset + 4 * i:offset + 4 * i + 4], "little")
                 for i in range(16)]
        a, b, c, d, e = h0, h1, h2, h3, h4
        ap, bp, cp, dp, ep = h0, h1, h2, h3, h4
        for j in range(80):
            t = (rol((a + mix(j, b, c, d) + words[_RMD_R[j]] + _RMD_K[j // 16])
                     & 0xFFFFFFFF, _RMD_S[j]) + e) & 0xFFFFFFFF
            a, e, d, c, b = e, d, rol(c, 10), b, t
            t = (rol((ap + mix(79 - j, bp, cp, dp) + words[_RMD_RP[j]] + _RMD_KP[j // 16])
                     & 0xFFFFFFFF, _RMD_SP[j]) + ep) & 0xFFFFFFFF
            ap, ep, dp, cp, bp = ep, dp, rol(cp, 10), bp, t
        t = (h1 + c + dp) & 0xFFFFFFFF
        h1 = (h2 + d + ep) & 0xFFFFFFFF
        h2 = (h3 + e + ap) & 0xFFFFFFFF
        h3 = (h4 + a + bp) & 0xFFFFFFFF
        h4 = (h0 + b + cp) & 0xFFFFFFFF
        h0 = t
    return b"".join(word.to_bytes(4, "little") for word in (h0, h1, h2, h3, h4))


def _ripemd160(data):
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return _ripemd160_pure(data)


def hash160(data):
    return _ripemd160(hashlib.sha256(data).digest())


def base58check(payload):
    data = payload + hash256(payload)[:4]
    value = int.from_bytes(data, "big")
    result = ""
    while value:
        value, digit = divmod(value, 58)
        result = BASE58[digit] + result
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + result


def add_points(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    numerator, denominator = (3 * x * x, 2 * y) if left == right else (v - y, u - x)
    slope = numerator * pow(denominator, -1, P) % P
    result_x = (slope * slope - x - u) % P
    return result_x, (slope * (x - result_x) - y) % P


def public_key(scalar):
    point, power = None, G
    while scalar:
        if scalar & 1:
            point = add_points(point, power)
        power = add_points(power, power)
        scalar >>= 1
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def p2pkh(pubkey):
    return b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"


def recipient_script(address, network_hrp="bc"):
    hrp, data = address.rsplit("1", 1)
    require(hrp == network_hrp and len(data) == 59 and data[0] == "p",
            "invalid Taproot recipient for this network")
    require(all(c in BASE32 for c in data), "invalid recipient encoding")
    digits = [BASE32.index(c) for c in data]
    polymod = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for digit in expanded + digits:
        high = polymod >> 25
        polymod = ((polymod & 0x1FFFFFF) << 5) ^ digit
        for index, generator in enumerate(generators):
            if high & (1 << index):
                polymod ^= generator
    require(polymod == 0x2BC830A3, "invalid recipient checksum")
    program = 0
    for digit in digits[1:-6]:
        program = (program << 5) | digit
    require(program & 15 == 0, "invalid recipient padding")
    return b"\x51\x20" + (program >> 4).to_bytes(32, "big")


def little(n, size):
    return n.to_bytes(size, "little")


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + little(n, 2)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + little(n, 4)
    return b"\xff" + little(n, 8)


def vector(data):
    return compact(len(data)) + data


@dataclass(frozen=True)
class Tx:
    txid: str
    version: int
    inputs: tuple
    outputs: tuple
    locktime: int
    witness: bool
    vsize: int


def parse_tx(raw):
    require(10 <= len(raw) <= 4_000_000, "invalid raw transaction size")
    stream = BytesIO(raw)

    def take(n):
        require(n <= len(raw) - stream.tell(), "truncated transaction")
        return stream.read(n)

    def number(size):
        return int.from_bytes(take(size), "little")

    def count():
        start = stream.tell()
        tag = number(1)
        size = {253: 2, 254: 4, 255: 8}.get(tag)
        result = number(size) if size else tag
        require(stream.tell() - start == len(compact(result)), "noncanonical compact size")
        require(result <= len(raw) - stream.tell(), "invalid compact size")
        return result

    version = number(4)
    witness = raw[4:6] == b"\x00\x01"
    if witness:
        take(2)
    body_start = stream.tell()
    inputs = tuple((take(32)[::-1].hex(), number(4), take(count()), number(4))
                   for _ in range(count()))
    outputs = tuple((number(8), take(count())) for _ in range(count()))
    body_end = stream.tell()
    require(inputs and outputs and sum(amount for amount, _ in outputs) <= MAX_MONEY,
            "invalid transaction inputs or outputs")
    if witness:
        has_stack = False
        for _ in inputs:
            items = count()
            has_stack |= items > 0
            for _ in range(items):
                take(count())
        require(has_stack, "empty witness serialization")
    locktime = number(4)
    require(stream.tell() == len(raw), "trailing transaction bytes")
    stripped = raw[:4] + raw[body_start:body_end] + raw[-4:]
    vsize = (len(stripped) * 3 + len(raw) + 3) // 4
    return Tx(hash256(stripped)[::-1].hex(), version, inputs, outputs, locktime, witness, vsize)


def unsigned_claim(outpoints, amount, script):
    inputs = b"".join(bytes.fromhex(txid)[::-1] + little(index, 4) + b"\x00\xff\xff\xff\xff"
                      for txid, index in outpoints)
    return (little(2, 4) + compact(len(outpoints)) + inputs + b"\x01"
            + little(amount, 8) + vector(script) + little(0, 4)).hex()


def check_scriptsig(script, pubkey):
    # P2PKH has two direct pushes: a DER signature plus SIGHASH_ALL, then the key.
    require(len(script) >= 2, "missing P2PKH signature")
    length = script[0]
    require(9 <= length <= 73 and script[1] == 0x30 and script[2] == length - 3
            and len(script) == length + 35 and script[length] == 1
            and script[length + 1:] == bytes([33]) + pubkey,
            "unexpected P2PKH signature or sighash")
