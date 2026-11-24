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


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


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
