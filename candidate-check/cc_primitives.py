"""secp256k1 arithmetic, SEC1 encoding, RIPEMD-160 and Base58Check for candidate-check.

Written for this component only. It imports nothing from other repository
components and nothing outside the Python standard library (hashlib SHA-256).
RIPEMD-160 is implemented here so the result does not depend on the OpenSSL
provider that the local Python build happens to ship.

Exceptions raised here carry fixed text only; they never contain input bytes,
scalars, coordinates or anything derived from them.

Not constant time: Python integers are variable time. Run secret-bearing checks
only on an entrant-controlled private machine.
"""

import hashlib

# Curve parameters, SEC 2 v2 section 2.4.1 (secp256k1): y^2 = x^3 + 7 over F_p.
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


class PrimitiveError(Exception):
    """Fixed-text failure of a primitive; carries no input-derived content."""


# --------------------------------------------------------------------------
# Field helpers
# --------------------------------------------------------------------------

def _inv_fermat(value):
    value %= P
    if value == 0:
        raise PrimitiveError("field inverse of zero")
    return pow(value, P - 2, P)


def _inv_euclid(value):
    """Extended Euclid inverse mod P; deliberately different from _inv_fermat."""
    value %= P
    if value == 0:
        raise PrimitiveError("field inverse of zero")
    r0, r1 = P, value
    t0, t1 = 0, 1
    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise PrimitiveError("field inverse does not exist")
    return t0 % P


def is_on_curve(x, y):
    """True for a finite affine point with canonical coordinates on the curve."""
    if not (isinstance(x, int) and isinstance(y, int)):
        return False
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - x * x * x - B) % P == 0


# --------------------------------------------------------------------------
# Multiplier A: Jacobian coordinates, left-to-right double-and-add
# --------------------------------------------------------------------------

def _jac_double(pt):
    x1, y1, z1 = pt
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = b * b % P
    d = 2 * ((x1 + b) * (x1 + b) - a - c) % P
    e = 3 * a % P
    x3 = (e * e - 2 * d) % P
    y3 = (e * (d - x3) - 8 * c) % P
    z3 = 2 * y1 * z1 % P
    return (x3, y3, z3)


def _jac_add_affine(pt, x2, y2):
    x1, y1, z1 = pt
    if z1 == 0:
        return (x2, y2, 1)
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    if h == 0:
        if r == 0:
            return _jac_double(pt)
        return (0, 1, 0)
    hh = h * h % P
    hhh = h * hh % P
    v = x1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    y3 = (r * (v - x3) - y1 * hhh) % P
    z3 = z1 * h % P
    return (x3, y3, z3)


def multiply_jacobian(scalar, point=G):
    """scalar * point for 1 <= scalar < N; returns affine (x, y)."""
    if not isinstance(scalar, int) or not (1 <= scalar < N):
        raise PrimitiveError("scalar outside [1, n-1]")
    px, py = point
    if not is_on_curve(px, py):
        raise PrimitiveError("base point not on curve")
    acc = (0, 1, 0)
    for shift in range(scalar.bit_length() - 1, -1, -1):
        acc = _jac_double(acc)
        if (scalar >> shift) & 1:
            acc = _jac_add_affine(acc, px, py)
    x3, y3, z3 = acc
    if z3 == 0:
        raise PrimitiveError("unexpected point at infinity")
    zinv = _inv_fermat(z3)
    zinv2 = zinv * zinv % P
    return (x3 * zinv2 % P, y3 * zinv2 * zinv % P)


# --------------------------------------------------------------------------
# Multiplier B: affine Montgomery ladder (independent formulas and inverse)
# --------------------------------------------------------------------------

def _affine_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = 3 * x1 * x1 * _inv_euclid(2 * y1) % P
    else:
        slope = (y2 - y1) * _inv_euclid(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def multiply_ladder(scalar, point=G):
    """scalar * point for 1 <= scalar < N using a fixed 256-step ladder."""
    if not isinstance(scalar, int) or not (1 <= scalar < N):
        raise PrimitiveError("scalar outside [1, n-1]")
    if not is_on_curve(point[0], point[1]):
        raise PrimitiveError("base point not on curve")
    r0, r1 = None, (point[0], point[1])
    for shift in range(255, -1, -1):
        if (scalar >> shift) & 1:
            r0 = _affine_add(r0, r1)
            r1 = _affine_add(r1, r1)
        else:
            r1 = _affine_add(r0, r1)
            r0 = _affine_add(r0, r0)
    if r0 is None:
        raise PrimitiveError("unexpected point at infinity")
    return r0


def multiply_checked(scalar):
    """scalar * G computed by both multipliers; they must agree and be on curve."""
    first = multiply_jacobian(scalar)
    second = multiply_ladder(scalar)
    if first != second or not is_on_curve(first[0], first[1]):
        raise PrimitiveError("multiplier disagreement")
    return first


# --------------------------------------------------------------------------
# SEC1 point encoding
# --------------------------------------------------------------------------

def encode_compressed(x, y):
    if not is_on_curve(x, y):
        raise PrimitiveError("point not on curve")
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decode_compressed(data):
    """Strict 33-byte compressed SEC1 decode; returns affine (x, y)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) != 33:
        raise PrimitiveError("compressed point must be 33 bytes")
    prefix = data[0]
    if prefix not in (2, 3):
        raise PrimitiveError("compressed point prefix must be 02 or 03")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise PrimitiveError("x coordinate outside field")
    rhs = (x * x * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        raise PrimitiveError("x coordinate has no curve point")
    if (y & 1) != (prefix & 1):
        y = P - y
    if not is_on_curve(x, y):
        raise PrimitiveError("decoded point not on curve")
    return (x, y)


# --------------------------------------------------------------------------
# Hashes
# --------------------------------------------------------------------------

_M32 = 0xFFFFFFFF
_RL = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RR = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_SL = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_SR = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rol(value, count):
    return ((value << count) | (value >> (32 - count))) & _M32


def _rmd_f(index, x, y, z):
    if index == 0:
        return x ^ y ^ z
    if index == 1:
        return (x & y) | (~x & _M32 & z)
    if index == 2:
        return (x | (~y & _M32)) ^ z
    if index == 3:
        return (x & z) | (y & ~z & _M32)
    return x ^ (y | (~z & _M32))


def ripemd160(data):
    """RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996), pure Python."""
    data = bytes(data)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    message = data + b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += (8 * len(data)).to_bytes(8, "little")
    for offset in range(0, len(message), 64):
        words = [int.from_bytes(message[offset + 4 * i:offset + 4 * i + 4], "little")
                 for i in range(16)]
        al, bl, cl, dl, el = state
        ar, br, cr, dr, er = state
        for step in range(80):
            rnd = step // 16
            t = (_rol((al + _rmd_f(rnd, bl, cl, dl) + words[_RL[step]] + _KL[rnd]) & _M32,
                      _SL[step]) + el) & _M32
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + _rmd_f(4 - rnd, br, cr, dr) + words[_RR[step]] + _KR[rnd]) & _M32,
                      _SR[step]) + er) & _M32
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        t = (state[1] + cl + dr) & _M32
        state[1] = (state[2] + dl + er) & _M32
        state[2] = (state[3] + el + ar) & _M32
        state[3] = (state[4] + al + br) & _M32
        state[4] = (state[0] + bl + cr) & _M32
        state[0] = t
    return b"".join(word.to_bytes(4, "little") for word in state)


def sha256(data):
    return hashlib.sha256(bytes(data)).digest()


def hash160(data):
    return ripemd160(sha256(data))


# --------------------------------------------------------------------------
# Base58Check / P2PKH
# --------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload):
    payload = bytes(payload)
    raw = payload + sha256(sha256(payload))[:4]
    number = int.from_bytes(raw, "big")
    digits = []
    while number:
        number, rem = divmod(number, 58)
        digits.append(_B58[rem])
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * zeros + "".join(reversed(digits))


def base58check_decode(text):
    """Strict Base58Check decode; returns the payload without the checksum."""
    if not isinstance(text, str) or not (1 <= len(text) <= 64):
        raise PrimitiveError("base58 text has an invalid size")
    number = 0
    for char in text:
        digit = _B58.find(char)
        if digit < 0:
            raise PrimitiveError("base58 text has an invalid character")
        number = number * 58 + digit
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * zeros + body
    if len(raw) < 5:
        raise PrimitiveError("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        raise PrimitiveError("base58check checksum mismatch")
    return payload


def p2pkh_address_from_compressed(sec):
    """Bitcoin mainnet P2PKH address of a 33-byte compressed public key."""
    if not isinstance(sec, (bytes, bytearray)) or len(sec) != 33:
        raise PrimitiveError("compressed point must be 33 bytes")
    return base58check_encode(b"\x00" + hash160(sec))


def p2pkh_hash_from_address(address):
    """20-byte hash of a mainnet P2PKH address (version byte 00)."""
    payload = base58check_decode(address)
    if len(payload) != 21 or payload[0] != 0:
        raise PrimitiveError("not a mainnet P2PKH address")
    return payload[1:]
