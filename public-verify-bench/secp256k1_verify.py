#!/usr/bin/env python3
"""Pure Python (standard library only) secp256k1 ECDSA primitives.

Backend: pure-python-stdlib (arbitrary-precision int arithmetic).
No third-party dependencies. Imports only: hashlib, hmac (both stdlib).

Scope of this file: the secp256k1 group operations plus ECDSA *verification*
(the operation this benchmark measures) and a deterministic (RFC 6979) ECDSA
*signer* used only to generate reproducible known-answer fixtures offline.

Domain parameters are the standardized secp256k1 curve (SEC 2 v2, section 2.4.1
"Recommended Parameters secp256k1", Certicom Research, 2010). They are public
constants, not generated here.
"""

import hashlib
import hmac

# secp256k1 domain parameters (SEC 2 v2, 2.4.1). Public constants.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# Point at infinity sentinel.
INF = None


def _inv(x, m):
    """Modular inverse via Python's built-in extended-gcd (pow(-1))."""
    return pow(x, -1, m)


def point_add(p1, p2):
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, point):
    """Double-and-add scalar multiplication."""
    k %= N
    result = INF
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_on_curve(point):
    if point is INF:
        return False
    x, y = point
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def decompress_pubkey(pub_bytes):
    """Decode an SEC1 public key (compressed 33B or uncompressed 65B)."""
    if len(pub_bytes) == 33 and pub_bytes[0] in (0x02, 0x03):
        x = int.from_bytes(pub_bytes[1:], "big")
        if x >= P:
            raise ValueError("x >= P")
        alpha = (pow(x, 3, P) + A * x + B) % P
        beta = pow(alpha, (P + 1) // 4, P)  # P % 4 == 3
        if (beta * beta - alpha) % P != 0:
            raise ValueError("not a quadratic residue")
        y = beta if (beta & 1) == (pub_bytes[0] & 1) else P - beta
        point = (x, y)
    elif len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
        x = int.from_bytes(pub_bytes[1:33], "big")
        y = int.from_bytes(pub_bytes[33:], "big")
        point = (x, y)
    else:
        raise ValueError("unsupported SEC1 encoding")
    if not is_on_curve(point):
        raise ValueError("pubkey not on curve")
    return point


def sha256_int(msg):
    """e = int(SHA-256(msg)). secp256k1 qlen == 256, so bits2int == int()."""
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def verify(pub_point, msg, r, s):
    """ECDSA verify over secp256k1 with SHA-256. Returns bool.

    pub_point: (x, y). msg: bytes. r, s: ints.
    Standard ECDSA acceptance (accepts both high- and low-s).
    """
    if not (1 <= r < N and 1 <= s < N):
        return False
    if not is_on_curve(pub_point):
        return False
    e = sha256_int(msg) % N
    w = _inv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    point = point_add(scalar_mul(u1, G), scalar_mul(u2, pub_point))
    if point is INF:
        return False
    return (point[0] % N) == r


# --- Deterministic signer (RFC 6979). Offline fixture generation only. ---

def _bits2octets(data):
    z1 = int.from_bytes(data, "big")  # bits2int, qlen==256
    z2 = z1 % N
    return z2.to_bytes(32, "big")


def _rfc6979_k(x, h1):
    """RFC 6979 deterministic nonce generator (HMAC-SHA256), secp256k1."""
    xb = x.to_bytes(32, "big")
    hb = _bits2octets(h1)
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            yield cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(priv, msg, low_s=True):
    """Deterministic ECDSA signature (RFC 6979). Returns (r, s).

    Used only to build reproducible fixtures. Never used on recovered keys.
    """
    h1 = hashlib.sha256(msg).digest()
    e = int.from_bytes(h1, "big") % N
    for k in _rfc6979_k(priv, h1):
        R = scalar_mul(k, G)
        r = R[0] % N
        if r == 0:
            continue
        s = (_inv(k, N) * (e + r * priv)) % N
        if s == 0:
            continue
        if low_s and s > N // 2:
            s = N - s
        return r, s
    raise RuntimeError("unreachable")


def pubkey_point(priv):
    return scalar_mul(priv, G)
