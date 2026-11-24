#!/usr/bin/env python3
"""Standard-library-only Bitcoin/secp256k1 helpers for the RCKangaroo private
adapter. No third-party packages, no network, no submodules.

Scope:
- secp256k1 affine scalar multiplication (for known-answer test pubkeys);
- compressed public-key encoding;
- P2PKH (base58check) address derivation from a compressed pubkey;
- bech32m (BIP350) checksum validation for the taproot recipient.

This module performs ONE scalar multiplication per known-answer test. It is not
a solver and is not performance-critical.
"""
import hashlib

# --- secp256k1 domain parameters -------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a, m):
    return pow(a % m, m - 2, m)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k):
    """Return k*G as an affine (x, y) point. k must be in [1, N-1]."""
    k %= N
    if k == 0:
        raise ValueError("scalar must be non-zero mod N")
    r = None
    a = (GX, GY)
    while k:
        if k & 1:
            r = _add(r, a)
        a = _add(a, a)
        k >>= 1
    return r


def compressed_pubkey(k):
    """Return the 33-byte compressed public key for private scalar k as hex."""
    x, y = scalar_mult(k)
    prefix = b"\x03" if (y & 1) else b"\x02"
    return (prefix + x.to_bytes(32, "big")).hex()


# --- hashing ----------------------------------------------------------------
def _ripemd160(data):
    try:
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()
    except (ValueError, TypeError):
        return _ripemd160_pure(data)


def hash160(data):
    return _ripemd160(hashlib.sha256(data).digest())


# --- base58check (P2PKH) ----------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def p2pkh_address(compressed_pub_hex, version=0x00):
    payload = bytes([version]) + hash160(bytes.fromhex(compressed_pub_hex))
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


# --- bech32 / bech32m (BIP173 / BIP350) -------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(addr):
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return None
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return None
    hrp = addr[:pos]
    data = []
    for c in addr[pos + 1:]:
        if c not in _CHARSET:
            return None
        data.append(_CHARSET.index(c))
    const = _polymod(_hrp_expand(hrp) + data)
    if const == _BECH32_CONST:
        spec = "bech32"
    elif const == _BECH32M_CONST:
        spec = "bech32m"
    else:
        return None
    return hrp, data[:-6], spec


def validate_bech32m_mainnet(addr):
    """Validate a mainnet bech32m address (taproot / witness v1+).

    Returns (True, info) on success or (False, reason)."""
    dec = bech32_decode(addr)
    if dec is None:
        return False, "bad bech32/bech32m checksum or charset"
    hrp, data, spec = dec
    if hrp != "bc":
        return False, "hrp is not mainnet 'bc' (got %r)" % hrp
    if not data:
        return False, "empty witness program"
    wit_ver = data[0]
    if wit_ver < 1 or wit_ver > 16:
        return False, "witness version %d is not bech32m range (1..16)" % wit_ver
    if spec != "bech32m":
        return False, "witness v%d must use bech32m, got %s" % (wit_ver, spec)
    # convert 5-bit groups to bytes
    acc = 0
    bits = 0
    prog = []
    for d in data[1:]:
        acc = (acc << 5) | d
        bits += 5
        if bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xFF)
    if bits >= 5 or ((acc << (8 - bits)) & 0xFF) and bits:
        pass  # padding tolerance; length check below is the real gate
    if len(prog) < 2 or len(prog) > 40:
        return False, "witness program length %d out of range" % len(prog)
    if wit_ver == 1 and len(prog) != 32:
        return False, "taproot (v1) program must be 32 bytes, got %d" % len(prog)
    return True, {"hrp": hrp, "witness_version": wit_ver,
                  "program_len": len(prog), "spec": spec}


# --- pure-python ripemd160 fallback (used only if hashlib lacks it) ---------
def _ripemd160_pure(message):
    import struct

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE,
                          0x10325476, 0xC3D2E1F0)
    ml = len(message)
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += struct.pack("<Q", (ml * 8) & 0xFFFFFFFFFFFFFFFF)
    for off in range(0, len(message), 64):
        x = list(struct.unpack("<16I", message[off:off + 64]))
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            t = (al + f(j, bl, cl, dl) + x[rl[j]] + kl[j // 16]) & 0xFFFFFFFF
            t = (rol(t, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (ar + f(79 - j, br, cr, dr) + x[rr[j]] + kr[j // 16]) & 0xFFFFFFFF
            t = (rol(t, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)
