"""SEC 2 v2 secp256k1 arithmetic; infinity is None. Not constant-time."""

from dataclasses import dataclass, asdict

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


@dataclass
class Operations:
    additions: int = 0
    doublings: int = 0
    inversions: int = 0
    scalar_multiplications: int = 0

    def snapshot(self):
        return asdict(self)


def on_curve(point):
    return point is None or (
        type(point) is tuple and len(point) == 2
        and all(type(v) is int and 0 <= v < P for v in point)
        and (point[1] * point[1] - point[0] ** 3 - 7) % P == 0
    )


def negate(point):
    return None if point is None else (point[0], -point[1] % P)


def add(left, right, ops=None):
    if ops is not None:
        ops.additions += 1
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u:
        if (y + v) % P == 0:
            return None
        if ops is not None:
            ops.doublings += 1
        numerator, denominator = 3 * x * x, 2 * y
    else:
        numerator, denominator = v - y, u - x
    if ops is not None:
        ops.inversions += 1
    slope = numerator * pow(denominator % P, -1, P) % P
    rx = (slope * slope - x - u) % P
    return rx, (slope * (x - rx) - y) % P


def _double(j, ops):
    x, y, z = j
    if ops is not None:
        ops.doublings += 1
    if z == 0 or y == 0:
        return (0, 1, 0)
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    rx = (m * m - 2 * s) % P
    return rx, (m * (s - rx) - 8 * yy * yy) % P, 2 * y * z % P


def _mixed(j, point, ops):
    if ops is not None:
        ops.additions += 1
    x, y, z = j
    if z == 0:
        return point[0], point[1], 1
    zz = z * z % P
    h = (point[0] * zz - x) % P
    r = (point[1] * zz * z - y) % P
    if h == 0:
        return _double(j, ops) if r == 0 else (0, 1, 0)
    hh = h * h % P
    hhh = h * hh % P
    v = x * hh % P
    rx = (r * r - hhh - 2 * v) % P
    return rx, (r * (v - rx) - y * hhh) % P, z * h % P


def multiply(scalar, point=G, ops=None):
    """Jacobian double-and-add, reducing only group scalars modulo N."""
    if type(scalar) is not int or not on_curve(point):
        raise ValueError("invalid scalar or point")
    if ops is not None:
        ops.scalar_multiplications += 1
    scalar %= N
    if scalar == 0 or point is None:
        return None
    result = (0, 1, 0)
    for bit in bin(scalar)[2:]:
        result = _double(result, ops)
        if bit == "1":
            result = _mixed(result, point, ops)
    x, y, z = result
    if not z:
        return None
    if ops is not None:
        ops.inversions += 1
    zi = pow(z, -1, P)
    return x * zi * zi % P, y * zi * zi * zi % P


def reference_multiply(scalar, point=G, ops=None):
    """Separate affine right-to-left implementation for acceptance checks."""
    if type(scalar) is not int or not 0 <= scalar < N or not on_curve(point):
        raise ValueError("invalid verification input")
    if ops is not None:
        ops.scalar_multiplications += 1
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point, ops)
        scalar >>= 1
        if scalar:
            point = add(point, point, ops)
    return result


def encode(point):
    if point is None or not on_curve(point):
        raise ValueError("point has no compressed encoding")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def decode(encoded):
    if type(encoded) is not bytes or len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed point")
    x = int.from_bytes(encoded[1:], "big")
    if x >= P:
        raise ValueError("noncanonical point")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (encoded[0] & 1):
        y = -y % P
    result = (x, y)
    if not on_curve(result):
        raise ValueError("point is not on curve")
    return result
