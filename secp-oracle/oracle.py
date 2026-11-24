"""Offline test driver for public SYNTHETIC known answers."""
import argparse
from collections import Counter
import ctypes as c
import hashlib
import json
from pathlib import Path
from time import perf_counter

HERE = Path(__file__).resolve().parent
SEED = "imd-p140-e2-secp-oracle-v1"
REVISION = "0cdc758a56360bf58a851fe91085a327ec97685a"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASELINE = HERE.parent / "public-verify-bench/fixtures/vectors.json"
BASELINE_SHA256 = "b2a93674959ab6938447134b8738aff8385b3d4e3a9d9c10637e5826c7210812"


def sha256(data):
    return hashlib.sha256(data).digest()


def seeded(label):
    return sha256(f"{SEED}:{label}".encode("ascii"))


def encode(value):
    return value.to_bytes(32, "big")


class Oracle:
    def __init__(self, library):
        self.lib = c.CDLL(str(library.resolve()))
        pointer = c.c_void_p
        self.lib.oracle_open.argtypes = []
        self.lib.oracle_open.restype = pointer
        self.lib.oracle_close.argtypes = [pointer]
        self.lib.oracle_close.restype = None
        self.lib.oracle_point.argtypes = [pointer, pointer, pointer, pointer]
        self.lib.oracle_parse.argtypes = [pointer, pointer, c.c_size_t, pointer]
        self.lib.oracle_sign.argtypes = [pointer, pointer, pointer, pointer]
        self.lib.oracle_verify.argtypes = [pointer, pointer, c.c_size_t, pointer, pointer]
        self.ctx = self.lib.oracle_open()
        if not self.ctx:
            raise RuntimeError("libsecp256k1 context creation failed")

    def point(self, scalar):
        compressed = c.create_string_buffer(33)
        uncompressed = c.create_string_buffer(65)
        if self.lib.oracle_point(self.ctx, encode(scalar), compressed, uncompressed):
            return compressed.raw, uncompressed.raw
        return None

    def parse(self, sec):
        compressed = c.create_string_buffer(33)
        if self.lib.oracle_parse(self.ctx, sec, len(sec), compressed):
            return compressed.raw
        return None

    def sign(self, scalar, digest):
        signature = c.create_string_buffer(64)
        if not self.lib.oracle_sign(self.ctx, encode(scalar), digest, signature):
            raise ValueError("could not sign SYNTHETIC fixture")
        return signature.raw

    def verify(self, sec, digest, signature):
        if len(digest) != 32 or len(signature) != 64:
            raise ValueError("invalid digest or compact signature size")
        return bool(self.lib.oracle_verify(self.ctx, sec, len(sec), digest, signature))


def interval_specs():
    for group, base in (("ordinary", 1 << 15), ("near-2pow139", 1 << 139)):
        low = base + int.from_bytes(seeded(f"{group}:low")[:2], "big")
        width = 32 + seeded(f"{group}:width")[0] % 32
        high = low + width
        interior = low + 1 + seeded(f"{group}:interior")[0] % (width - 1)
        for position, scalar in (
            ("below", low - 1), ("low", low), ("interior", interior),
            ("high", high), ("above", high + 1),
        ):
            yield f"{group}-{position}", low, high, scalar


def signature_cases(oracle, label, scalar):
    digest = seeded(f"{label}:digest")
    compact = oracle.sign(scalar, digest)
    high_s = compact[:32] + encode(N - int.from_bytes(compact[32:], "big"))
    for kind, message, signature, expected in (
        ("valid", digest, compact, True),
        ("wrong-digest", seeded(f"{label}:wrong-digest"), compact, False),
        ("zero-r", digest, bytes(32) + compact[32:], False),
        ("high-s", digest, high_s, False),
    ):
        yield dict(case=kind, digest_hex=message.hex(), compact_hex=signature.hex(),
                   expected_valid=expected)


def make_corpus(oracle):
    intervals = []
    for label, low, high, scalar in interval_specs():
        compressed, uncompressed = oracle.point(scalar)
        intervals.append(dict(
            classification="SYNTHETIC", id=label, low=str(low), high=str(high),
            scalar=str(scalar), sec_compressed=compressed.hex(),
            sec_uncompressed=uncompressed.hex(),
            expected_in_interval=not label.endswith(("-below", "-above")),
            signatures=list(signature_cases(oracle, label, scalar)),
        ))
    distances = []
    for bit in (125, 126, 128, 139):
        for delta, edge in ((-1, "below"), (0, "at"), (1, "above")):
            value = (1 << bit) + delta
            compressed, _ = oracle.point(value)
            distances.append(dict(
                classification="SYNTHETIC", id=f"2pow{bit}-{edge}",
                boundary_exponent=str(bit), distance=str(value),
                bit_length=str(value.bit_length()), uint256_be_hex=encode(value).hex(),
                sec_compressed=compressed.hex(), expected_valid=True,
            ))
    return {
        "$schema": "./fixture.schema.json",
        "classification": "SYNTHETIC",
        "provenance": {
            "seed_namespace": SEED,
            "libsecp256k1_commit": REVISION,
            "digest": "SHA-256",
            "signature": "ECDSA RFC6979, low-S, compact r || s",
        },
        "intervals": intervals,
        "distances": distances,
    }


class Checks:
    def __init__(self):
        self.counts = Counter()
        self.failures = []

    def equal(self, group, case, actual, expected):
        self.counts[group] += 1
        if actual != expected:
            self.failures.append(f"{group}/{case}: got {actual!r}, expected {expected!r}")


def check_published(oracle, checks):
    # SEC 2 v2 section 2.4.1, generator coordinates and order.
    x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    compressed, uncompressed = oracle.point(1)  # SYNTHETIC generator scalar
    checks.equal("published", "SEC2/G compressed", compressed.hex(), "02" + x)
    checks.equal("published", "SEC2/G uncompressed", uncompressed.hex(), "04" + x + y)
    checks.equal("scalar_bounds", "zero", oracle.point(0), None)
    checks.equal("scalar_bounds", "order", oracle.point(N), None)
    checks.equal("scalar_bounds", "order plus one", oracle.point(N + 1), None)
    checks.equal("scalar_bounds", "order minus one", oracle.point(N - 1)[0].hex(), "03" + x)
    checks.equal("sec_rejections", "infinity encoding", oracle.parse(b"\x00"), None)
    checks.equal("sec_rejections", "out of field", oracle.parse(b"\x02" + b"\xff" * 32), None)

    data = json.loads((HERE / "published-points.json").read_bytes())
    for row in data["vectors"]:
        scalar = int(row["scalar_be_hex"], 16)
        _, sec = oracle.point(scalar)
        checks.equal("published", f"BIP340/{row['index']} x", sec[1:33].hex(), row["x_hex"])


def check_corpus(oracle, checks, data):
    for row in data["intervals"]:
        label = row["id"]
        scalar = int(row["scalar"])
        low, high = int(row["low"]), int(row["high"])
        checks.equal("membership", label, low <= scalar <= high, row["expected_in_interval"])
        compressed = bytes.fromhex(row["sec_compressed"])
        for field in ("sec_compressed", "sec_uncompressed"):
            sec = bytes.fromhex(row[field])
            checks.equal("sec_roundtrips", f"{label}/{field}", oracle.parse(sec), compressed)
            for sig in row["signatures"]:
                valid = oracle.verify(sec, bytes.fromhex(sig["digest_hex"]),
                                      bytes.fromhex(sig["compact_hex"]))
                checks.equal("fixture_ecdsa", f"{label}/{field}/{sig['case']}",
                             valid, sig["expected_valid"])
    for row in data["distances"]:
        label = row["id"]
        distance = int(row["distance"])
        boundary = 1 << int(row["boundary_exponent"])
        offset = {"below": -1, "at": 0, "above": 1}[label.rsplit("-", 1)[1]]
        checks.equal("distance", f"{label}/edge", distance, boundary + offset)
        checks.equal("distance", f"{label}/bit length", str(distance.bit_length()), row["bit_length"])
        checks.equal("distance", f"{label}/uint256 BE",
                     int.from_bytes(bytes.fromhex(row["uint256_be_hex"]), "big"), distance)
        sec = bytes.fromhex(row["sec_compressed"])
        checks.equal("distance", f"{label}/SEC valid", oracle.parse(sec) == sec, row["expected_valid"])


def check_baseline(oracle, checks, raw):
    data = json.loads(raw)
    checks.equal("baseline_metadata", "sha256", sha256(raw).hex(), BASELINE_SHA256)
    checks.equal("baseline_metadata", "count", len(data["vectors"]), 128)
    checks.equal("baseline_metadata", "declared count", data["count"], len(data["vectors"]))
    seed = b"public-verify-bench/secp256k1/synthetic-kat/v1"
    for row in data["vectors"]:
        index = str(row["index"])
        counter = index.encode("ascii")
        # Reimplement only the documented public SYNTHETIC seed derivation.
        scalar = int.from_bytes(sha256(seed + b":" + counter), "big") % N or 1
        digest = sha256(bytes.fromhex(row["msg_hex"]))
        sec = bytes.fromhex(row["pub_compressed_hex"])
        compact = bytes.fromhex(row["r_hex"] + row["s_hex"])
        checks.equal("baseline_point", index, oracle.point(scalar)[0], sec)
        checks.equal("baseline_signature", index, oracle.sign(scalar, digest), compact)
        checks.equal("baseline_verification", index,
                     oracle.verify(sec, digest, compact), row["valid"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--emit", action="store_true", help="emit only the public SYNTHETIC corpus")
    parser.add_argument("--require-baseline", action="store_true",
                        help="fail if the pinned goal-trunk baseline is absent")
    args = parser.parse_args()

    start = perf_counter()
    oracle = Oracle(args.library)
    checks = Checks()
    baseline_status = "not_run"
    try:
        corpus = make_corpus(oracle)
        generated = (json.dumps(corpus, indent=2) + "\n").encode("ascii")
        if args.emit:
            print(generated.decode("ascii"), end="")
            return 0
        raw = (HERE / "fixtures.json").read_bytes()
        digest = sha256(raw).hex()
        checks.equal("corpus_integrity", "sha256", digest,
                     (HERE / "fixtures.sha256").read_text().split()[0])
        checks.equal("corpus_integrity", "deterministic regeneration", raw == generated, True)
        check_published(oracle, checks)
        check_corpus(oracle, checks, json.loads(raw))
        if BASELINE.is_file():
            failure_count = len(checks.failures)
            check_baseline(oracle, checks, BASELINE.read_bytes())
            baseline_status = "passed" if len(checks.failures) == failure_count else "failed"
        else:
            baseline_status = "unavailable: public-verify-bench/fixtures/vectors.json absent"
            if args.require_baseline:
                checks.failures.append(baseline_status)
    finally:
        oracle.lib.oracle_close(oracle.ctx)

    print(json.dumps({
        "checks": dict(checks.counts), "total_checks": sum(checks.counts.values()),
        "discrepancies": checks.failures, "baseline_status": baseline_status,
        "fixture_sha256": digest, "driver_elapsed_seconds": round(perf_counter() - start, 6),
    }, indent=2))
    return bool(checks.failures)


if __name__ == "__main__":
    raise SystemExit(main())
