"""Two-herd r-adding Pollard kangaroo with exact distances and bounded storage.

Tame: P = d*G. Wild: P = Q + d*G. The distances are signed, unreduced
Python integers, including each walk's starting offset. Only the candidate
d_tame - d_wild is reduced modulo the group order, then checked independently.
"""

import hashlib
import math
import re
import time
from .manifest import canonical, decimal, digest, identifier, validate_manifest
from .secp256k1 import N, Operations, add, decode, encode, multiply, reference_multiply

def density_plan(width, max_records, effort_factor=8):
    """Heuristic only: expected DPs for effort_factor*ceil(sqrt(width)) steps.

    A half-capacity target leaves headroom, not a probabilistic guarantee. Walk
    correlations, cycles and uneven work can invalidate the independent hash model.
    """
    if type(width) is not int or width < 1 or type(max_records) is not int or not 2 <= max_records <= 100000:
        raise ValueError("invalid planning input")
    if type(effort_factor) is not int or not 1 <= effort_factor <= 1024:
        raise ValueError("invalid effort factor")
    root = math.isqrt(width - 1) + 1
    budget = effort_factor * root
    target = max_records // 2
    ratio = (budget + target - 1) // target
    bits = max(0, (ratio - 1).bit_length())
    return {"schema": "kangaroo-density-plan@1", "width": str(width),
            "modelSteps": str(budget), "targetRecords": target, "dpBits": bits,
            "expectedRecordsNumerator": str(budget), "expectedRecordsDenominator": str(1 << bits)}


DP_FIELDS = {"schema", "manifestHash", "jumpHash", "workerId", "walkId",
             "generation", "herd", "point", "distance"}


def jump_table(width, seed, ops=None):
    identifier(seed)
    span = max(2, math.isqrt(width))
    distances = [1]
    for index in range(1, 32):
        material = canonical(["kangaroo-jumps@1", str(width), seed, index])
        distances.append(1 + int.from_bytes(hashlib.sha256(material).digest(), "big") % span)
    points = [multiply(distance, ops=ops) for distance in distances]
    description = {"schema": "kangaroo-jumps@1", "width": str(width), "seed": seed,
                   "distances": [str(d) for d in distances],
                   "points": [encode(p).hex() for p in points],
                   "selector": "sha256(kangaroo-select@1\\0 || SEC1), big endian mod 32"}
    return distances, points, digest(description)


def distinguished(point, bits):
    if point is None:
        return False
    h = hashlib.sha256(b"kangaroo-dp@1\0" + encode(point)).digest()
    return int.from_bytes(h, "big") & ((1 << bits) - 1) == 0


def validate_record(record, manifest, jump_hash, check_equation=True, ops=None):
    if type(jump_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", jump_hash):
        raise ValueError("invalid expected jump hash")
    if type(record) is not dict or set(record) != DP_FIELDS or record["schema"] != "walk-dp@1":
        raise ValueError("invalid DP schema")
    if record["manifestHash"] != digest(manifest) or record["jumpHash"] != jump_hash:
        raise ValueError("incompatible DP")
    identifier(record["workerId"])
    identifier(record["walkId"])
    if type(record["generation"]) is not int or not 0 <= record["generation"] < (1 << 31):
        raise ValueError("invalid generation")
    if record["herd"] not in ("tame", "wild"):
        raise ValueError("invalid herd")
    encoded = record["point"]
    if type(encoded) is not str or not re.fullmatch(r"0[23][0-9a-f]{64}", encoded):
        raise ValueError("invalid DP point")
    point = decode(bytes.fromhex(encoded))
    distance = decimal(record["distance"])
    if check_equation:
        expected = multiply(distance, ops=ops)
        if record["herd"] == "wild":
            expected = add(decode(bytes.fromhex(manifest["publicKey"])), expected, ops)
        if expected != point:
            raise ValueError("invalid DP equation")
    return point, distance


def verified_collision(left, right, manifest, jump_hash, ops=None):
    """Private coordinator primitive. Never print or serialize its return value."""
    q, lo, hi = validate_manifest(manifest)
    lp, ld = validate_record(left, manifest, jump_hash, ops=ops)
    rp, rd = validate_record(right, manifest, jump_hash, ops=ops)
    if lp != rp or left["herd"] == right["herd"]:
        return None
    candidate = (ld - rd if left["herd"] == "tame" else rd - ld) % N
    if not lo <= candidate <= hi or not 1 <= candidate < N:
        return None
    if reference_multiply(candidate, ops=ops) != q:
        return None
    return candidate


class Engine:
    def __init__(self, manifest, seed="trial-v1", worker_id="local", generation=0,
                 dp_bits=0, max_records=10000, production_authorized=False,
                 setup_ops=None, initialize=True):
        self.q, self.lower, self.upper = validate_manifest(manifest)
        if manifest["mode"] == "real" and not production_authorized:
            raise ValueError("entrant authorization required")
        identifier(seed)
        identifier(worker_id)
        if type(generation) is not int or not 0 <= generation < (1 << 31):
            raise ValueError("invalid generation")
        if type(dp_bits) is not int or not 0 <= dp_bits <= 256:
            raise ValueError("invalid DP bits")
        if type(max_records) is not int or not 2 <= max_records <= 100000:
            raise ValueError("invalid memory bound")
        self.manifest = dict(manifest)
        self.manifest_hash = digest(manifest)
        self.config = {"seed": seed, "workerId": worker_id, "generation": generation,
                       "dpBits": dp_bits, "maxRecords": max_records}
        self.lengths, self.jumps, self.jump_hash = jump_table(self.upper - self.lower + 1, seed, setup_ops)
        tame_offset = wild_offset = 0
        if (worker_id, generation) != ("local", 0):
            span = max(1, math.isqrt(self.upper - self.lower + 1))
            def offset(herd):
                material = canonical(["kangaroo-start@1", seed, worker_id, generation, herd])
                return int.from_bytes(hashlib.sha256(material).digest(), "big") % span
            tame_offset, wild_offset = offset("tame"), -offset("wild")
        td = self.upper + tame_offset
        self.walks = {
            "tame": {"point": multiply(td, ops=setup_ops), "distance": td},
            "wild": {"point": add(self.q, multiply(wild_offset, ops=setup_ops), setup_ops),
                     "distance": wild_offset},
        }
        self.next_herd = "tame"
        self.steps = 0
        self.table = {}
        self.solution = None
        self.status = "searching"
        self.counts = {"dpVisits": 0, "oppositeHerdCollisions": 0, "rejectedCollisions": 0}
        self.walk_ops = Operations()
        if initialize:
            self._visit("tame", setup_ops)
            if self.status == "searching":
                self._visit("wild", setup_ops)

    def record(self, herd):
        walk = self.walks[herd]
        return {"schema": "walk-dp@1", "manifestHash": self.manifest_hash,
                "jumpHash": self.jump_hash, "workerId": self.config["workerId"],
                "walkId": herd, "generation": self.config["generation"], "herd": herd,
                "point": encode(walk["point"]).hex(), "distance": str(walk["distance"])}

    def _visit(self, herd, ops):
        if not distinguished(self.walks[herd]["point"], self.config["dpBits"]):
            return
        record = self.record(herd)
        self.counts["dpVisits"] += 1
        key = record["point"]  # All 33 bytes, including parity; never a truncated hash.
        previous = self.table.get(key)
        if previous is not None:
            if previous["herd"] != herd:
                self.counts["oppositeHerdCollisions"] += 1
                candidate = verified_collision(previous, record, self.manifest, self.jump_hash, ops)
                if candidate is not None:
                    self.solution = [dict(previous), record]
                    self.status = "solved"
                else:
                    self.counts["rejectedCollisions"] += 1
            return
        if len(self.table) >= self.config["maxRecords"]:
            self.status = "memory_limit"
            return
        self.table[key] = record

    def increase_capacity(self, max_records):
        """Resume a saturated walk by retaining its pending DP before advancing.

        The pending point is the most recently advanced herd, already counted in
        dpVisits and represented by its exact walk state in v1 checkpoints.
        """
        if type(max_records) is not int or not self.config["maxRecords"] < max_records <= 100000:
            raise ValueError("capacity must increase within the storage bound")
        if self.status != "memory_limit":
            raise ValueError("capacity increase requires saturation")
        herd = "wild" if self.next_herd == "tame" else "tame"
        record = self.record(herd)
        if not distinguished(self.walks[herd]["point"], self.config["dpBits"]) or record["point"] in self.table:
            raise ValueError("invalid pending distinguished point")
        self.config["maxRecords"] = max_records
        self.table[record["point"]] = record
        self.status = "searching"

    def step(self):
        if self.status != "searching":
            return
        herd = self.next_herd
        walk = self.walks[herd]
        encoded = b"\0" if walk["point"] is None else encode(walk["point"])
        selector = hashlib.sha256(b"kangaroo-select@1\0" + encoded).digest()
        index = int.from_bytes(selector, "big") % len(self.jumps)
        walk["point"] = add(walk["point"], self.jumps[index], self.walk_ops)
        walk["distance"] += self.lengths[index]
        self.steps += 1
        self.next_herd = "wild" if herd == "tame" else "tame"
        self._visit(herd, self.walk_ops)

    def run(self, max_steps, max_seconds, stopped=lambda: False, checkpoint=None,
            checkpoint_steps=10000):
        if type(max_steps) is not int or not 0 <= max_steps <= 10**12:
            raise ValueError("invalid step budget")
        if not math.isfinite(max_seconds) or not 0 <= max_seconds <= 86400:
            raise ValueError("invalid time budget")
        if type(checkpoint_steps) is not int or checkpoint_steps < 1:
            raise ValueError("invalid checkpoint interval")
        start, before = time.monotonic(), self.steps
        reason = self.status
        while self.status == "searching":
            if stopped():
                reason = "interrupted"
                break
            if time.monotonic() - start >= max_seconds:
                reason = "time_limit"
                break
            if self.steps - before >= max_steps:
                reason = "step_limit"
                break
            self.step()
            if checkpoint is not None and self.steps % checkpoint_steps == 0:
                checkpoint(self)
        if self.status != "searching":
            reason = self.status
        return {"reason": reason, "steps": self.steps - before,
                "solveWallSeconds": time.monotonic() - start}

    def candidate_bytes(self, ops=None):
        if self.status != "solved" or self.solution is None:
            return None
        candidate = verified_collision(*self.solution, self.manifest, self.jump_hash, ops=ops)
        if candidate is None:
            raise ValueError("solution verification failed")
        return candidate.to_bytes(32, "big")

    def export_records(self):
        records = [self.table[k] for k in sorted(self.table)]
        if self.solution is not None:
            for record in self.solution:
                if record not in records:
                    records.append(record)
        return records

    def snapshot(self):
        return {"schema": "kangaroo-state@1", "manifest": self.manifest,
                "manifestHash": self.manifest_hash, "jumpHash": self.jump_hash,
                "config": self.config, "steps": str(self.steps), "nextHerd": self.next_herd,
                "status": self.status, "solution": self.solution, "counts": self.counts,
                "walkOperations": self.walk_ops.snapshot(),
                "walks": {herd: {"point": None if walk["point"] is None else encode(walk["point"]).hex(),
                                 "distance": str(walk["distance"])} for herd, walk in self.walks.items()},
                "table": [self.table[k] for k in sorted(self.table)]}

    @classmethod
    def restore(cls, state, expected_manifest, production_authorized=False, setup_ops=None,
                stopped=lambda: False):
        required = {"schema", "manifest", "manifestHash", "jumpHash", "config", "steps",
                    "nextHerd", "status", "solution", "counts", "walkOperations", "walks", "table"}
        if type(state) is not dict or set(state) != required or state["schema"] != "kangaroo-state@1":
            raise ValueError("invalid state")
        if state["manifest"] != expected_manifest or state["manifestHash"] != digest(expected_manifest):
            raise ValueError("checkpoint manifest mismatch")
        config = state["config"]
        if type(config) is not dict or set(config) != {"seed", "workerId", "generation", "dpBits", "maxRecords"}:
            raise ValueError("invalid checkpoint config")
        engine = cls(expected_manifest, config["seed"], config["workerId"], config["generation"],
                     config["dpBits"], config["maxRecords"], production_authorized, setup_ops, initialize=False)
        if state["jumpHash"] != engine.jump_hash:
            raise ValueError("checkpoint jump mismatch")
        engine.steps = decimal(state["steps"])
        if engine.steps < 0 or state["nextHerd"] != ("tame" if engine.steps % 2 == 0 else "wild"):
            raise ValueError("invalid step cursor")
        engine.next_herd = state["nextHerd"]
        if type(state["walks"]) is not dict or set(state["walks"]) != {"tame", "wild"}:
            raise ValueError("invalid walks")
        for herd, walk in state["walks"].items():
            if type(walk) is not dict or set(walk) != {"point", "distance"}:
                raise ValueError("invalid walk")
            distance = decimal(walk["distance"])
            point = None if walk["point"] is None else decode(bytes.fromhex(walk["point"]))
            expected = multiply(distance, ops=setup_ops)
            if herd == "wild":
                expected = add(engine.q, expected, setup_ops)
            if point != expected or (point is not None and encode(point).hex() != walk["point"]):
                raise ValueError("invalid walk equation")
            engine.walks[herd] = {"point": point, "distance": distance}
        if type(state["table"]) is not list or len(state["table"]) > config["maxRecords"]:
            raise ValueError("invalid DP table size")
        for record in state["table"]:
            if stopped():
                raise ValueError("restore interrupted or time limited")
            point, _ = validate_record(record, expected_manifest, engine.jump_hash, ops=setup_ops)
            if (not distinguished(point, config["dpBits"]) or record["point"] in engine.table
                    or record["workerId"] != config["workerId"] or record["generation"] != config["generation"]
                    or record["walkId"] != record["herd"]):
                raise ValueError("invalid DP table")
            engine.table[record["point"]] = record
        for key, template in (("counts", engine.counts), ("walkOperations", engine.walk_ops.snapshot())):
            value = state[key]
            if (type(value) is not dict or set(value) != set(template)
                    or any(type(v) is not int or v < 0 for v in value.values())):
                raise ValueError("invalid operation counts")
        engine.counts = state["counts"].copy()
        engine.walk_ops = Operations(**state["walkOperations"])
        engine.status, engine.solution = state["status"], state["solution"]
        if engine.status not in ("searching", "solved", "memory_limit"):
            raise ValueError("invalid state status")
        if engine.status == "solved":
            if type(engine.solution) is not list or len(engine.solution) != 2 or engine.candidate_bytes(ops=setup_ops) is None:
                raise ValueError("invalid solution")
        elif engine.solution is not None:
            raise ValueError("unexpected solution")
        if engine.status == "memory_limit":
            herd = "wild" if engine.next_herd == "tame" else "tame"
            if (engine.steps == 0 or len(engine.table) != config["maxRecords"]
                    or not distinguished(engine.walks[herd]["point"], config["dpBits"])
                    or engine.record(herd)["point"] in engine.table):
                raise ValueError("invalid saturated checkpoint")
        return engine
