"""Restart the fixed toy-comparison fixture suite at whole-trial boundaries."""

import argparse
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import time

BENCHMARK = Path(__file__).resolve().parent.parent / "toy-comparison" / "toy_dlog.py"
sys.path.insert(0, str(BENCHMARK.parent))
sys.dont_write_bytecode = True
import toy_dlog as benchmark

VERSION = 1
TRIAL_IDS = (
    "endpoint-low", "endpoint-high", "interior-alpha", "interior-bravo",
    "interior-charlie", "interior-delta", "interior-echo",
)
ASSIGNMENTS = {shard: TRIAL_IDS[shard::2] for shard in (0, 1)}
METHODS = ("bsgs", "kangaroo")
COUNTERS = ("group_ops", "setup_ops", "search_ops")


def fixture_digest():
    fixtures = [benchmark.reproduce_fixture(trial) for trial in TRIAL_IDS]
    if ((benchmark.P, benchmark.N, benchmark.G) != (130787, 65393, 4)
            or benchmark.METHODS != METHODS
            or any((fixture.a, fixture.b) != (1000, 5096) for fixture in fixtures)):
        raise ValueError("benchmark no longer matches the fixed experiment")
    manifest = {
        "version": VERSION,
        "benchmark_sha256": hashlib.sha256(BENCHMARK.read_bytes()).hexdigest(),
        "group": [benchmark.P, benchmark.N, benchmark.G],
        "assignments": ASSIGNMENTS,
        "methods": METHODS,
        "fixtures": [asdict(fixture) for fixture in fixtures],
    }
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_checkpoint(path, digest):
    with path.open(encoding="utf-8") as stream:
        checkpoint = json.load(stream, object_pairs_hook=unique_object)
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "version", "fixture_digest", "shard", "completed",
    }:
        raise ValueError(f"{path}: invalid checkpoint fields")
    if type(checkpoint["version"]) is not int or checkpoint["version"] != VERSION:
        raise ValueError(f"{path}: checkpoint version mismatch")
    if checkpoint["fixture_digest"] != digest:
        raise ValueError(f"{path}: fixture digest mismatch")
    shard = checkpoint["shard"]
    if type(shard) is not int or shard not in ASSIGNMENTS:
        raise ValueError(f"{path}: invalid shard")
    completed = checkpoint["completed"]
    if not isinstance(completed, dict) or set(completed) - set(ASSIGNMENTS[shard]):
        raise ValueError(f"{path}: invalid completed trial IDs for shard {shard}")
    for trial, methods in completed.items():
        if not isinstance(methods, dict) or set(methods) != set(METHODS):
            raise ValueError(f"{path}: invalid methods for {trial}")
        for counts in methods.values():
            if (not isinstance(counts, dict) or set(counts) != set(COUNTERS)
                    or any(type(value) is not int or value < 0 for value in counts.values())
                    or counts["group_ops"] != counts["setup_ops"] + counts["search_ops"]):
                raise ValueError(f"{path}: invalid operation counts for {trial}")
    return shard, completed


def save_checkpoint(path, digest, shard, completed):
    checkpoint = {
        "version": VERSION, "fixture_digest": digest,
        "shard": shard, "completed": completed,
    }
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(checkpoint, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def shard_lock(path):
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def run_trial(trial):
    fixture = benchmark.reproduce_fixture(trial)
    counts = {}
    for method in METHODS:
        result = benchmark.solve(method, fixture)
        if not result.success or result.recovered != fixture.x:
            raise ValueError(f"{trial}: {method} disagreed with the known answer")
        counts[method] = {field: getattr(result, field) for field in COUNTERS}
    return counts


def run_shard(directory, shard, digest):
    started = time.perf_counter()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"shard-{shard}.json"
    with shard_lock(path):
        try:
            stored_shard, completed = read_checkpoint(path, digest)
        except FileNotFoundError:
            completed = {}
        else:
            if stored_shard != shard:
                raise ValueError(f"{path}: expected shard {shard}, found {stored_shard}")
        reused = [trial for trial in ASSIGNMENTS[shard] if trial in completed]
        executed = []
        for trial in ASSIGNMENTS[shard]:
            if trial not in completed:
                completed[trial] = run_trial(trial)
                save_checkpoint(path, digest, shard, completed)
                executed.append(trial)
    return {
        "shard": shard, "fixture_digest": digest,
        "reused": reused, "executed": executed,
        "elapsed_seconds": time.perf_counter() - started,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def merge(paths, digest):
    completed = {}
    shards = set()
    duplicate_records = 0
    for path in paths:
        shard, records = read_checkpoint(path, digest)
        shards.add(shard)
        for trial, counts in records.items():
            if trial in completed:
                if completed[trial] != counts:
                    raise ValueError(f"{path}: conflicting counts for {trial}")
                duplicate_records += 1
            else:
                completed[trial] = counts
    missing_shards = sorted(ASSIGNMENTS.keys() - shards)
    missing_trials = [trial for trial in TRIAL_IDS if trial not in completed]
    return {
        "fixture_digest": digest,
        "complete": not missing_shards and not missing_trials,
        "missing_shards": missing_shards, "missing_trials": missing_trials,
        "completed_trials": [trial for trial in TRIAL_IDS if trial in completed],
        "duplicate_records_ignored": duplicate_records,
        "counts": {
            method: {
                field: sum(counts[method][field] for counts in completed.values())
                for field in COUNTERS
            } for method in METHODS
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="start or resume a shard")
    run.add_argument("directory", type=Path)
    run.add_argument("shard", type=int, choices=ASSIGNMENTS)
    check = commands.add_parser("check", help="merge and check completeness")
    check.add_argument("checkpoint", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        digest = fixture_digest()
        if args.command == "run":
            print(json.dumps(run_shard(args.directory, args.shard, digest), sort_keys=True))
            return 0
        report = merge(args.checkpoint, digest)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["complete"] else 1
    except (OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
