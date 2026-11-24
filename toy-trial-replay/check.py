"""Exercise replay in fresh subprocesses and emit measured JSON evidence."""

import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPLAY = HERE / "replay.py"
BENCHMARK = HERE.parent / "toy-comparison" / "toy_dlog.py"
INTERRUPT = """
import os
from pathlib import Path
import resource
import signal
import sys
import time

started = time.perf_counter()
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import replay

replace = replay.os.replace
attempts = 0

def interrupt_second_replace(source, destination):
    global attempts
    attempts += 1
    if attempts == 2:
        print(replay.json.dumps({
            "elapsed_seconds_before_signal": time.perf_counter() - started,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }), flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
    replace(source, destination)

replay.os.replace = interrupt_second_replace
replay.run_shard(Path(sys.argv[2]), 0, replay.fixture_digest())
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(*args, expected=0):
    result = subprocess.run(
        [sys.executable, "-I", "-B", *map(str, args)],
        capture_output=True, text=True, check=False,
    )
    require(result.returncode == expected, f"{args}: {result.returncode}: {result.stderr}")
    return (json.loads(result.stdout) if result.stdout else result.stderr.strip())


def main():
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(dir=HERE) as root:
        clean = Path(root) / "clean"
        restarted = Path(root) / "restarted"
        clean_runs = [invoke(REPLAY, "run", clean, shard) for shard in (0, 1)]
        clean_paths = [clean / f"shard-{shard}.json" for shard in (0, 1)]
        baseline = invoke(REPLAY, "check", *clean_paths)

        interrupted = invoke("-c", INTERRUPT, REPLAY, restarted, expected=-signal.SIGKILL)
        paths = [restarted / f"shard-{shard}.json" for shard in (0, 1)]
        partial_copy = restarted / "partial-copy.json"
        partial_copy.write_bytes(paths[0].read_bytes())
        partial = invoke(REPLAY, "check", partial_copy, clean_paths[1], expected=1)
        require(partial["missing_shards"] == [] and partial["missing_trials"] ==
                ["interior-alpha", "interior-charlie", "interior-echo"],
                "interrupted shard did not preserve exactly the first commit")

        resumed = invoke(REPLAY, "run", restarted, 0)
        require(resumed["reused"] == ["endpoint-low"] and
                resumed["executed"] == partial["missing_trials"], "incorrect resume work")
        restarted_shard1 = invoke(REPLAY, "run", restarted, 1)
        resumed_report = invoke(REPLAY, "check", *paths)
        require(resumed_report == baseline, "resumed report differs from clean report")

        repeated_run = invoke(REPLAY, "run", restarted, 0)
        require(not repeated_run["executed"] and
                len(repeated_run["reused"]) == 4, "repeat re-executed completed trials")
        repeated_report = invoke(REPLAY, "check", *paths, paths[0], partial_copy)
        require(repeated_report["duplicate_records_ignored"] == 5, "wrong duplicate count")
        require(all(repeated_report[key] == baseline[key] for key in baseline
                    if key != "duplicate_records_ignored"), "repeat changed merged results")

        missing = invoke(REPLAY, "check", paths[0], expected=1)
        require(missing["missing_shards"] == [1] and missing["missing_trials"] ==
                clean_runs[1]["executed"], "incorrect missing shard report")

        damaged = json.loads(paths[0].read_text())
        damaged["fixture_digest"] = "0" * 64
        paths[0].write_text(json.dumps(damaged))
        mismatch = invoke(REPLAY, "check", *paths, expected=2)
        require("fixture digest mismatch" in mismatch, mismatch)
        mismatch_resume = invoke(REPLAY, "run", restarted, 0, expected=2)
        require("fixture digest mismatch" in mismatch_resume, mismatch_resume)

        upstream = invoke(BENCHMARK, "--json")["results"]
        require(len(upstream) == 14 and all(row["success"] for row in upstream),
                "upstream known-answer trials failed")
        for method, counts in baseline["counts"].items():
            for counter, count in counts.items():
                require(count == sum(row[counter] for row in upstream if row["method"] == method),
                        f"{method} {counter} differs from direct benchmark")

    print(json.dumps({
        "fixture_digest": baseline["fixture_digest"],
        "baseline": baseline, "resumed": resumed_report, "repeated": repeated_report,
        "interrupted_checkpoint": partial, "missing_shard": missing,
        "digest_mismatch": {"check_exit": 2, "resume_exit": 2,
                            "diagnostic": mismatch.split(": ")[-1]},
        "direct_benchmark_matches": True,
        "measurements": {
            "suite_elapsed_seconds": time.perf_counter() - started,
            "clean_shard_runs": clean_runs,
            "interrupted_shard": {**interrupted, "signal": "SIGKILL"},
            "resume_run": resumed,
            "restarted_shard1_run": restarted_shard1,
            "repeated_run": repeated_run,
        },
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
