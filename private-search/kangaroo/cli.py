"""Bounded local runner. Diagnostics deliberately exclude input and exception text."""

import argparse
import faulthandler
import json
import math
import os
from pathlib import Path
import resource
import signal
import sys
import time

from . import VERSION
from .engine import Engine
from .manifest import LOWER, PRODUCTION, canonical, synthetic_manifest, validate_manifest
from .secp256k1 import Operations
from .storage import CandidateSink, PrivateDirectory, strict_json

CHECKOUT = Path(__file__).resolve().parents[2]
COMPONENT = CHECKOUT / "private-search"


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid arguments")


def parser():
    p = QuietParser(description="Bounded CPU kangaroo; synthetic by default. POSIX, offline, private state.")
    p.add_argument("--mode", choices=("synthetic", "real"), default="synthetic")
    p.add_argument("--entrant-controlled", action="store_true",
                   help="Attest this is an entrant-controlled private machine, never a shared worker")
    p.add_argument("--private-dir", help="Explicit absolute 0700 state directory; real mode requires outside checkout")
    p.add_argument("--candidate-fd", type=int, help="Inherited write-only FD >=3; exactly 32 big-endian bytes")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--export-dp", action="store_true", help="Private snapshot in private-dir/dp.jsonl")
    p.add_argument("--max-steps", type=int)
    p.add_argument("--max-seconds", type=float)
    p.add_argument("--checkpoint-steps", type=int, default=10000)
    p.add_argument("--seed", default="trial-v1")
    p.add_argument("--worker-id", default="local")
    p.add_argument("--generation", type=int, default=0)
    p.add_argument("--dp-bits", type=int)
    p.add_argument("--max-records", type=int, default=10000)
    p.add_argument("--synthetic-width", type=int, default=4096)
    p.add_argument("--synthetic-lower", type=int, default=LOWER)
    p.add_argument("--synthetic-position", choices=("lower", "upper", "middle", "seeded"), default="seeded")
    return p


def validate_args(args, require_sink=True):
    real = args.mode == "real"
    if real and (not args.entrant_controlled or args.private_dir is None
                 or (require_sink and args.candidate_fd is None)
                 or args.max_steps is None or args.max_seconds is None):
        raise ValueError("real execution needs explicit entrant, private state, sink and budgets")
    if real and (args.synthetic_width != 4096 or args.synthetic_lower != LOWER
                 or args.synthetic_position != "seeded"):
        raise ValueError("synthetic flags cannot change production challenge")
    if args.resume and args.private_dir is None or args.export_dp and args.private_dir is None:
        raise ValueError("private directory required")
    if args.max_steps is None:
        args.max_steps = 10000
    if args.max_seconds is None:
        args.max_seconds = 10.0
    if not 1 <= args.max_steps <= 10**12 or not math.isfinite(args.max_seconds) or not 0 < args.max_seconds <= 86400:
        raise ValueError("invalid execution bound")
    if not 1 <= args.checkpoint_steps <= 10**12:
        raise ValueError("invalid checkpoint bound")
    if args.dp_bits is None:
        args.dp_bits = 20 if real else 0


def harden_process():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    faulthandler.disable()


def process_peak_bytes():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def report_error(launcher=False):
    """Even a failed diagnostic write must not expose chained exceptions."""
    message = ('{"schema":"private-search-status@1","status":"error","code":"launcher-refused-or-failed"}\n'
               if launcher else
               '{"schema":"private-search-status@1","status":"error","code":"refused-or-failed"}\n')
    try:
        sys.stderr.write(message)
        sys.stderr.flush()
    except BaseException:
        pass


def production_manifest():
    # The file is an auditable public manifest, never an override mechanism.
    with (COMPONENT / "production-manifest.json").open("rb") as handle:
        value = strict_json(handle.read(8192))
    if value != PRODUCTION:
        raise ValueError("fixed production manifest changed")
    validate_manifest(value)
    return value


def execute(args):
    started = time.monotonic()
    harden_process()
    validate_args(args)
    real = args.mode == "real"
    stopped = [False]
    def interrupt(_number, _frame):
        stopped[0] = True
    old_signals = {s: signal.signal(s, interrupt) for s in (signal.SIGINT, signal.SIGTERM)}
    store = None
    try:
        setup_ops = Operations()
        known = None
        if real:
            manifest = production_manifest()
        else:
            manifest, known = synthetic_manifest(args.synthetic_lower, args.synthetic_width,
                                                 args.synthetic_position, args.seed, ops=setup_ops)
        if args.private_dir is not None:
            store = PrivateDirectory(args.private_dir, str(CHECKOUT) if real else None, create=not args.resume)
        sink = CandidateSink(args.candidate_fd, store) if args.candidate_fd is not None else None
        if real and sink is None:
            raise ValueError("private sink required")
        config = {"seed": args.seed, "workerId": args.worker_id, "generation": args.generation,
                  "dpBits": args.dp_bits, "maxRecords": args.max_records}
        if args.resume:
            state = store.load()
            if state.get("config") != config:
                raise ValueError("resume parameters mismatch")
            engine = Engine.restore(state, manifest, production_authorized=real, setup_ops=setup_ops,
                                    stopped=lambda: stopped[0] or time.monotonic() - started >= args.max_seconds)
        else:
            if store is not None and store.exists("checkpoint.json"):
                raise ValueError("existing checkpoint requires explicit resume")
            engine = Engine(manifest, args.seed, args.worker_id, args.generation,
                            args.dp_bits, args.max_records, production_authorized=real, setup_ops=setup_ops)
            if store is not None:
                store.save(engine, export=args.export_dp)
        setup_seconds = time.monotonic() - started
        setup_peak = process_peak_bytes()
        operations_before = engine.walk_ops.snapshot()
        usage_before = resource.getrusage(resource.RUSAGE_SELF)
        callback = None if store is None else lambda value: store.save(value, export=args.export_dp)
        result = engine.run(args.max_steps, max(0.0, args.max_seconds - setup_seconds),
                            stopped=lambda: stopped[0], checkpoint=callback,
                            checkpoint_steps=args.checkpoint_steps)
        usage_after = resource.getrusage(resource.RUSAGE_SELF)
        # Persist collision evidence BEFORE delivery. Resume re-verifies it; delivery is at-least-once.
        if store is not None:
            store.save(engine, export=args.export_dp)
        delivered = False
        delivery_start = time.monotonic()
        delivery_ops = Operations()
        if engine.status == "solved":
            candidate = engine.candidate_bytes(ops=delivery_ops)
            if known is not None and candidate != known.to_bytes(32, "big"):
                raise ValueError("known answer mismatch")
            if sink is not None:
                sink.deliver(candidate)
                delivered = True
            del candidate
        delivery_seconds = time.monotonic() - delivery_start
        elapsed = result["solveWallSeconds"]
        operations = {k: v - operations_before[k] for k, v in engine.walk_ops.snapshot().items()}
        metrics = {
            "schema": "private-search-metrics@1", "engineVersion": VERSION,
            "deviceLabel": "unknown", "mode": args.mode, "seed": args.seed,
            "manifestHash": engine.manifest_hash, "jumpHash": engine.jump_hash,
            "setupWallSeconds": setup_seconds, "solveWallSeconds": elapsed,
            "deliveryWallSeconds": delivery_seconds,
            "totalWallSeconds": time.monotonic() - started,
            "solveCpuSeconds": usage_after.ru_utime + usage_after.ru_stime - usage_before.ru_utime - usage_before.ru_stime,
            "setupProcessPeakRssBytes": setup_peak, "processPeakRssBytes": process_peak_bytes(),
            "steps": result["steps"], "totalSteps": str(engine.steps),
            "walkStepsPerSecond": result["steps"] / elapsed if elapsed else 0.0,
            "setupOperations": setup_ops.snapshot(), "solveOperations": operations,
            "deliveryVerificationOperations": delivery_ops.snapshot(),
            "retainedDpRecords": len(engine.table), "status": result["reason"],
            "candidateDelivered": delivered,
        }
        if store is not None:
            store.atomic_write("metrics.json", canonical(metrics) + b"\n")
        # No input-derived identifiers, paths, points, distances, exception strings, or keys.
        public_fields = ("mode", "status", "candidateDelivered") if real else (
            "mode", "status", "candidateDelivered", "steps", "totalSteps",
            "setupWallSeconds", "solveWallSeconds", "processPeakRssBytes")
        summary = {k: metrics[k] for k in public_fields}
        summary["schema"] = "private-search-status@1"
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0 if result["reason"] == "solved" else 3
    finally:
        if store is not None:
            store.close()
        for number, handler in old_signals.items():
            signal.signal(number, handler)


def guarded_main(argv=None):
    try:
        return execute(parser().parse_args(argv))
    except (Exception, KeyboardInterrupt):
        # Never interpolate exception text: filesystem paths and injected records can contain secrets.
        report_error()
        return 2
