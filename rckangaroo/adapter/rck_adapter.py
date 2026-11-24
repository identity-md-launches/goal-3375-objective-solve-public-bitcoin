#!/usr/bin/env python3
"""IdentityMD private adapter for RetiredC/RCKangaroo (pinned commit
618473acd7f5e696be5ec4f8377c18cc55c1361c).

The patched solver (rckangaroo/upstream) emits a recovered key ONLY as 32
big-endian bytes to an inherited --candidate-fd (which must be >= 3, never a
standard stream) and fails closed otherwise. This wrapper owns that fd. It:

  * drains the child's stdout/stderr concurrently from the moment of spawn, so a
    noisy or pipe-filling child can never deadlock the candidate read;
  * enforces a deadline measured from spawn (no unbounded blocking);
  * reads EXACTLY 32 bytes and requires a clean EOF afterwards -- any extra byte
    is treated as a protocol violation and fails closed;
  * never prints key bytes and never echoes raw child output; only a constant,
    allowlisted set of counters/booleans is surfaced publicly;
  * runs the child in a PRIVATE working directory outside the checkout, so a
    stray file the child writes cannot land in the repository;
  * writes the candidate to a private file OUTSIDE the checkout with
    O_CREAT|O_EXCL|O_NOFOLLOW mode 0600 (never follows a symlink, never
    overwrites/truncates an existing file);
  * detects the checkout physically (realpath), not by a lexical string compare,
    so a `..`/symlink path cannot escape the "outside the checkout" rule;
  * trusts the #140 manifest only after verifying it against pinned constants.

Subcommands
-----------
  selftest-output   Drive any solver command through the candidate-fd path and
                    assert fail-closed / no-leak behaviour. Used by the
                    non-CUDA output-path tests with a fake solver. No crypto.
  kat               Generated known-answer test: build a small-range challenge
                    with a known private key, run the REAL solver, and verify
                    the recovered 32 bytes equal the known key. Requires the
                    built CUDA binary + a compatible GPU (see cuda_kat_harness).
  verify-manifest   Independently validate the fixed #140 manifest offline
                    (recipient bech32m checksum, pubkey->address match,
                    pinned-constant match). No key.
  real140           Entrant-private real run, locked to the exact #140 manifest
                    and verified against pinned constants. Refuses unless
                    explicitly acknowledged and given an entrant-controlled
                    private dir outside the checkout. Independently checks the
                    recovered candidate against the target pubkey and interval
                    before any handoff.

This wrapper performs no host inventory, rents no hardware, reads no machine
credentials/home/env/config, and downloads nothing.
"""
import argparse
import hashlib
import json
import os
import re
import select
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True  # keep the vendored tree free of .pyc artifacts

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import btccrypto  # noqa: E402

CANDIDATE_LEN = 32
# Physically-detected repository root (adapter lives at <repo>/rckangaroo/adapter).
# This is authoritative; a caller-supplied --checkout-root can only ADD to it.
REPO_ROOT = os.path.realpath(os.path.join(HERE, os.pardir, os.pardir))

# Pinned #140 identity. The on-disk manifest is mutable; it is trusted only
# after matching these constants, so a tampered manifest cannot redirect a real
# run or substitute the recipient.
EXPECTED = {
    "address": "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
    "pubkey_compressed":
        "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640",
    "recipient": "bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx",
    "start_hex": "80000000000000000000000000000000000",
    "range_bits": 140,
}
# sha256 of the shipped manifest_140.json (advisory integrity signal).
EXPECTED_MANIFEST_SHA256 = \
    "9057d510ca1ed66ff144c893462d18facb98ed3dd233253d3c7dd12bb06de4d9"

# Interval [2^139, 2^140 - 1].
INTERVAL_LOW = 1 << 139
INTERVAL_HIGH = (1 << 140) - 1

# Patterns that could carry key material in child logs. Covers the phrase
# "private key", long hex runs, long decimal runs (a 140-bit scalar is ~42
# decimal digits), and base64-ish runs (32 bytes -> ~44 base64 chars).
_LEAK_RE = re.compile(
    r"(?i)private\s*key"
    r"|[0-9a-f]{40,}"
    r"|[0-9]{39,}"
    r"|[A-Za-z0-9+/]{40,}={0,2}")

# Upper bound on child output we retain for leak inspection (bytes). The child
# is expected to be quiet; this only bounds pathological output.
_DRAIN_CAP = 1 << 20


class ManifestError(Exception):
    """Raised when the on-disk manifest does not match pinned constants."""


def leak_detected(text):
    return bool(_LEAK_RE.search(text or ""))


def _scrub(text):
    if not text:
        return ""
    out = []
    for line in text.splitlines():
        out.append("[redacted: suppressed potential key material]"
                   if _LEAK_RE.search(line) else line)
    return "\n".join(out)


def _is_within(child, parent):
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:  # different drives / relative mismatch
        return False


def _forbidden_roots(checkout_root_arg):
    roots = {REPO_ROOT}
    if checkout_root_arg:
        roots.add(os.path.realpath(os.path.abspath(checkout_root_arg)))
    return roots


def _refuse_inside_checkout(path, checkout_root_arg, what):
    real = os.path.realpath(os.path.abspath(path))
    for root in _forbidden_roots(checkout_root_arg):
        if real == root or _is_within(real, root):
            raise SystemExit(
                "refusing: %s %r resolves inside the checkout (%s); sensitive "
                "files must live OUTSIDE the repository" % (what, path, root))
    return real


def _ensure_private_dir(path, checkout_root):
    """Create/return a private dir that is PHYSICALLY outside the checkout.

    Containment is decided by realpath (not a lexical prefix), so `..` and
    symlink tricks cannot smuggle a path back into the repository."""
    _refuse_inside_checkout(path, checkout_root, "--private-dir")
    ap = os.path.abspath(path)
    os.makedirs(ap, mode=0o700, exist_ok=True)
    os.chmod(ap, 0o700)
    # Re-check after creation to defeat a symlink swapped in during makedirs.
    _refuse_inside_checkout(ap, checkout_root, "--private-dir")
    return ap


def _open_private_exclusive(path):
    """Open a brand-new private file for the candidate. Never follows a symlink
    and never overwrites an existing file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    return os.open(path, flags, 0o600)


def _drain(stream, sink):
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if sink["len"] < _DRAIN_CAP:
                room = _DRAIN_CAP - sink["len"]
                sink["buf"].append(chunk[:room])
            sink["len"] += len(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def run_solver_candidate(solver_cmd, private_out_path, timeout=None, cwd=None):
    """Spawn solver_cmd (list) with an inherited write-pipe as --candidate-fd.

    Returns (public_result, key_int_or_None, captured_text). key_int and
    captured_text are for the caller's PRIVATE verification only and are never
    placed in public_result. public_result contains only allowlisted fields.
    Fails closed on timeout, short/extra frames, nonzero rc, or sink error."""
    r_fd, w_fd = os.pipe()
    # The sink fd handed to the child must never be a standard stream.
    while 0 <= w_fd < 3:
        nw = os.dup(w_fd)
        os.close(w_fd)
        w_fd = nw
    cmd = list(solver_cmd) + ["--candidate-fd", str(w_fd)]

    out_sink = {"buf": [], "len": 0}
    err_sink = {"buf": [], "len": 0}
    data = b""
    extra = False
    eof = False
    timed_out = False
    rc = None
    t_out = t_err = None
    deadline = None if timeout is None else time.monotonic() + float(timeout)

    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(w_fd,), close_fds=True, cwd=cwd)
        os.close(w_fd)
        w_fd = -1

        # Drain stdout/stderr concurrently so the child can never block on a
        # full pipe while we wait for the candidate.
        t_out = threading.Thread(target=_drain, args=(proc.stdout, out_sink),
                                 daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, err_sink),
                                 daemon=True)
        t_out.start()
        t_err.start()

        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
            else:
                remaining = None
            ready, _, _ = select.select([r_fd], [], [], remaining)
            if not ready:
                timed_out = True
                break
            chunk = os.read(r_fd, 64)
            if not chunk:
                eof = True
                break
            data += chunk
            if len(data) > CANDIDATE_LEN:
                extra = True
                break
            # When exactly 32 bytes are in hand, loop again: the next read must
            # yield EOF (clean frame) or more bytes (extra -> violation).

        if proc.poll() is None:
            if timed_out or extra:
                proc.kill()
        try:
            grace = 5.0
            rc = proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
    finally:
        for fd in (r_fd, w_fd):
            if fd is not None and fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for t in (t_out, t_err):
            if t is not None:
                t.join(timeout=5)

    captured = b"".join(out_sink["buf"]).decode("utf-8", "replace") + "\n" + \
        b"".join(err_sink["buf"]).decode("utf-8", "replace")

    result = {
        "solver_returncode": rc,
        "bytes_received": len(data),
        "extra_bytes_detected": extra,
        "eof_confirmed": eof,
        "timed_out": timed_out,
        "stdout_bytes": out_sink["len"],
        "stderr_bytes": err_sink["len"],
        "leak_pattern_detected": leak_detected(captured),
        "candidate_written": False,
        "status": None,
    }

    def _scrub_mem():
        nonlocal data
        data = b"\x00" * len(data)

    if timed_out:
        result["status"] = "FAILCLOSED_TIMEOUT"
        _scrub_mem()
        return result, None, captured
    if extra:
        result["status"] = "FAILCLOSED_EXTRA_BYTES"
        _scrub_mem()
        return result, None, captured
    if len(data) != CANDIDATE_LEN or not eof:
        result["status"] = "FAILCLOSED_NO_CANDIDATE"
        _scrub_mem()
        return result, None, captured
    if rc != 0:
        result["status"] = "FAILCLOSED_SOLVER_RC"
        _scrub_mem()
        return result, None, captured

    try:
        fd = _open_private_exclusive(private_out_path)
    except OSError as e:
        result["status"] = "FAILCLOSED_SINK_OPEN"
        result["sink_errno"] = e.errno
        _scrub_mem()
        return result, None, captured
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    result["candidate_written"] = True
    result["status"] = "OK"
    result["private_out_path"] = os.path.abspath(private_out_path)
    key_int = int.from_bytes(data, "big")
    _scrub_mem()
    return result, key_int, captured


# --------------------------------------------------------------------------
def load_pinned_manifest(path):
    """Load the manifest and verify it against the pinned #140 constants.

    Raises ManifestError on any mismatch so a mutable/tampered manifest cannot
    redirect the target or recipient."""
    with open(path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        m = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ManifestError("manifest is not valid JSON: %s" % e)
    errs = []
    if m.get("address") != EXPECTED["address"]:
        errs.append("address")
    if m.get("pubkey_compressed") != EXPECTED["pubkey_compressed"]:
        errs.append("pubkey_compressed")
    rec = (m.get("recipient") or {}).get("address")
    if rec != EXPECTED["recipient"]:
        errs.append("recipient.address")
    iv = m.get("interval") or {}
    if iv.get("rckangaroo_start_hex") != EXPECTED["start_hex"]:
        errs.append("interval.rckangaroo_start_hex")
    if iv.get("rckangaroo_range_bits") != EXPECTED["range_bits"]:
        errs.append("interval.rckangaroo_range_bits")
    if errs:
        raise ManifestError(
            "manifest does not match pinned #140 constants: %s" % ", ".join(errs))
    return m, digest


def _public(result, extra=None):
    """Project a result onto the allowlisted public fields only."""
    allow = ("status", "solver_returncode", "bytes_received",
             "extra_bytes_detected", "eof_confirmed", "timed_out",
             "stdout_bytes", "stderr_bytes", "leak_pattern_detected",
             "candidate_written", "private_out_path", "sink_errno")
    out = {k: result[k] for k in allow if k in result}
    if extra:
        out.update(extra)
    return out


def cmd_selftest_output(args):
    """Non-CUDA: exercise the output path with an arbitrary solver command."""
    priv = _ensure_private_dir(args.private_dir, args.checkout_root)
    if args.out_file:
        out_path = _refuse_inside_checkout(
            args.out_file, args.checkout_root, "--out-file")
        out_path = os.path.abspath(args.out_file)
    else:
        out_path = os.path.join(
            priv, "candidate.selftest.%s.bin" % os.urandom(8).hex())
    result, _key, captured = run_solver_candidate(
        args.solver_cmd, out_path, timeout=args.timeout, cwd=priv)
    # A forbidden token is "leaked" only if it survives scrubbing (i.e. would
    # reach a surfaced/public text). Raw child output is never echoed.
    leaked = False
    if args.forbid_hex:
        leaked = args.forbid_hex.lower() in _scrub(captured).lower()
    pub = _public(result, {"forbidden_hex_leaked": leaked})
    print(json.dumps(pub, indent=2))
    ok = (result["status"] == args.expect) and not leaked
    return 0 if ok else 1


def cmd_verify_manifest(args):
    try:
        m, digest = load_pinned_manifest(os.path.join(HERE, "manifest_140.json"))
    except ManifestError as e:
        print(json.dumps({"objective": "bitcoin-puzzle-140",
                          "status": "MANIFEST_REJECTED", "reason": str(e)},
                         indent=2))
        return 1
    report = {"objective": "bitcoin-puzzle-140", "checks": {}}
    report["manifest_sha256"] = digest
    report["manifest_sha256_matches_pin"] = (digest == EXPECTED_MANIFEST_SHA256)
    rec = m["recipient"]["address"]
    ok_rec, info = btccrypto.validate_bech32m_mainnet(rec)
    report["checks"]["recipient_bech32m_mainnet"] = {"ok": ok_rec, "info": info}
    derived = btccrypto.p2pkh_address(m["pubkey_compressed"])
    ok_addr = (derived == m["address"])
    report["checks"]["pubkey_to_address_match"] = {
        "ok": ok_addr, "derived": derived, "expected": m["address"]}
    start_hex = m["interval"]["rckangaroo_start_hex"]
    ok_start = (int(start_hex, 16) == INTERVAL_LOW)
    report["checks"]["start_equals_2pow139"] = {"ok": ok_start}
    report["note"] = ("UTXO/spendable-prize state is a live on-chain check and "
                      "is NOT performed offline here.")
    print(json.dumps(report, indent=2))
    return 0 if (ok_rec and ok_addr and ok_start) else 1


def _build_challenge(range_bits, seed):
    """Deterministic known-answer challenge: k in [2^(R-1), 2^R - 1]."""
    if range_bits < 32:
        raise SystemExit("known-answer range must be >= 32 bits")
    lo = 1 << (range_bits - 1)
    span = (1 << range_bits) - lo
    h = hashlib.sha256(("rck-kat-%d-%s" % (range_bits, seed)).encode()).digest()
    k = lo + (int.from_bytes(h, "big") % span)
    pub = btccrypto.compressed_pubkey(k)
    start_hex = format(lo, "x")
    return k, pub, start_hex


def _independent_pubkey_check(key_int, expected_pub, lo, hi):
    """Independently confirm the recovered scalar: in range AND k*G == target
    pubkey. Returns bool. Never logs the key."""
    if key_int is None or not (lo <= key_int <= hi):
        return False
    try:
        return btccrypto.compressed_pubkey(key_int) == expected_pub
    except Exception:
        return False


def cmd_kat(args):
    """Generated known-answer test against the REAL solver binary."""
    if not os.path.isfile(args.solver_bin):
        print(json.dumps({"status": "UNAVAILABLE",
                          "reason": "solver binary not found: %s" % args.solver_bin,
                          "hint": "build with rckangaroo/build/build_cuda.sh on a CUDA host"},
                         indent=2))
        return 3
    k, pub, start_hex = _build_challenge(args.range_bits, args.seed)
    priv = _ensure_private_dir(args.private_dir, args.checkout_root)
    out_path = os.path.join(priv, "candidate.kat.%s.bin" % os.urandom(8).hex())
    solver_cmd = [args.solver_bin, "-pubkey", pub, "-range", str(args.range_bits),
                  "-start", start_hex, "-dp", str(args.dp)]
    result, key_int, _captured = run_solver_candidate(
        solver_cmd, out_path, timeout=args.timeout, cwd=priv)
    lo = 1 << (args.range_bits - 1)
    hi = (1 << args.range_bits) - 1
    indep = _independent_pubkey_check(key_int, pub, lo, hi)
    verified = (result["status"] == "OK" and key_int == k and indep)
    report = _public(result, {"range_bits": args.range_bits,
                              "known_answer_match": (key_int == k),
                              "independent_pubkey_check": indep,
                              "pubkey": pub})
    if not verified:
        report.pop("private_out_path", None)
    print(json.dumps(report, indent=2))
    return 0 if verified else 1


def cmd_real140(args):
    try:
        m, digest = load_pinned_manifest(os.path.join(HERE, "manifest_140.json"))
    except ManifestError as e:
        print(json.dumps({"status": "MANIFEST_REJECTED", "reason": str(e)},
                         indent=2))
        return 1
    if not args.i_am_entrant_private_host:
        raise SystemExit(
            "refusing: real #140 mode runs ONLY on an entrant-controlled private "
            "host. Re-run with --i-am-entrant-private-host after confirming this "
            "is NOT a shared worker.")
    priv = _ensure_private_dir(args.private_dir, args.checkout_root)
    if not os.path.isfile(args.solver_bin):
        print(json.dumps({"status": "UNAVAILABLE",
                          "reason": "solver binary not found: %s" % args.solver_bin},
                         indent=2))
        return 3
    pub = m["pubkey_compressed"]
    start_hex = m["interval"]["rckangaroo_start_hex"]
    range_bits = m["interval"]["rckangaroo_range_bits"]
    out_path = os.path.join(priv, "candidate.140.%s.bin" % os.urandom(8).hex())
    solver_cmd = [args.solver_bin, "-pubkey", pub, "-range", str(range_bits),
                  "-start", start_hex, "-dp", str(args.dp)]
    result, key_int, _captured = run_solver_candidate(
        solver_cmd, out_path, timeout=args.timeout, cwd=priv)
    indep = False
    if result["status"] == "OK":
        indep = _independent_pubkey_check(
            key_int, pub, INTERVAL_LOW, INTERVAL_HIGH)
        if not indep:
            # Candidate does not reproduce the target pubkey/interval: refuse
            # the handoff and remove the file. Never disclose the key.
            try:
                os.unlink(result["private_out_path"])
            except OSError:
                pass
            result["candidate_written"] = False
            result["status"] = "FAILCLOSED_CANDIDATE_MISMATCH"
            result.pop("private_out_path", None)
    report = _public(result, {"independent_pubkey_check": indep})
    report["next_action"] = (
        "If status==OK and independent_pubkey_check==true, the 32-byte candidate "
        "is at the private path above. Hand it to the separate secure-claim tool "
        "(regtest-tested) to sign and broadcast a tx paying ONLY %s minus network "
        "fees. Never print the key." % EXPECTED["recipient"])
    print(json.dumps(report, indent=2))
    return 0 if result["status"] == "OK" else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--checkout-root", default=os.getcwd(),
                   help="additional repository root; private dirs must be "
                        "outside it (the physical checkout is always enforced)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("selftest-output")
    s.add_argument("--private-dir", required=True)
    s.add_argument("--out-file", default="",
                   help="exact candidate path (must be outside checkout); "
                        "default is a fresh random name under --private-dir")
    s.add_argument("--expect", default="OK",
                   choices=["OK", "FAILCLOSED_NO_CANDIDATE",
                            "FAILCLOSED_SOLVER_RC", "FAILCLOSED_EXTRA_BYTES",
                            "FAILCLOSED_TIMEOUT", "FAILCLOSED_SINK_OPEN"])
    s.add_argument("--forbid-hex", default="")
    s.add_argument("--timeout", type=float, default=30)
    s.add_argument("solver_cmd", nargs=argparse.REMAINDER,
                   help="solver command (after --); --candidate-fd is appended")
    s.set_defaults(func=cmd_selftest_output)

    v = sub.add_parser("verify-manifest")
    v.set_defaults(func=cmd_verify_manifest)

    k = sub.add_parser("kat")
    k.add_argument("--solver-bin", required=True)
    k.add_argument("--range-bits", type=int, default=32)
    k.add_argument("--dp", type=int, default=14)
    k.add_argument("--seed", default="default")
    k.add_argument("--private-dir", required=True)
    k.add_argument("--timeout", type=float, default=None)
    k.set_defaults(func=cmd_kat)

    r = sub.add_parser("real140")
    r.add_argument("--solver-bin", required=True)
    r.add_argument("--dp", type=int, default=30)
    r.add_argument("--private-dir", required=True)
    r.add_argument("--i-am-entrant-private-host", action="store_true")
    r.add_argument("--timeout", type=float, default=None)
    r.set_defaults(func=cmd_real140)

    args = p.parse_args(argv)
    if getattr(args, "solver_cmd", None) and args.solver_cmd and args.solver_cmd[0] == "--":
        args.solver_cmd = args.solver_cmd[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
