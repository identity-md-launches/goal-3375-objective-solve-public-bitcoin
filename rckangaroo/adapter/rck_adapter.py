#!/usr/bin/env python3
"""IdentityMD private adapter for RetiredC/RCKangaroo (pinned commit
618473acd7f5e696be5ec4f8377c18cc55c1361c).

The patched solver (rckangaroo/upstream) emits a recovered key ONLY as 32
big-endian bytes to an inherited --candidate-fd and fails closed otherwise.
This wrapper owns that fd: it never prints key bytes, scrubs child output,
and writes the candidate to a private file OUTSIDE the checkout (mode 0600).

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
                    (recipient bech32m checksum, pubkey->address match). No key.
  real140           Entrant-private real run, locked to the exact #140 manifest.
                    Refuses unless explicitly acknowledged and given an
                    entrant-controlled private dir outside the checkout.

This wrapper performs no host inventory, rents no hardware, reads no machine
credentials/home/env/config, and downloads nothing.
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True  # keep the vendored tree free of .pyc artifacts

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import btccrypto  # noqa: E402

CANDIDATE_LEN = 32
# Patterns that could carry key material in child logs; scrubbed before echo.
_LEAK_RE = re.compile(r"(?i)(private\s*key|[0-9a-f]{40,64})")


def _scrub(text):
    if not text:
        return ""
    out = []
    for line in text.splitlines():
        if _LEAK_RE.search(line):
            out.append("[redacted: suppressed potential key material]")
        else:
            out.append(line)
    return "\n".join(out)


def _ensure_private_dir(path, checkout_root):
    ap = os.path.abspath(path)
    cr = os.path.abspath(checkout_root)
    if ap == cr or ap.startswith(cr + os.sep):
        raise SystemExit(
            "refusing: --private-dir %r is inside the checkout; sensitive "
            "files must live OUTSIDE the repository" % path)
    os.makedirs(ap, mode=0o700, exist_ok=True)
    os.chmod(ap, 0o700)
    return ap


def run_solver_candidate(solver_cmd, private_out_path, timeout=None):
    """Spawn solver_cmd (list), passing the write end of a pipe as the
    --candidate-fd value. Read exactly 32 bytes; write them 0600 to
    private_out_path. Returns a dict result. Never returns key bytes and never
    prints them. Fails closed on any shortfall."""
    r_fd, w_fd = os.pipe()
    cmd = list(solver_cmd) + ["--candidate-fd", str(w_fd)]
    captured_stdout, captured_stderr, rc = "", "", None
    data = b""
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(w_fd,), close_fds=True)
        os.close(w_fd)  # parent keeps only the read end
        w_fd = -1
        while len(data) < CANDIDATE_LEN:
            chunk = os.read(r_fd, CANDIDATE_LEN - len(data))
            if not chunk:
                break
            data += chunk
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        captured_stdout = out.decode("utf-8", "replace") if out else ""
        captured_stderr = err.decode("utf-8", "replace") if err else ""
        rc = proc.returncode
    finally:
        try:
            os.close(r_fd)
        except OSError:
            pass
        if w_fd >= 0:
            try:
                os.close(w_fd)
            except OSError:
                pass

    result = {
        "solver_returncode": rc,
        "bytes_received": len(data),
        "child_stdout_scrubbed": _scrub(captured_stdout),
        "child_stderr_scrubbed": _scrub(captured_stderr),
        "candidate_written": False,
        "status": None,
    }
    if len(data) != CANDIDATE_LEN:
        result["status"] = "FAILCLOSED_NO_CANDIDATE"
        # scrub any partial bytes from memory
        data = b"\x00" * len(data)
        return result, None
    if rc not in (0,):
        result["status"] = "FAILCLOSED_SOLVER_RC"
        data = b"\x00" * len(data)
        return result, None
    # persist candidate privately
    fd = os.open(private_out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(private_out_path, 0o600)
    result["candidate_written"] = True
    result["status"] = "OK"
    result["private_out_path"] = os.path.abspath(private_out_path)
    key_int = int.from_bytes(data, "big")
    data = b"\x00" * len(data)
    return result, key_int


# --------------------------------------------------------------------------
def cmd_selftest_output(args):
    """Non-CUDA: exercise the output path with an arbitrary solver command."""
    priv = _ensure_private_dir(args.private_dir, args.checkout_root)
    out_path = os.path.join(priv, "candidate.selftest.bin")
    solver_cmd = args.solver_cmd
    result, key_int = run_solver_candidate(solver_cmd, out_path, timeout=args.timeout)
    # Confirm no sentinel leak if an expected sentinel hex was supplied.
    leaked = False
    if args.forbid_hex:
        blob = (result["child_stdout_scrubbed"] + "\n"
                + result["child_stderr_scrubbed"]).lower()
        leaked = args.forbid_hex.lower() in blob
    result["forbidden_hex_leaked"] = leaked
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ()}, indent=2))
    ok = (result["status"] == args.expect) and not leaked
    return 0 if ok else 1


def cmd_verify_manifest(args):
    with open(os.path.join(HERE, "manifest_140.json")) as f:
        m = json.load(f)
    report = {"objective": "bitcoin-puzzle-140", "checks": {}}
    rec = m["recipient"]["address"]
    ok_rec, info = btccrypto.validate_bech32m_mainnet(rec)
    report["checks"]["recipient_bech32m_mainnet"] = {"ok": ok_rec, "info": info}
    derived = btccrypto.p2pkh_address(m["pubkey_compressed"])
    ok_addr = (derived == m["address"])
    report["checks"]["pubkey_to_address_match"] = {
        "ok": ok_addr, "derived": derived, "expected": m["address"]}
    start_hex = m["interval"]["rckangaroo_start_hex"]
    ok_start = (int(start_hex, 16) == (1 << 139))
    report["checks"]["start_equals_2pow139"] = {"ok": ok_start}
    report["note"] = ("UTXO/spendable-prize state is a live on-chain check and "
                      "is NOT performed offline here.")
    print(json.dumps(report, indent=2))
    return 0 if (ok_rec and ok_addr and ok_start) else 1


def _build_challenge(range_bits, seed):
    """Deterministic known-answer challenge: k in [2^(R-1), 2^R - 1]."""
    import hashlib
    if range_bits < 32:
        raise SystemExit("known-answer range must be >= 32 bits")
    lo = 1 << (range_bits - 1)
    span = (1 << range_bits) - lo
    h = hashlib.sha256(("rck-kat-%d-%s" % (range_bits, seed)).encode()).digest()
    k = lo + (int.from_bytes(h, "big") % span)
    pub = btccrypto.compressed_pubkey(k)
    start_hex = format(lo, "x")
    return k, pub, start_hex


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
    out_path = os.path.join(priv, "candidate.kat.bin")
    solver_cmd = [args.solver_bin, "-pubkey", pub, "-range", str(args.range_bits),
                  "-start", start_hex, "-dp", str(args.dp)]
    result, key_int = run_solver_candidate(solver_cmd, out_path, timeout=args.timeout)
    verified = (result["status"] == "OK" and key_int == k)
    report = {k2: v for k2, v in result.items()}
    report["range_bits"] = args.range_bits
    report["known_answer_match"] = verified
    report["pubkey"] = pub  # public data only
    if not verified:
        report.pop("private_out_path", None)
    print(json.dumps(report, indent=2))
    return 0 if verified else 1


def cmd_real140(args):
    with open(os.path.join(HERE, "manifest_140.json")) as f:
        m = json.load(f)
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
    out_path = os.path.join(priv, "candidate.140.bin")
    solver_cmd = [args.solver_bin, "-pubkey", pub, "-range", str(range_bits),
                  "-start", start_hex, "-dp", str(args.dp)]
    result, _ = run_solver_candidate(solver_cmd, out_path, timeout=args.timeout)
    report = {k2: v for k2, v in result.items()}
    report["next_action"] = (
        "If status==OK, the 32-byte candidate is at the private path above. "
        "Hand it to the separate secure-claim tool (regtest-tested) to sign and "
        "broadcast a tx paying ONLY %s minus network fees. Never print the key."
        % m["recipient"]["address"])
    print(json.dumps(report, indent=2))
    return 0 if result["status"] == "OK" else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--checkout-root", default=os.getcwd(),
                   help="repository root; private dirs must be outside it")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("selftest-output")
    s.add_argument("--private-dir", required=True)
    s.add_argument("--expect", default="OK",
                   choices=["OK", "FAILCLOSED_NO_CANDIDATE", "FAILCLOSED_SOLVER_RC"])
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
    # normalise solver_cmd: strip a leading "--"
    if getattr(args, "solver_cmd", None) and args.solver_cmd and args.solver_cmd[0] == "--":
        args.solver_cmd = args.solver_cmd[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
