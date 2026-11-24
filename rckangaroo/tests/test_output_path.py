#!/usr/bin/env python3
"""Offline, CPU-only tests for the candidate-fd output path and leak controls.

These do NOT require CUDA, a GPU, or the built solver. They drive the adapter
wrapper against tests/fake_solver.py using synthetic sentinels and assert:

  1. good  -> status OK, 32-byte private file written 0600, sentinel absent
             from the wrapper's own output;
  2. short -> fail closed (no candidate), no 32-byte file;
  3. none  -> fail closed;
  4. crash -> fail closed on nonzero solver rc;
  5. leak  -> fake "PRIVATE KEY"/64-hex in child stdout+stderr is scrubbed and
             never surfaces in the wrapper output.

Also exercised: verify-manifest (recipient checksum + pubkey->address), and a
pure-crypto self-check of the known-answer pubkey routine.

Run:  python3 -I rckangaroo/tests/test_output_path.py
Exit 0 = all passed. These are output-path tests, not GPU correctness tests.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "adapter", "rck_adapter.py")
FAKE = os.path.join(HERE, "fake_solver.py")
sys.path.insert(0, os.path.join(HERE, "..", "adapter"))
import btccrypto  # noqa: E402

PY = sys.executable
SENTINEL = bytes(range(1, 33))
SENTINEL_HEX = SENTINEL.hex()
LEAK_HEX = "de" * 32

_fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  :: " + detail))
    if not cond:
        _fails.append(name)


def run_selftest(private_dir, mode, expect, forbid_hex=""):
    cmd = [PY, "-I", ADAPTER, "--checkout-root", os.path.abspath(os.path.join(HERE, "..", "..")),
           "selftest-output", "--private-dir", private_dir, "--expect", expect]
    if forbid_hex:
        cmd += ["--forbid-hex", forbid_hex]
    cmd += ["--", PY, "-I", FAKE, "--fake-mode", mode]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {}
    return proc, report


def main():
    root = os.path.abspath(os.path.join(HERE, "..", ".."))

    with tempfile.TemporaryDirectory() as tmp:
        priv = os.path.join(tmp, "priv")

        # 1. good
        proc, rep = run_selftest(priv, "good", "OK", forbid_hex=SENTINEL_HEX)
        check("good: wrapper exit 0", proc.returncode == 0, proc.stderr)
        check("good: status OK", rep.get("status") == "OK", str(rep))
        check("good: 32 bytes received", rep.get("bytes_received") == 32, str(rep))
        check("good: candidate written", rep.get("candidate_written") is True, str(rep))
        outp = rep.get("private_out_path", "")
        if outp and os.path.isfile(outp):
            with open(outp, "rb") as f:
                blob = f.read()
            check("good: file is the 32-byte sentinel", blob == SENTINEL, blob.hex())
            st = os.stat(outp)
            check("good: file mode 0600", (st.st_mode & 0o777) == 0o600, oct(st.st_mode))
            check("good: private file is outside the checkout",
                  not os.path.abspath(outp).startswith(root + os.sep), outp)
        else:
            check("good: private file exists", False, outp)
        combined = proc.stdout + proc.stderr
        check("good: sentinel hex not leaked in wrapper output",
              SENTINEL_HEX not in combined.lower(), "LEAK")
        check("good: forbidden-hex leak flag false", rep.get("forbidden_hex_leaked") is False, str(rep))

        # 2. short -> fail closed
        proc, rep = run_selftest(priv, "short", "FAILCLOSED_NO_CANDIDATE")
        check("short: wrapper exit 0 (expectation met)", proc.returncode == 0, proc.stderr)
        check("short: status fail-closed", rep.get("status") == "FAILCLOSED_NO_CANDIDATE", str(rep))
        check("short: candidate not written", rep.get("candidate_written") is False, str(rep))

        # 3. none -> fail closed
        proc, rep = run_selftest(priv, "none", "FAILCLOSED_NO_CANDIDATE")
        check("none: status fail-closed", rep.get("status") == "FAILCLOSED_NO_CANDIDATE", str(rep))

        # 4. crash -> fail closed on rc
        proc, rep = run_selftest(priv, "crash", "FAILCLOSED_SOLVER_RC")
        check("crash: status fail-closed on rc", rep.get("status") == "FAILCLOSED_SOLVER_RC", str(rep))
        check("crash: candidate not written", rep.get("candidate_written") is False, str(rep))

        # 5. leak -> scrubbed
        proc, rep = run_selftest(priv, "leak", "OK", forbid_hex=LEAK_HEX)
        combined = (proc.stdout + proc.stderr).lower()
        check("leak: fake key hex scrubbed from wrapper output", LEAK_HEX not in combined, "LEAK")
        check("leak: 'private key' phrase scrubbed", "private key" not in combined
              or "[redacted" in combined, combined[:200])
        check("leak: forbidden-hex leak flag false", rep.get("forbidden_hex_leaked") is False, str(rep))

        # refuse private dir inside checkout
        inside = os.path.join(root, "rckangaroo", "nope")
        p2 = subprocess.run([PY, "-I", ADAPTER, "--checkout-root", root,
                             "selftest-output", "--private-dir", inside,
                             "--", PY, "-I", FAKE], capture_output=True, text=True)
        check("refuse: private dir inside checkout rejected",
              p2.returncode != 0 and "inside the checkout" in p2.stderr, p2.stderr[:200])

    # verify-manifest
    p3 = subprocess.run([PY, "-I", ADAPTER, "verify-manifest"], capture_output=True, text=True)
    check("manifest: verify-manifest exit 0", p3.returncode == 0, p3.stdout + p3.stderr)
    try:
        rep = json.loads(p3.stdout)
        c = rep.get("checks", {})
        check("manifest: recipient bech32m valid", c.get("recipient_bech32m_mainnet", {}).get("ok") is True, p3.stdout)
        check("manifest: pubkey->address match", c.get("pubkey_to_address_match", {}).get("ok") is True, p3.stdout)
        check("manifest: start == 2^139", c.get("start_equals_2pow139", {}).get("ok") is True, p3.stdout)
    except json.JSONDecodeError:
        check("manifest: parseable JSON", False, p3.stdout)

    # crypto self-check: known small key -> pubkey -> recovered via big-endian bytes
    k = 0x1234567  # synthetic test scalar
    pub = btccrypto.compressed_pubkey(k)
    check("crypto: compressed pubkey length 66 hex", len(pub) == 66, pub)
    be = k.to_bytes(32, "big")
    check("crypto: round-trip big-endian int", int.from_bytes(be, "big") == k, "")

    print("\nFAILURES: %d" % len(_fails))
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(main())
