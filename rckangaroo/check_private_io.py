#!/usr/bin/env python3
"""Offline, CPU-only acceptance check for the RCKangaroo private-I/O sink.

Run:  python3 -I -B rckangaroo/check_private_io.py
Exit 0 iff every check passes.

Scope and honesty
------------------
This verifies the *CPU-side* behaviour and policy of the candidate-fd private
sink (the Python wrapper `adapter/rck_adapter.py`) and the *static* integrity of
the patched C++ sink. It drives the wrapper against synthetic fake solvers with
REAL subprocesses and asserts fail-closed / no-leak behaviour for:

  good, fd>=3, noisy/pipe-filling child (no deadlock), silent hang (deadline),
  32-bytes-held-open-no-EOF, 33-byte over-long frame, 10-byte short frame,
  empty frame, crashing solver, symlink target (no-follow), pre-existing file
  (no-overwrite), and decimal/hex/base64 key-shaped log output (leak scrub).

It also unit-checks the leak regex, the physical (realpath) checkout escape
guard, and the pinned-manifest tamper rejection, and statically confirms the
patched C++ source rejects fd 0/1/2, removes the stdout "PRIVATE KEY" print and
the RESULTS.TXT writer, and preserves the GPLv3 license and upstream pin. It
regenerates nothing and downloads nothing.

NOT covered here (and deliberately marked UNAVAILABLE in the item result):
building the CUDA solver and running the GPU known-answer test. No GPU / CUDA
toolchain is assumed. This check makes NO ECDLP / performance claim.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.realpath(os.path.join(HERE, os.pardir))
ADAPTER_DIR = os.path.join(HERE, "adapter")
ADAPTER = os.path.join(ADAPTER_DIR, "rck_adapter.py")
PATCH = os.path.join(HERE, "patches", "0001-candidate-fd-key-sink.patch")
CPP = os.path.join(HERE, "upstream", "RCKangaroo.cpp")
LICENSE = os.path.join(HERE, "upstream", "LICENSE.TXT")
PROVENANCE = os.path.join(HERE, "PROVENANCE.json")
SHA256SUMS = os.path.join(HERE, "SHA256SUMS.txt")
MANIFEST = os.path.join(ADAPTER_DIR, "manifest_140.json")

PY = sys.executable
SENTINEL = bytes(range(1, 33))
SENTINEL_HEX = SENTINEL.hex()

sys.path.insert(0, ADAPTER_DIR)
import rck_adapter  # noqa: E402  (CPU logic under test)

_fails = []
_npass = 0


def check(name, cond, detail=""):
    global _npass
    if cond:
        _npass += 1
        print("PASS " + name)
    else:
        _fails.append(name)
        print("FAIL " + name + ("  :: " + str(detail) if detail else ""))


# --- a single parametric fake solver, materialised to a temp file -----------
FAKE_SOLVER = r'''
import os, sys, time, base64
def getarg(name, default=None):
    a = sys.argv
    for i, x in enumerate(a):
        if x == name and i + 1 < len(a):
            return a[i + 1]
    return default
mode = getarg("--mode", "good")
fd = int(getarg("--candidate-fd", "-1"))
S = bytes(range(1, 33))
if mode == "leak_hex":
    sys.stdout.write("PRIVATE KEY: %s\n" % ("de" * 32)); sys.stdout.flush()
    sys.stderr.write("fatal dump key=%s\n" % ("ab" * 32)); sys.stderr.flush()
elif mode == "leak_dec":
    sys.stdout.write("recovered scalar = %d\n" % ((1 << 139) + 777)); sys.stdout.flush()
elif mode == "leak_b64":
    sys.stdout.write("blob=%s\n" % base64.b64encode(S).decode()); sys.stdout.flush()
elif mode == "hang_noisy":
    os.write(1, b"X" * (512 * 1024))
elif mode == "noisy_ok":
    os.write(1, b"progress line\n" * 2000)
if mode in ("good", "crash", "leak_hex", "leak_dec", "leak_b64",
            "hang_noisy", "noisy_ok"):
    if fd >= 0:
        os.write(fd, S); os.close(fd)
elif mode == "fdbyte":
    if fd >= 0:
        os.write(fd, bytes([min(fd, 255)]) + S[1:]); os.close(fd)
elif mode == "short":
    if fd >= 0:
        os.write(fd, S[:10]); os.close(fd)
elif mode == "extra33":
    if fd >= 0:
        os.write(fd, S + b"\x99"); os.close(fd)
elif mode == "none":
    if fd >= 0:
        os.close(fd)
elif mode == "hold32":
    if fd >= 0:
        os.write(fd, S)   # keep fd OPEN: no EOF
    time.sleep(30)
elif mode == "hang_silent":
    time.sleep(30)
sys.exit(7 if mode == "crash" else 0)
'''


def run_sel(tmp, mode, expect, timeout=8.0, forbid_hex="", out_file=None,
            pre_symlink=False, pre_file=False, extra_args=None):
    """Drive adapter selftest-output against the fake solver in a fresh priv dir."""
    priv = tempfile.mkdtemp(dir=tmp)
    target = out_file
    if (pre_symlink or pre_file) and target is None:
        target = os.path.join(priv, "candidate.target.bin")
    if pre_symlink:
        os.symlink(os.path.join(tmp, "elsewhere.bin"), target)
    if pre_file:
        with open(target, "wb") as f:
            f.write(b"preexisting")
    cmd = [PY, "-I", "-B", ADAPTER, "--checkout-root", REPO_ROOT,
           "selftest-output", "--private-dir", priv, "--expect", expect,
           "--timeout", str(timeout)]
    if forbid_hex:
        cmd += ["--forbid-hex", forbid_hex]
    if target:
        cmd += ["--out-file", target]
    if extra_args:
        cmd += extra_args
    cmd += ["--", PY, "-I", "-B", FS, "--mode", mode]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 25)
    try:
        rep = json.loads(proc.stdout)
    except json.JSONDecodeError:
        rep = {}
    return proc, rep, priv, target


def behavioural(tmp):
    # 1. good
    proc, rep, priv, _ = run_sel(tmp, "good", "OK", forbid_hex=SENTINEL_HEX)
    check("good: exit 0", proc.returncode == 0, proc.stderr[-300:])
    check("good: status OK", rep.get("status") == "OK", rep)
    check("good: 32 bytes", rep.get("bytes_received") == 32, rep)
    check("good: eof confirmed", rep.get("eof_confirmed") is True, rep)
    check("good: written", rep.get("candidate_written") is True, rep)
    outp = rep.get("private_out_path", "")
    if outp and os.path.isfile(outp):
        with open(outp, "rb") as f:
            blob = f.read()
        check("good: file == sentinel", blob == SENTINEL, blob.hex())
        check("good: mode 0600", (os.stat(outp).st_mode & 0o777) == 0o600,
              oct(os.stat(outp).st_mode))
        check("good: file outside checkout",
              not os.path.realpath(outp).startswith(REPO_ROOT + os.sep), outp)
    else:
        check("good: file exists", False, outp)
    combined = (proc.stdout + proc.stderr).lower()
    check("good: sentinel hex absent from wrapper output",
          SENTINEL_HEX not in combined, "LEAK")
    check("good: forbidden-hex flag false",
          rep.get("forbidden_hex_leaked") is False, rep)

    # 2. fd >= 3 actually handed to child
    proc, rep, priv, _ = run_sel(tmp, "fdbyte", "OK")
    outp = rep.get("private_out_path", "")
    first = None
    if outp and os.path.isfile(outp):
        with open(outp, "rb") as f:
            first = f.read(1)
    check("fd: child received fd >= 3",
          first is not None and first[0] >= 3, first)

    # 3. noisy pipe-filling child must NOT deadlock
    proc, rep, priv, _ = run_sel(tmp, "hang_noisy", "OK", timeout=8.0)
    check("noisy: no deadlock, status OK", rep.get("status") == "OK", rep)
    check("noisy: stdout drained (>256KB counted)",
          rep.get("stdout_bytes", 0) >= 256 * 1024, rep)

    # 3b. ordinary noisy-but-fine child
    proc, rep, priv, _ = run_sel(tmp, "noisy_ok", "OK", timeout=8.0)
    check("noisy_ok: status OK", rep.get("status") == "OK", rep)

    # 4. silent hang -> deadline fail-closed
    proc, rep, priv, _ = run_sel(tmp, "hang_silent", "FAILCLOSED_TIMEOUT",
                                 timeout=2.0)
    check("hang: fail-closed on deadline",
          rep.get("status") == "FAILCLOSED_TIMEOUT", rep)
    check("hang: timed_out flag", rep.get("timed_out") is True, rep)
    check("hang: not written", rep.get("candidate_written") is False, rep)

    # 5. 32 bytes but fd held open (no EOF) -> fail-closed
    proc, rep, priv, _ = run_sel(tmp, "hold32", "FAILCLOSED_TIMEOUT",
                                 timeout=2.0)
    check("hold32: fail-closed (no clean EOF)",
          rep.get("status") == "FAILCLOSED_TIMEOUT", rep)
    check("hold32: not written", rep.get("candidate_written") is False, rep)

    # 6. 33-byte over-long frame -> extra detected
    proc, rep, priv, _ = run_sel(tmp, "extra33", "FAILCLOSED_EXTRA_BYTES")
    check("extra33: extra bytes detected",
          rep.get("status") == "FAILCLOSED_EXTRA_BYTES"
          and rep.get("extra_bytes_detected") is True, rep)
    check("extra33: not written", rep.get("candidate_written") is False, rep)

    # 7. short frame
    proc, rep, priv, _ = run_sel(tmp, "short", "FAILCLOSED_NO_CANDIDATE")
    check("short: fail-closed", rep.get("status") == "FAILCLOSED_NO_CANDIDATE", rep)

    # 8. empty frame
    proc, rep, priv, _ = run_sel(tmp, "none", "FAILCLOSED_NO_CANDIDATE")
    check("none: fail-closed", rep.get("status") == "FAILCLOSED_NO_CANDIDATE", rep)

    # 9. crash (nonzero rc)
    proc, rep, priv, _ = run_sel(tmp, "crash", "FAILCLOSED_SOLVER_RC")
    check("crash: fail-closed on rc",
          rep.get("status") == "FAILCLOSED_SOLVER_RC", rep)
    check("crash: not written", rep.get("candidate_written") is False, rep)

    # 10. symlink target -> O_NOFOLLOW refuses
    proc, rep, priv, tgt = run_sel(tmp, "good", "FAILCLOSED_SINK_OPEN",
                                   pre_symlink=True)
    check("symlink: sink open refused (no-follow)",
          rep.get("status") == "FAILCLOSED_SINK_OPEN", rep)
    check("symlink: not written", rep.get("candidate_written") is False, rep)
    check("symlink: link target not created/written",
          not os.path.exists(os.path.join(tmp, "elsewhere.bin")), "WROTE THROUGH LINK")

    # 11. pre-existing file -> O_EXCL refuses overwrite
    proc, rep, priv, tgt = run_sel(tmp, "good", "FAILCLOSED_SINK_OPEN",
                                   pre_file=True)
    check("overwrite: sink open refused (exclusive)",
          rep.get("status") == "FAILCLOSED_SINK_OPEN", rep)
    if tgt and os.path.isfile(tgt):
        with open(tgt, "rb") as f:
            check("overwrite: existing file untouched",
                  f.read() == b"preexisting", "CLOBBERED")

    # 12. leak scrubbing (hex / decimal / base64)
    for mode, tok in (("leak_hex", "de" * 32),
                      ("leak_dec", str((1 << 139) + 777)),
                      ("leak_b64", base64.b64encode(SENTINEL).decode())):
        proc, rep, priv, _ = run_sel(tmp, mode, "OK", forbid_hex=tok)
        combined = (proc.stdout + proc.stderr)
        check("%s: token absent from wrapper output" % mode,
              tok not in combined, "LEAK")
        check("%s: leak pattern detected internally" % mode,
              rep.get("leak_pattern_detected") is True, rep)
        check("%s: forbidden token did not survive scrub" % mode,
              rep.get("forbidden_hex_leaked") is False, rep)

    # 13. private dir inside checkout refused
    inside = os.path.join(REPO_ROOT, "rckangaroo", "nope_priv")
    p = subprocess.run([PY, "-I", "-B", ADAPTER, "--checkout-root", REPO_ROOT,
                        "selftest-output", "--private-dir", inside,
                        "--", PY, "-I", "-B", FS, "--mode", "good"],
                       capture_output=True, text=True, timeout=30)
    check("refuse: private dir inside checkout rejected",
          p.returncode != 0 and "inside the checkout" in p.stderr,
          p.stderr[:200])
    check("refuse: no dir created inside checkout",
          not os.path.exists(inside), inside)


def unit_checks(tmp):
    # leak regex
    check("regex: 64-hex flagged", rck_adapter.leak_detected("x " + "de" * 32))
    check("regex: decimal scalar flagged",
          rck_adapter.leak_detected("k=%d" % ((1 << 140) - 1)))
    check("regex: base64 blob flagged",
          rck_adapter.leak_detected(base64.b64encode(SENTINEL).decode()))
    check("regex: 'private key' phrase flagged",
          rck_adapter.leak_detected("Private Key: redacted"))
    check("regex: benign text not flagged",
          not rck_adapter.leak_detected("MAIN MODE\nSpeed: 123 MKeys/s\nDP 14"))

    # physical (realpath) checkout escape guard
    raised = False
    try:
        rck_adapter._refuse_inside_checkout(
            os.path.join(REPO_ROOT, "rckangaroo", "x"), None, "t")
    except SystemExit:
        raised = True
    check("escape: direct in-checkout path refused", raised)

    raised = False
    try:
        rck_adapter._refuse_inside_checkout(
            os.path.join(REPO_ROOT, "rckangaroo", "..", "rckangaroo", "y"),
            None, "t")
    except SystemExit:
        raised = True
    check("escape: dotdot-normalised in-checkout path refused", raised)

    # symlink that points back inside the checkout must be refused physically
    link = os.path.join(tmp, "sneaky_link")
    os.symlink(REPO_ROOT, link)
    raised = False
    try:
        rck_adapter._refuse_inside_checkout(
            os.path.join(link, "rckangaroo", "z"), None, "t")
    except SystemExit:
        raised = True
    check("escape: symlink-into-checkout refused physically", raised)

    # a genuinely-outside path is accepted
    outside = os.path.join(tmp, "ok_outside")
    ok = True
    try:
        rck_adapter._refuse_inside_checkout(outside, None, "t")
    except SystemExit:
        ok = False
    check("escape: outside path accepted", ok)

    # pinned-manifest tamper rejection
    m, digest = rck_adapter.load_pinned_manifest(MANIFEST)
    check("manifest: shipped manifest loads & matches pins", m is not None)
    check("manifest: sha256 matches pin",
          digest == rck_adapter.EXPECTED_MANIFEST_SHA256, digest)

    for field, mangle in (
            ("recipient", lambda d: d["recipient"].__setitem__(
                "address", "bc1qtamperedrecipientxxxxxxxxxxxxxxxxxxxxxx")),
            ("pubkey", lambda d: d.__setitem__("pubkey_compressed", "02" + "00" * 32)),
            ("address", lambda d: d.__setitem__("address", "1TamperedAddrzzz")),
            ("start", lambda d: d["interval"].__setitem__(
                "rckangaroo_start_hex", "40000000000000000000000000000000000"))):
        raw = json.loads(open(MANIFEST).read())
        mangle(raw)
        tf = os.path.join(tmp, "tampered_%s.json" % field)
        with open(tf, "w") as f:
            json.dump(raw, f)
        raised = False
        try:
            rck_adapter.load_pinned_manifest(tf)
        except rck_adapter.ManifestError:
            raised = True
        check("manifest: tampered %s rejected" % field, raised)

    # verify-manifest subcommand on the real (shipped) manifest
    p = subprocess.run([PY, "-I", "-B", ADAPTER, "verify-manifest"],
                       capture_output=True, text=True, timeout=60)
    check("manifest: verify-manifest exit 0", p.returncode == 0, p.stderr[:200])
    try:
        rep = json.loads(p.stdout)
        c = rep.get("checks", {})
        check("manifest: recipient bech32m valid",
              c.get("recipient_bech32m_mainnet", {}).get("ok") is True, p.stdout)
        check("manifest: pubkey->address match",
              c.get("pubkey_to_address_match", {}).get("ok") is True, p.stdout)
        check("manifest: start == 2^139",
              c.get("start_equals_2pow139", {}).get("ok") is True, p.stdout)
    except json.JSONDecodeError:
        check("manifest: verify-manifest parseable", False, p.stdout[:200])


def static_checks():
    cpp = open(CPP, encoding="utf-8", errors="replace").read()
    patch = open(PATCH, encoding="utf-8", errors="replace").read()
    lic = open(LICENSE, encoding="utf-8", errors="replace").read()
    prov = json.loads(open(PROVENANCE).read())

    check("cpp: candidate-fd option present", "--candidate-fd" in cpp)
    check("cpp: rejects fd 0/1/2 (>= 3 guard)", "gCandidateFd < 3" in cpp)
    check("cpp: no stdout PRIVATE KEY print",
          "PRIVATE KEY:" not in cpp.replace("NEVER written", ""))
    check("cpp: RESULTS.TXT writer removed", 'fopen("RESULTS.TXT"' not in cpp)
    check("patch: fd>=3 guard in patch", "gCandidateFd < 3" in patch)

    # patch applies/reverses consistently against the vendored patched source
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, "rckangaroo", "upstream")
        os.makedirs(dst)
        shutil.copy(CPP, os.path.join(dst, "RCKangaroo.cpp"))
        r = subprocess.run(["git", "apply", "--reverse", "-p1", PATCH],
                           cwd=td, capture_output=True, text=True)
        pristine_ok = r.returncode == 0
        check("patch: reverse-applies to vendored source", pristine_ok,
              r.stderr[:200])
        if pristine_ok:
            h = hashlib.sha256(
                open(os.path.join(dst, "RCKangaroo.cpp"), "rb").read()).hexdigest()
            exp = prov["vendored_source_files"]["patched_file"]["pristine_sha256"]
            check("patch: recovered pristine matches recorded hash", h == exp, h)

    # license + pin preserved
    check("license: GPLv3 preserved",
          "GNU GENERAL PUBLIC LICENSE" in lic and "Version 3" in lic)
    check("provenance: upstream commit pinned",
          prov.get("upstream", {}).get("pinned_commit") ==
          "618473acd7f5e696be5ec4f8377c18cc55c1361c")

    # provenance hash bookkeeping for the two changed vendored artifacts
    pf = prov["vendored_source_files"]["patched_file"]
    actual_cpp = hashlib.sha256(open(CPP, "rb").read()).hexdigest()
    actual_patch = hashlib.sha256(open(PATCH, "rb").read()).hexdigest()
    check("provenance: patched_sha256 matches file",
          pf["patched_sha256"] == actual_cpp, actual_cpp)
    check("provenance: patch_sha256 matches file",
          pf["patch_sha256"] == actual_patch, actual_patch)


def sha256sums_check():
    base = HERE
    recorded = {}
    for line in open(SHA256SUMS):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        h, _, path = line.partition("  ")
        recorded[path] = h
    bad = []
    missing = []
    for path, h in recorded.items():
        fp = os.path.normpath(os.path.join(base, path))
        if not os.path.isfile(fp):
            missing.append(path)
            continue
        actual = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        if actual != h:
            bad.append(path)
    check("sums: SHA256SUMS all present", not missing, missing)
    check("sums: SHA256SUMS all match", not bad, bad)


def main():
    global FS
    with tempfile.TemporaryDirectory() as tmp:
        FS = os.path.join(tmp, "fs.py")
        with open(FS, "w") as f:
            f.write(FAKE_SOLVER)
        print("== behavioural subprocess tests ==")
        behavioural(tmp)
        print("\n== unit checks ==")
        unit_checks(tmp)
    print("\n== static / provenance checks ==")
    static_checks()
    sha256sums_check()

    print("\nPASSED: %d   FAILED: %d" % (_npass, len(_fails)))
    if _fails:
        print("FAILURES:")
        for n in _fails:
            print("  - " + n)
        return 1
    print("ALL CHECKS PASSED (CPU/private-I/O). "
          "CUDA build + GPU KAT remain UNAVAILABLE (no GPU/toolchain assumed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
