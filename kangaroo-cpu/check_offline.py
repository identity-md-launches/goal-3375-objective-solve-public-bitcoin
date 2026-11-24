#!/usr/bin/env python3
"""Mandatory offline acceptance check for the kangaroo-cpu comparator (SYNTHETIC ONLY).

Run from the repository root:   python3 -I -B kangaroo-cpu/check_offline.py [--rebuild] [--json FILE]

No network, no downloads, no toolchain required.  The native backend is the vendored,
statically linked binary bin/kangaroo-linux-x86_64-static (sha256 pinned in PROVENANCE.json,
built from upstream/ + patches/ by build.py --static).  If that binary is missing, has the
wrong hash or cannot execute here, the check FAILS (exit 1): a missing backend is never a
skipped pass.  --rebuild additionally builds from source with a local C++ compiler and runs
the endpoint KATs on that build (informational; it never replaces the vendored backend).

Gates (all mandatory, all against the real native backend on generated synthetic fixtures):
  provenance   vendored upstream files, patches and binary match their pinned sha256
  unit         pure-Python unit tests (fixtures, verifier, refusals, width bound)
  backend      vendored binary executes and reports the pinned upstream version
  kat          known-answer cases incl. lower endpoint (formerly the point-at-infinity
               failure), singleton, start+1, end-1, upper endpoint and high offsets near n
               and at 2^255; every answer is re-verified independently in Python
  threads      1- vs 2-thread runs: solve KAT plus a bounded (-m) counted-jump rate run
  resume       -w/-wi/-ws work file, SIGKILL, resume with -i, solve and verify
  refusal      #140 key/interval and width > 2^125 refused before any process starts
Output: a JSON summary without key material (synthetic answers are only compared, never printed).
The objective (Bitcoin Puzzle #140) is not attempted here and stays INCOMPLETE.
"""
import argparse, hashlib, json, os, platform, shutil, subprocess, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kcpu  # noqa: E402

P140 = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
RESULTS = {"component": "kangaroo-cpu native JLP comparator (synthetic only)", "gates": {},
           "failures": [], "objectiveStatus": "INCOMPLETE",
           "units": {"elapsed_total_s": "s wall, process start to exit",
                     "time_to_first_thread_start_s": "s wall until 'SolveKeyCPU Thread' (startup: parse, tables, herd setup)",
                     "search_s_after_thread_start": "s wall after first thread start (walk)",
                     "peak_rss_kib_task_process": "KiB, wait4 ru_maxrss of the kangaroo process; Linux keeps the forking Python parent's peak across exec, so values at ~that floor mean <= floor",
                     "vmhwm_kib_sampled": "KiB, max VmHWM of the kangaroo process from /proc sampled every ~0.1 s (null if it exited before the first sample)",
                     "session_group_ops": "exact jump (group addition) count from [KCPU-COUNT]",
                     "group_ops_per_s": "session_group_ops / search_s_after_thread_start"}}


def sha256(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def fail(gate, msg):
    RESULTS["failures"].append({"gate": gate, "error": msg})


def slim(r):
    keep = ("label", "width_bits", "where", "threads", "max_step", "exit_status", "killed", "solved", "verified",
            "aborted", "endpoint_resolved", "session_group_ops", "offset_group_ops_from_workfile",
            "elapsed_total_s", "time_to_first_thread_start_s", "search_s_after_thread_start", "group_ops_per_s",
            "peak_rss_kib_task_process", "vmhwm_kib_sampled", "cpu_user_s", "cpu_sys_s", "range_width_log2", "dp_used",
            "expected_ops_log2", "fetch_kangaroos")
    return {k: r.get(k) for k in keep}


def gate_provenance(prov):
    bad = []
    for rel, h in prov["upstream_files_sha256"].items():
        p = os.path.join(HERE, "upstream", rel)
        if not os.path.isfile(p) or sha256(p) != h:
            bad.append("upstream/" + rel)
    for rel, h in prov["patches_sha256"].items():
        p = os.path.join(HERE, "patches", rel)
        if not os.path.isfile(p) or sha256(p) != h:
            bad.append("patches/" + rel)
    vb = prov.get("vendored_binary", {})
    bp = os.path.join(HERE, vb.get("path", "bin/missing"))
    if not os.path.isfile(bp):
        bad.append("MISSING backend binary " + vb.get("path", "?"))
    elif sha256(bp) != vb.get("sha256"):
        bad.append("backend binary hash mismatch " + vb["path"])
    lic = os.path.join(HERE, "upstream", "LICENSE.txt")
    if "GNU GENERAL PUBLIC LICENSE" not in open(lic, errors="replace").read():
        bad.append("upstream GPL license text missing")
    for b in bad:
        fail("provenance", b)
    RESULTS["gates"]["provenance"] = "pass" if not bad else "FAIL"
    RESULTS["binary"] = {"path": "kangaroo-cpu/" + vb.get("path", "?"), "sha256": vb.get("sha256"),
                         "bytes": vb.get("bytes")}
    return bp if not bad else None


def gate_unit():
    sys.path.insert(0, os.path.join(HERE, "tests"))
    import test_kcpu
    suite = unittest.TestLoader().loadTestsFromTestCase(test_kcpu.Pure)
    with open(os.devnull, "w") as dn:
        res = unittest.TextTestRunner(stream=dn, verbosity=0).run(suite)
    RESULTS["unit"] = {"run": res.testsRun, "failures": len(res.failures), "errors": len(res.errors)}
    for t, tb in res.failures + res.errors:
        fail("unit", "%s: %s" % (t.id(), tb.strip().splitlines()[-1]))
    ok = res.wasSuccessful() and res.testsRun > 0
    RESULTS["gates"]["unit"] = "pass" if ok else "FAIL"


def gate_backend(bp):
    if bp is None:
        fail("backend", "no verified backend binary; cannot run native checks (not skipped: failed)")
        RESULTS["gates"]["backend"] = "FAIL"
        return None
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        fail("backend", "vendored backend is Linux x86-64 only; this host is %s/%s. Build with "
             "kangaroo-cpu/build.py and pass --binary." % (platform.system(), platform.machine()))
        RESULTS["gates"]["backend"] = "FAIL"
        return None
    if not os.access(bp, os.X_OK):
        try:
            os.chmod(bp, 0o755)
        except OSError:
            pass
    try:
        r = subprocess.run([bp, "-v"], capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
    except OSError as e:
        fail("backend", "backend does not execute: %s" % e)
        RESULTS["gates"]["backend"] = "FAIL"
        return None
    RESULTS["backend_version"] = out.splitlines()[0] if out else ""
    if "Kangaroo v2.2" not in out:
        fail("backend", "unexpected backend version output: %r" % out[:200])
        RESULTS["gates"]["backend"] = "FAIL"
        return None
    RESULTS["gates"]["backend"] = "pass"
    return bp


def fixtures():
    return {c["label"]: c for c in json.load(open(os.path.join(HERE, "fixtures", "fixtures.json")))["cases"]}


# label -> expectation ("endpoint": resolved exactly with 0 walk ops; "walk": solved by kangaroo walk)
KATS = [("SYNTHETIC-w36-start-endpoint", "endpoint"),
        ("SYNTHETIC-w28-high-offset-2^255", "endpoint"),
        ("SYNTHETIC-w24-high-offset-near-n-start-endpoint", "endpoint"),
        ("SYNTHETIC-w0-singleton", "endpoint"),
        ("SYNTHETIC-w12-start-plus-one", "walk"),
        ("SYNTHETIC-w16-end-minus-one", "walk"),
        ("SYNTHETIC-w32-random", "walk"),
        ("SYNTHETIC-w36-end-endpoint", "walk"),
        ("SYNTHETIC-w20-narrow-high-offset-near-n", "walk"),
        ("SYNTHETIC-w24-narrow-high-offset-end-endpoint", "walk")]


def run_kats(bp, gate, fx):
    out, ok = [], True
    for lab, kind in KATS:
        r = kcpu.run_job(bp, fx[lab], threads=1, max_step=8.0, timeout=180)
        s = slim(r); s["expect"] = kind; out.append(s)
        problems = []
        if not r["verified"]:
            problems.append("not solved/verified")
        if kind == "endpoint" and not (r["endpoint_resolved"] and r["session_group_ops"] == 0):
            problems.append("lower endpoint not resolved exactly (endpoint=%s ops=%s)" % (r["endpoint_resolved"], r["session_group_ops"]))
        if kind == "walk" and not (r["session_group_ops"] or 0) > 0:
            problems.append("no counted jumps for a walk case")
        if problems:
            ok = False
            fail(gate, "%s: %s" % (lab, "; ".join(problems)))
    return out, ok


def gate_threads(bp, fx):
    ncpu = os.cpu_count() or 1
    t2 = 2 if ncpu >= 2 else 1
    rec = {"os_cpu_count_visible": ncpu, "threads_compared": [1, t2], "solve": [], "bounded_rate": []}
    ok = True
    for t in (1, t2):
        r = kcpu.run_job(bp, fx["SYNTHETIC-w40-thread-kat"], threads=t, max_step=8.0, timeout=300)
        rec["solve"].append(slim(r))
        if not r["verified"] or not (r["session_group_ops"] or 0) > 0:
            ok = False; fail("threads", "w40 solve with %d thread(s) not verified" % t)
    # bounded counted-jump run: -m 0.004 of expected ops on a 2^56 synthetic interval (not expected to solve)
    for t in (1, t2):
        r = kcpu.run_job(bp, fx["SYNTHETIC-w56-rate-bounded"], threads=t, max_step=0.004, timeout=300)
        rec["bounded_rate"].append(slim(r))
        if not (r["session_group_ops"] or 0) > 0 or r["exit_status"] != 0:
            ok = False; fail("threads", "bounded w56 run with %d thread(s) produced no counted jumps" % t)
    rr = rec["bounded_rate"]
    if len(rr) == 2 and rr[0].get("group_ops_per_s") and rr[1].get("group_ops_per_s"):
        rec["rate_ratio_2t_over_1t"] = round(rr[1]["group_ops_per_s"] / rr[0]["group_ops_per_s"], 3)
    if t2 == 1:
        rec["note"] = "only one CPU visible: 2-thread comparison not possible on this host"
    rec["scope_note"] = "synthetic 2^40/2^56 runs on this host only; no extrapolation to 2^139 is made"
    RESULTS["threads"] = rec
    RESULTS["gates"]["threads"] = "pass" if ok else "FAIL"


def gate_resume(bp, fx, kill_after):
    f = fx["SYNTHETIC-w50-save-resume"]
    wd = tempfile.mkdtemp(prefix="resume-", dir=kcpu.storage_root())
    ok = True
    try:
        wf = os.path.join(wd, "work.kwf")
        attempts = 0
        while True:  # a lucky early solve (before the first save) leaves nothing to resume: retry, max 5
            attempts += 1
            if os.path.exists(wf):
                os.remove(wf)
            r1 = kcpu.run_job(bp, f, threads=1, max_step=8.0, extra=["-w", wf, "-wi", "1", "-ws"], workdir=wd,
                              kill_after=kill_after, kill_after_file=(wf, 0.5), timeout=120)
            if not r1["verified"] or attempts >= 5:
                break
        size = os.path.getsize(wf) if os.path.exists(wf) else None
        rec = {"interrupt": "SIGKILL >= %.1fs and 0.5s after the first periodic save (-w -wi 1 -ws)" % kill_after, "first_run": slim(r1),
               "workfile_bytes": size, "interrupt_attempts": attempts}
        if r1["verified"]:
            rec["note"] = "first run solved before the interrupt; resume not exercised"
            ok = False; fail("resume", "first run finished before SIGKILL; increase width or lower --kill-after")
        elif not size:
            ok = False; fail("resume", "no work file saved before SIGKILL")
        else:
            r2 = kcpu.run_job(bp, f, threads=1, max_step=8.0, extra=["-i", wf], workdir=wd, timeout=900)
            rec["resumed_run"] = slim(r2)
            if not r2["verified"]:
                ok = False; fail("resume", "resumed run did not solve/verify")
            if not (r2.get("offset_group_ops_from_workfile") or 0) > 0:
                ok = False; fail("resume", "resumed run did not load a non-zero saved jump count")
            if "loaded" not in (r2.get("fetch_kangaroos") or ""):
                ok = False; fail("resume", "resumed run did not report loaded kangaroos")
    finally:
        shutil.rmtree(wd, ignore_errors=True)
    RESULTS["resume"] = rec
    RESULTS["gates"]["resume"] = "pass" if ok else "FAIL"


def gate_refusal(fx):
    w32 = fx["SYNTHETIC-w32-random"]
    cases, ok = [], True
    for s, e, pk, why in [(2**139, 2**140 - 1, P140, "#140 key + interval"),
                          (2**139, 2**140 - 1, w32["pubkey"], "#140 interval, other key"),
                          (2**10, 2**10 + 5, P140, "#140 key, other interval"),
                          (1, 1 + 2**125, w32["pubkey"], "width 2^126 > 2^125 bound")]:
        try:
            kcpu.check_target(s, e, pk); cases.append({"case": why, "refused": False}); ok = False
        except kcpu.Refused:
            cases.append({"case": why, "refused": True})
    try:
        kcpu.check_target(1, 2**125, w32["pubkey"]); cases.append({"case": "width exactly 2^125-1 accepted", "accepted": True})
    except kcpu.Refused:
        cases.append({"case": "width exactly 2^125-1 accepted", "accepted": False}); ok = False
    bad = dict(w32, pubkey=P140, start="%x" % 2**139, end="%x" % (2**140 - 1))
    try:
        kcpu.run_job("/nonexistent/never-executed", bad); cases.append({"case": "run_job #140", "refused": False}); ok = False
    except kcpu.Refused:
        cases.append({"case": "run_job #140 (refused before exec)", "refused": True})
    if kcpu.MAX_WIDTH_BITS != 125:
        ok = False; cases.append({"case": "MAX_WIDTH_BITS == 125", "ok": False})
    if not ok:
        fail("refusal", "a production/oversized target was not refused: %s" % cases)
    RESULTS["refusals"] = cases
    RESULTS["gates"]["refusal"] = "pass" if ok else "FAIL"


def optional_rebuild(fx):
    cxx = os.environ.get("CXX", "g++")
    if shutil.which(cxx.split()[0]) is None or shutil.which("patch") is None:
        RESULTS["rebuild"] = {"status": "not run (no %s or patch on host)" % cxx}
        return
    out = tempfile.mkdtemp(prefix="kcpu-rebuild-")
    try:
        r = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "build.py"), "--out", out, "--jobs", "4",
                            "--static"], capture_output=True, text=True, timeout=900)
        if r.returncode:
            RESULTS["rebuild"] = {"status": "build failed (exit %d)" % r.returncode, "stderr_tail": r.stderr[-800:]}
            return
        info = json.loads(r.stdout.strip().splitlines()[-1])
        res, ok = run_kats(os.path.join(out, "kangaroo"), "rebuild", fx)
        RESULTS["rebuild"] = {"status": "pass" if ok else "FAIL", "sha256": info["sha256"], "cxx": info["cxx"],
                              "same_hash_as_vendored": info["sha256"] == RESULTS["binary"]["sha256"],
                              "kats_passed": sum(1 for x in res if x["verified"]), "kats": len(res)}
    finally:
        shutil.rmtree(out, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", help="use this backend instead of the vendored one (its hash is reported, not pinned)")
    ap.add_argument("--rebuild", action="store_true", help="also build from source and run the KATs on it")
    ap.add_argument("--json", help="also write the full JSON summary here")
    ap.add_argument("--kill-after", type=float, default=1.0)
    a = ap.parse_args()
    t0 = time.monotonic()
    prov = json.load(open(os.path.join(HERE, "PROVENANCE.json")))
    bp = gate_provenance(prov)
    if a.binary:
        bp = os.path.abspath(a.binary)
        RESULTS["binary"] = {"path": bp, "sha256": sha256(bp) if os.path.isfile(bp) else None, "override": True}
        RESULTS["failures"] = [x for x in RESULTS["failures"] if "backend binary" not in x["error"]]
    gate_unit()
    gate_refusal(fixtures())
    bp = gate_backend(bp)
    fx = fixtures()
    if bp:
        kats, ok = run_kats(bp, "kat", fx)
        RESULTS["kat"] = kats
        RESULTS["gates"]["kat"] = "pass" if ok else "FAIL"
        gate_threads(bp, fx)
        gate_resume(bp, fx, a.kill_after)
        if a.rebuild:
            optional_rebuild(fx)
    else:
        for g in ("kat", "threads", "resume"):
            RESULTS["gates"][g] = "FAIL (backend unavailable; not skipped)"
    RESULTS["checks_kind"] = {"real_backend_synthetic": ["kat", "threads", "resume"], "pure_python": ["unit", "refusal"],
                              "hash": ["provenance"], "regtest": "none (not this component)",
                              "production": "unrun by design (#140 refused)"}
    RESULTS["check_wall_s"] = round(time.monotonic() - t0, 1)
    passed = all(v == "pass" for v in RESULTS["gates"].values()) and not RESULTS["failures"]
    RESULTS["status"] = "PASS" if passed else "FAIL"
    txt = json.dumps(RESULTS, indent=1, sort_keys=True)
    if a.json:
        with open(a.json, "w") as f:
            f.write(txt + "\n")
    print(txt)
    print("kangaroo-cpu check_offline: %s gates=%s objectiveStatus=INCOMPLETE" %
          (RESULTS["status"], ",".join("%s:%s" % kv for kv in sorted(RESULTS["gates"].items()))))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
