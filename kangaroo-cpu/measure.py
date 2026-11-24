#!/usr/bin/env python3
"""Run the synthetic measurement suite and write a JSON record (no key material).
Usage: python3 -I kangaroo-cpu/measure.py --binary BUILD/kangaroo --out FILE.json [--threads2 2]"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kcpu

ap = argparse.ArgumentParser()
ap.add_argument("--binary", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--threads2", type=int, default=2); ap.add_argument("--kill-after", type=float, default=3.0)
a = ap.parse_args()
fx = {c["label"]: c for c in json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "fixtures.json")))["cases"]}
rec = {"device_label": "unknown (no task-supplied label)", "os_cpu_count_visible": os.cpu_count(),
       "python": platform.python_version(), "binary_sha256": kcpu.hashlib.sha256(open(a.binary, "rb").read()).hexdigest(),
       "units": {"elapsed": "s wall", "rss": "KiB peak RSS of the kangaroo process (wait4)", "ops": "exact jump/group-addition count from [KCPU-COUNT]"},
       "kat": [], "threads": [], "save_resume": {}, "refusals": []}
for lab in ["SYNTHETIC-w32-random", "SYNTHETIC-w36-start-endpoint", "SYNTHETIC-w36-end-endpoint",
            "SYNTHETIC-w20-narrow-high-offset-near-n", "SYNTHETIC-w24-narrow-high-offset-end-endpoint",
            "SYNTHETIC-w28-high-offset-2^255"]:
    r = kcpu.run_job(a.binary, fx[lab], threads=1, max_step=8.0, timeout=300); rec["kat"].append(r); print(json.dumps(r), flush=True)
for t in (1, a.threads2):
    r = kcpu.run_job(a.binary, fx["SYNTHETIC-w44-thread-scaling"], threads=t, max_step=8.0, timeout=600); rec["threads"].append(r); print(json.dumps(r), flush=True)
# interrupted save/resume
f = fx["SYNTHETIC-w46-save-resume"]
wd = tempfile.mkdtemp(prefix="resume-", dir=kcpu.storage_root())
try:
    wf = os.path.join(wd, "work.kwf")
    r1 = kcpu.run_job(a.binary, f, threads=1, max_step=8.0, extra=["-w", wf, "-wi", "1", "-ws"], workdir=wd, kill_after=a.kill_after)
    info = subprocess.run([os.path.abspath(a.binary), "-winfo", wf], cwd=wd, capture_output=True, text=True, timeout=60).stdout if os.path.exists(wf) else ""
    winfo = {l.split(":")[0].strip(): l.split(":", 1)[1].strip() for l in info.splitlines() if ":" in l and not l.lower().startswith(("start", "stop", "key", "pub"))}
    r2 = kcpu.run_job(a.binary, f, threads=1, max_step=8.0, extra=["-i", wf], workdir=wd, timeout=600)
    rec["save_resume"] = {"interrupt": "SIGKILL after %.1fs with -w -wi 1 -ws" % a.kill_after, "first_run": r1,
                          "workfile_bytes": os.path.getsize(wf) if os.path.exists(wf) else None,
                          "winfo_fields": winfo, "resumed_run": r2,
                          "expected_kangaroos_1thread": 1024}
    print(json.dumps(rec["save_resume"]), flush=True)
finally:
    shutil.rmtree(wd, ignore_errors=True)
for s, e, pk, why in [(2**139, 2**140 - 1, "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640", "#140 key+interval"),
                      (2**139, 2**140 - 1, fx["SYNTHETIC-w32-random"]["pubkey"], "#140 interval, other key"),
                      (1, 2**126, fx["SYNTHETIC-w32-random"]["pubkey"], "width 2^126 > limit")]:
    try: kcpu.check_target(s, e, pk); rec["refusals"].append({"case": why, "refused": False})
    except kcpu.Refused as x: rec["refusals"].append({"case": why, "refused": True, "reason": str(x)})
bad = dict(fx["SYNTHETIC-w32-random"]); bad["pubkey"] = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
bad["start"], bad["end"] = "%x" % 2**139, "%x" % (2**140 - 1)
try: kcpu.run_job(a.binary, bad); rec["refusals"].append({"case": "run_job #140", "refused": False})
except kcpu.Refused as x: rec["refusals"].append({"case": "run_job #140", "refused": True, "reason": str(x)})
json.dump(rec, open(a.out, "w"), indent=1); print("wrote", a.out)
