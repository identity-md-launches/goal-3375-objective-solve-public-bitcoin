#!/usr/bin/env python3
"""Offline, CUDA-free build of the vendored JeanLucPons/Kangaroo (GPLv3) source.

Usage:  python3 -I kangaroo-cpu/build.py --out DIR [--cxx "g++"] [--jobs 2]

Steps (no network): verify vendored file hashes against PROVENANCE.json, copy
upstream/ into DIR/src, apply patches/*.patch with `patch -p1` (sha256 checked),
compile the 16 CPU translation units (the Makefile's non-gpu SRC list) and link
DIR/kangaroo.  Missing prerequisites are reported explicitly and exit 2.
"""
import argparse, concurrent.futures as cf, hashlib, json, os, shlex, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
SRCS = ["SECPK1/IntGroup.cpp", "main.cpp", "SECPK1/Random.cpp", "Timer.cpp", "SECPK1/Int.cpp",
        "SECPK1/IntMod.cpp", "SECPK1/Point.cpp", "SECPK1/SECP256K1.cpp", "Kangaroo.cpp",
        "HashTable.cpp", "Thread.cpp", "Check.cpp", "Backup.cpp", "Network.cpp", "Merge.cpp",
        "PartMerge.cpp"]
CXXFLAGS = ["-m64", "-mssse3", "-Wno-unused-result", "-Wno-write-strings", "-O2", "-I."]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def die(msg, code=2):
    print("BUILD-FAIL: " + msg, file=sys.stderr)
    sys.exit(code)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="build directory (outside the repo or disposable)")
    ap.add_argument("--cxx", default=os.environ.get("CXX", "g++"), help="C++ compiler command")
    ap.add_argument("--jobs", type=int, default=2)
    a = ap.parse_args()
    prov = json.load(open(os.path.join(HERE, "PROVENANCE.json")))
    up = os.path.join(HERE, "upstream")
    for rel, h in prov["upstream_files_sha256"].items():
        p = os.path.join(up, rel)
        if not os.path.isfile(p):
            die("vendored file missing: " + rel)
        if sha256(p) != h:
            die("vendored file hash mismatch: " + rel)
    for rel, h in prov["patches_sha256"].items():
        if sha256(os.path.join(HERE, "patches", rel)) != h:
            die("patch hash mismatch: " + rel)
    cxx = shlex.split(a.cxx)
    if shutil.which(cxx[0]) is None:
        die("C++ compiler not found: %r (install g++ >= 7 or clang++, or pass --cxx)" % a.cxx)
    if shutil.which("patch") is None:
        die("`patch` utility not found (GNU patch required)")
    out = os.path.abspath(a.out)
    src = os.path.join(out, "src")
    if os.path.exists(src):
        shutil.rmtree(src)
    shutil.copytree(up, src)
    for rel in sorted(prov["patches_sha256"]):
        r = subprocess.run(["patch", "-p1", "--forward", "-i", os.path.join(HERE, "patches", rel)],
                           cwd=src, capture_output=True, text=True)
        if r.returncode:
            die("patch %s failed:\n%s%s" % (rel, r.stdout, r.stderr))
    obj = os.path.join(out, "obj")
    os.makedirs(obj, exist_ok=True)
    t0 = time.time()

    def cc(f):
        o = os.path.join(obj, f.replace("/", "_") + ".o")
        r = subprocess.run(cxx + CXXFLAGS + ["-c", f, "-o", o], cwd=src, capture_output=True, text=True)
        return f, o, r

    objs = []
    with cf.ThreadPoolExecutor(max(1, a.jobs)) as ex:
        for f, o, r in ex.map(cc, SRCS):
            if r.returncode:
                die("compile %s failed (exit %d):\n%s" % (f, r.returncode, r.stderr[-4000:]))
            objs.append(o)
    exe = os.path.join(out, "kangaroo")
    r = subprocess.run(cxx + objs + ["-lpthread", "-o", exe], capture_output=True, text=True)
    if r.returncode:
        die("link failed:\n" + r.stderr[-4000:])
    print(json.dumps({"binary": exe, "sha256": sha256(exe), "cxx": a.cxx,
                      "cxxflags": CXXFLAGS, "build_seconds": round(time.time() - t0, 2)}))


if __name__ == "__main__":
    main()
