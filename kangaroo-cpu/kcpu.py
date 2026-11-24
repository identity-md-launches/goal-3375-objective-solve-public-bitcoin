#!/usr/bin/env python3
"""kangaroo-cpu adapter: bounded SYNTHETIC jobs for the pinned JeanLucPons/Kangaroo CPU build.

Comparison harness only.  It refuses production targets:
  * any interval wider than 2^125 (backend limit: 126-bit signed distance field in
    HashTable.h; the adapter refuses rather than editing a range check),
  * the Bitcoin Puzzle #140 public key or interval [2^139, 2^140-1] (explicit deny),
  * any public key that is not re-derived from a fixture's own synthetic scalar
    (so an arbitrary public key cannot be submitted at all).
All upstream stdout, input files, -o key files and work files are written into a
fresh disposable directory under a synthetic storage root and deleted afterwards.
Standard library only.
"""
import hashlib, json, os, pty, re, select, shutil, signal, subprocess, sys, tempfile, time

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
MAX_WIDTH_BITS = 125
DENY_PUBKEYS = {"031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"}
DENY_INTERVALS = {(2**139, 2**140 - 1)}


class Refused(Exception):
    pass


def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0: return None
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r


def compress(pt):
    return ("03" if pt[1] & 1 else "02") + "%064x" % pt[0]


def decompress(h):
    x = int(h[2:], 16); y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P: raise ValueError("not on curve")
    if (y & 1) != int(h[:2], 16) - 2: y = P - y
    return (x, y)


def check_target(start, end, pubkey):
    """Raise Refused for anything this comparison adapter must not run."""
    pk = pubkey.lower()
    if pk in DENY_PUBKEYS or (start, end) in DENY_INTERVALS:
        raise Refused("production target (Bitcoin Puzzle #140) refused by kangaroo-cpu adapter")
    if not (0 < start <= end < N):
        raise Refused("interval must satisfy 0 < start <= end < n")
    width = end - start
    if width.bit_length() > MAX_WIDTH_BITS:
        raise Refused("interval width 2^%d exceeds backend limit 2^%d" % (width.bit_length(), MAX_WIDTH_BITS))
    return width.bit_length()


def make_fixture(seed, label, width_bits, offset=None, where="random"):
    """Deterministic synthetic challenge.  offset defaults to sha256-derived 2^width.. value."""
    h = lambda t: int.from_bytes(hashlib.sha256(("%s|%s|%s" % (seed, label, t)).encode()).digest(), "big")
    width = 2**width_bits - 1
    start = offset if offset is not None else (2**width_bits + h("off") % 2**(width_bits + 8))
    end = start + width
    k = {"start": start, "end": end, "random": start + h("k") % (width + 1)}[where]
    pub = compress(mul(k))
    return {"label": "SYNTHETIC-" + label, "seed": seed, "width_bits": width_bits, "where": where,
            "start": "%x" % start, "end": "%x" % end, "pubkey": pub, "synthetic_key": "%x" % k}


def verify_answer(fx, found_hex):
    """Independent check from the fixture's input interval and public point only."""
    k = int(found_hex, 16)
    s, e = int(fx["start"], 16), int(fx["end"], 16)
    return s <= k <= e and compress(mul(k)) == fx["pubkey"].lower() and mul(k) == decompress(fx["pubkey"])


def _guard(fx):
    s, e = int(fx["start"], 16), int(fx["end"], 16)
    check_target(s, e, fx["pubkey"])
    if not fx.get("label", "").startswith("SYNTHETIC-"):
        raise Refused("only labeled SYNTHETIC- fixtures are accepted")
    if compress(mul(int(fx["synthetic_key"], 16))) != fx["pubkey"].lower():
        raise Refused("pubkey is not derived from the fixture's synthetic scalar")


def storage_root():
    root = os.path.join(tempfile.gettempdir(), "kcpu-synthetic-storage")
    os.makedirs(root, mode=0o700, exist_ok=True)
    return root


def run_job(binary, fx, threads=1, dp=None, max_step=8.0, timeout=600, extra=(), workdir=None,
            kill_after=None, keep=False):
    """Run one bounded synthetic job; returns a measurement dict (no key material)."""
    _guard(fx)
    binary = os.path.abspath(binary)
    own = workdir is None
    wd = workdir or tempfile.mkdtemp(prefix="job-", dir=storage_root())
    try:
        inp = os.path.join(wd, "in.txt")
        with open(inp, "w") as f:
            f.write("%s\n%s\n%s\n" % (fx["start"], fx["end"], fx["pubkey"]))
        outf = os.path.join(wd, "keys.txt")
        cmd = [binary, "-t", str(threads), "-m", str(max_step), "-o", outf]
        if dp is not None: cmd += ["-d", str(dp)]
        cmd += list(extra) + [inp]
        m, s = pty.openpty()  # tty stdout => line-buffered upstream output for timestamps
        t0 = time.monotonic()
        pr = subprocess.Popen(cmd, cwd=wd, stdout=s, stderr=s, stdin=subprocess.DEVNULL)
        os.close(s)
        buf, t_thread, killed = b"", None, False
        while True:
            el = time.monotonic() - t0
            if kill_after is not None and not killed and el > kill_after:
                pr.send_signal(signal.SIGKILL); killed = True
            if el > timeout and not killed:
                pr.send_signal(signal.SIGKILL); killed = True
            r, _, _ = select.select([m], [], [], 0.2)
            if r:
                try: chunk = os.read(m, 65536)
                except OSError: chunk = b""
                if not chunk: break
                buf += chunk
                if t_thread is None and b"SolveKeyCPU Thread" in buf:
                    t_thread = time.monotonic() - t0
            elif pr.poll() is not None:
                break
        _, status, ru = os.wait4(pr.pid, 0)
        elapsed = time.monotonic() - t0
        os.close(m)
        log = buf.decode(errors="replace")
        with open(os.path.join(wd, "stdout.log"), "w") as f: f.write(log)  # quarantined
        found = None
        if os.path.exists(outf):
            mm = re.search(r"Priv:\s*0x([0-9A-Fa-f]+)", open(outf).read())
            found = mm.group(1) if mm else None
        cnt = re.findall(r"\[KCPU-COUNT\] key=\d+ session_group_ops=(\d+) cpu_group_ops=(\d+) offset_group_ops=(\d+)", log)
        res = {"label": fx["label"], "width_bits": fx["width_bits"], "where": fx["where"],
               "threads": threads, "dp": dp, "max_step": max_step,
               "exit_status": os.waitstatus_to_exitcode(status), "killed": killed,
               "elapsed_total_s": round(elapsed, 3),
               "time_to_first_thread_start_s": None if t_thread is None else round(t_thread, 3),
               "search_s_after_thread_start": None if t_thread is None else round(elapsed - t_thread, 3),
               "peak_rss_kib_task_process": ru.ru_maxrss, "cpu_user_s": round(ru.ru_utime, 3),
               "cpu_sys_s": round(ru.ru_stime, 3),
               "session_group_ops": int(cnt[-1][0]) if cnt else None,
               "offset_group_ops_from_workfile": int(cnt[-1][2]) if cnt else None,
               "solved": found is not None, "verified": bool(found) and verify_answer(fx, found),
               "aborted": "Aborted" in log}
        for k, pat in (("range_width_log2", r"Range width: 2\^(\d+)"), ("dp_used", r"DP size: (\d+)"),
                       ("expected_ops_log2", r"Expected operations: 2\^([\d.]+)"),
                       ("fetch_kangaroos", r"FectchKangaroos: (.*)"), ("loaded_header", r"ReadHeader: .*(\[.*\])")):
            mm = re.search(pat, log)
            res[k] = mm.group(1).strip() if mm else None
        if res["session_group_ops"] and res["search_s_after_thread_start"]:
            res["group_ops_per_s"] = round(res["session_group_ops"] / res["search_s_after_thread_start"])
        return res
    finally:
        if own and not keep:
            shutil.rmtree(wd, ignore_errors=True)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--fixtures", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "fixtures.json"))
    ap.add_argument("--label"); ap.add_argument("-t", type=int, default=1); ap.add_argument("-m", type=float, default=8.0)
    a = ap.parse_args()
    for fx in json.load(open(a.fixtures))["cases"]:
        if a.label and fx["label"] != a.label: continue
        try:
            print(json.dumps(run_job(a.binary, fx, threads=a.t, max_step=a.m)))
        except Refused as e:
            print(json.dumps({"label": fx["label"], "refused": str(e)}))
