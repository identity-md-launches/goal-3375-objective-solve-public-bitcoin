#!/usr/bin/env python3
"""prize-state: public, read-only prize evidence collector for ONE address.

Target (hard-coded, not configurable): 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo
(Bitcoin Puzzle #140).  Python 3 standard library only.  No keys, no signing,
no broadcasting, no wallet.  Only HTTP GET to two free public Esplora indexes:
  blockstream: https://blockstream.info/api
  mempool:     https://mempool.space/api

Subcommands
  collect --out DIR [--max-requests N] [--timeout S]   live, bounded collection
  derive  BUNDLE                                       re-derive summary (stdout)
  verify  BUNDLE                                       offline verification, exit 0/1
  claim-input BUNDLE                                   machine-readable claim interface

Every raw HTTP body is stored byte-exact and hashed.  The summary is a pure
function of (manifest.json, raw/ bodies); `verify` recomputes it offline and
requires byte-identical equality, then recomputes every txid from raw hex.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

SCHEMA = "prize-state/v1"
ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
PROVIDERS = {
    "blockstream": "https://blockstream.info/api",
    "mempool": "https://mempool.space/api",
}
PRIOR_OBSERVATION = {
    "note": "HISTORICAL ONLY - never current; superseded by this bundle's own observation",
    "sats": 1400002880,
    "height": 977345,
    "hash": "00000000000000000001caebc8ecdb62adccbd17b4b63816a1f1535c010941d8",
}
LIMITATIONS = [
    "Two Esplora indexes are third-party views, not a validating full node; neither proves proof-of-work or script validity.",
    "Requests are sequential HTTP GETs; equal tip before/after only bounds, does not prove, that address data reflects that tip.",
    "A common confirmed tip across providers does not make mempool data atomic or global: each mempool is a local, unsynchronised view.",
    "Absence of a pending spend in two mempools does not prove none exists elsewhere (unbroadcast or other nodes' mempools).",
    "Freshness decays immediately: any new block or broadcast after observed_until can change the spendable set; re-run before any claim.",
    "Confirmed-history pagination relies on provider ordering; completeness is cross-checked against chain_stats counts and sums.",
]
CHAIN_PAGE = 25
MAX_PAGES = 20
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Fail(Exception):
    pass


# ---------------------------------------------------------------- primitives
def sha256(b):
    return hashlib.sha256(b).digest()


def dsha(b):
    return sha256(sha256(b))


def b58check_decode(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise Fail("bad base58 char")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5 or dsha(raw[:-4])[:4] != raw[-4:]:
        raise Fail("bad base58check checksum")
    return raw[:-4]


def p2pkh_script(addr):
    p = b58check_decode(addr)
    if len(p) != 21 or p[0] != 0:
        raise Fail("not a mainnet P2PKH address")
    return "76a914" + p[1:].hex() + "88ac"


SCRIPT = p2pkh_script(ADDRESS)


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def need_int(v, what, nonneg=True):
    if not is_int(v):
        raise Fail("%s is not an integer: %r" % (what, v))
    if nonneg and v < 0:
        raise Fail("%s negative" % what)
    return v


def is_hex32(s):
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def parse_tx(hexstr):
    """Parse a raw tx; return dict with recomputed txid, inputs, outputs."""
    if not isinstance(hexstr, str) or len(hexstr) % 2:
        raise Fail("raw tx is not hex")
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        raise Fail("raw tx is not hex")
    p = [0]

    def rd(n):
        if p[0] + n > len(b):
            raise Fail("raw tx truncated")
        r = b[p[0]:p[0] + n]
        p[0] += n
        return r

    def vi():
        x = rd(1)[0]
        if x < 0xfd:
            return x
        return int.from_bytes(rd({0xfd: 2, 0xfe: 4, 0xff: 8}[x]), "little")

    ver = rd(4)
    segwit = False
    if b[p[0]:p[0] + 2] == b"\x00\x01":
        segwit = True
        rd(2)
    s0 = p[0]
    vin = []
    for _ in range(vi()):
        prev = rd(32)[::-1].hex()
        idx = int.from_bytes(rd(4), "little")
        rd(vi())
        rd(4)
        vin.append({"txid": prev, "vout": idx})
    vout = []
    for _ in range(vi()):
        val = int.from_bytes(rd(8), "little")
        spk = rd(vi()).hex()
        vout.append({"value": val, "scriptpubkey": spk})
    s1 = p[0]
    if segwit:
        for _ in vin:
            for _ in range(vi()):
                rd(vi())
    lock = rd(4)
    if p[0] != len(b):
        raise Fail("trailing bytes in raw tx")
    txid = dsha(ver + b[s0:s1] + lock)[::-1].hex()
    return {"txid": txid, "vin": vin, "vout": vout}


def canon(obj):
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n"


def file_sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


# ---------------------------------------------------------------- collection
class Session:
    def __init__(self, out, max_requests, timeout):
        self.out, self.max, self.timeout, self.n = out, max_requests, timeout, 0

    def get(self, rnd, prov, key, path, reqs):
        url = PROVIDERS[prov] + path
        rec = {"key": key, "url": url}
        if self.n >= self.max:
            rec.update(error="request budget exhausted (%d)" % self.max)
            reqs.append(rec)
            raise Fail(rec["error"])
        self.n += 1
        t0, m0 = time.time(), time.monotonic()
        body, status, err = b"", None, None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "prize-state/1 (read-only evidence collector)"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                status = r.status
                body = r.read(20_000_000)
        except urllib.error.HTTPError as e:
            status, err = e.code, "HTTP %d" % e.code
            body = e.read(100_000)
        except Exception as e:  # network error: record, never fall back
            err = "%s: %s" % (type(e).__name__, e)
        rel = "raw/r%d/%s/%03d.body" % (rnd, prov, len(reqs))
        os.makedirs(os.path.dirname(os.path.join(self.out, rel)), exist_ok=True)
        with open(os.path.join(self.out, rel), "wb") as f:
            f.write(body)
        rec.update(file=rel, http_status=status, bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                   t_start=utc(t0), t_end=utc(time.time()), elapsed_ms=int((time.monotonic() - m0) * 1000))
        if err:
            rec["error"] = err
        reqs.append(rec)
        if err or status != 200:
            raise Fail("%s %s" % (url, err or status))
        return body


def collect_provider(sess, rnd, prov):
    reqs = []
    out = {"requests": reqs}
    a = "/address/" + ADDRESS

    def j(key, path):
        try:
            return json.loads(sess.get(rnd, prov, key, path, reqs))
        except ValueError:
            raise Fail("non-JSON body for " + key)

    def txt(key, path):
        return sess.get(rnd, prov, key, path, reqs).decode("ascii", "strict").strip()

    try:
        txt("tip_before_height", "/blocks/tip/height")
        txt("tip_before_hash", "/blocks/tip/hash")
        j("address", a)
        txids, last = [], None
        for page in range(MAX_PAGES):
            lst = j("chain_page_%02d" % page, a + "/txs/chain" + ("/" + last if last else ""))
            if not isinstance(lst, list):
                raise Fail("chain page not a list")
            txids += [t.get("txid") for t in lst]
            if len(lst) < CHAIN_PAGE:
                break
            last = lst[-1]["txid"]
        else:
            raise Fail("history exceeds page bound")
        mp = j("mempool_txs", a + "/txs/mempool")
        txids += [t.get("txid") for t in mp]
        j("utxo", a + "/utxo")
        need = []
        for t in txids:
            if not is_hex32(t):
                raise Fail("bad txid in history")
            if t not in need:
                need.append(t)
        for t in need:
            txt("hex:" + t, "/tx/%s/hex" % t)
            j("status:" + t, "/tx/%s/status" % t)
            outs = j("outspends:" + t, "/tx/%s/outspends" % t)
            raw = parse_tx(open(os.path.join(sess.out, reqs[-3]["file"])).read().strip())
            for i, o in enumerate(raw["vout"]):
                if o["scriptpubkey"] == SCRIPT and i < len(outs) and outs[i].get("spent"):
                    sp = outs[i].get("txid")
                    if is_hex32(sp) and sp not in need and ("hex:" + sp) not in [r["key"] for r in reqs]:
                        txt("hex:" + sp, "/tx/%s/hex" % sp)
                        j("status:" + sp, "/tx/%s/status" % sp)
        th = txt("tip_after_hash", "/blocks/tip/hash")
        txt("tip_after_height", "/blocks/tip/height")
        if is_hex32(th):
            j("tipstatus:" + th, "/block/%s/status" % th)
    except Fail as e:
        out["error"] = str(e)
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out


def collect(outdir, max_requests, timeout):
    if os.path.exists(outdir) and os.listdir(outdir):
        raise SystemExit("refusing to write into non-empty " + outdir)
    os.makedirs(outdir, exist_ok=True)
    sess = Session(outdir, max_requests, timeout)
    src = os.path.abspath(__file__)
    manifest = {"schema": SCHEMA, "address": ADDRESS, "max_requests": max_requests,
                "collector_sha256": file_sha(src), "rounds": []}
    for rnd in (1, 2):
        r = {"round": rnd, "providers": {}}
        for prov in PROVIDERS:
            r["providers"][prov] = collect_provider(sess, rnd, prov)
        manifest["rounds"].append(r)
        with open(os.path.join(outdir, "manifest.json"), "w") as f:
            f.write(canon(manifest))
        s = derive(outdir)
        if rnd == 1 and s["rounds"][-1]["needs_repeat"]:
            continue  # tip moved or no common tip: repeat once, never wait for a block
        break
    finish(outdir)
    return derive(outdir)


def finish(outdir):
    s = derive(outdir)
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        f.write(canon(s))
    files = []
    for root, _, fs in os.walk(outdir):
        for n in fs:
            rel = os.path.relpath(os.path.join(root, n), outdir)
            if rel != "SHA256SUMS":
                files.append(rel)
    with open(os.path.join(outdir, "SHA256SUMS"), "w") as f:
        for rel in sorted(files):
            f.write("%s  %s\n" % (file_sha(os.path.join(outdir, rel)), rel))


# ---------------------------------------------------------------- derivation
def derive_provider(bundle, pdata):
    """Pure function of recorded bodies -> provider view. Raises Fail on bad data."""
    by = {}
    for r in pdata["requests"]:
        if "file" in r:
            body = open(os.path.join(bundle, r["file"]), "rb").read()
            if hashlib.sha256(body).hexdigest() != r["sha256"] or len(body) != r["bytes"]:
                raise Fail("body hash mismatch " + r["file"])
            if "error" not in r and r.get("http_status") == 200:
                by[r["key"]] = body
    if pdata.get("error"):
        return {"status": "UNAVAILABLE", "error": pdata["error"]}

    def J(k):
        try:
            return json.loads(by[k])
        except KeyError:
            raise Fail("missing response " + k)
        except ValueError:
            raise Fail("non-JSON " + k)

    def T(k):
        if k not in by:
            raise Fail("missing response " + k)
        return by[k].decode("ascii").strip()

    issues = []
    hb, ha = T("tip_before_height"), T("tip_after_height")
    if not (hb.isdigit() and ha.isdigit()):
        raise Fail("tip height not integer")
    tb = {"height": int(hb), "hash": T("tip_before_hash")}
    ta = {"height": int(ha), "hash": T("tip_after_hash")}
    for t in (tb, ta):
        if not is_hex32(t["hash"]):
            raise Fail("bad tip hash")
    tst = J("tipstatus:" + ta["hash"])
    tip_active = tst.get("in_best_chain") is True and tst.get("height") == ta["height"]
    if not tip_active:
        issues.append("tip_after not reported in_best_chain at its height")
    stable = tb == ta
    addr = J("address")
    if addr.get("address") != ADDRESS:
        raise Fail("address mismatch in index response")
    cs, ms = addr.get("chain_stats", {}), addr.get("mempool_stats", {})
    for k in ("funded_txo_count", "funded_txo_sum", "spent_txo_count", "spent_txo_sum", "tx_count"):
        need_int(cs.get(k), "chain_stats." + k)
        need_int(ms.get(k), "mempool_stats." + k)
    pages = sorted(k for k in by if k.startswith("chain_page_"))
    index_txs = {}
    chain_ids = []
    for k in pages:
        for t in J(k):
            chain_ids.append(t["txid"])
            index_txs[t["txid"]] = t
    mem_ids = []
    for t in J("mempool_txs"):
        mem_ids.append(t["txid"])
        index_txs[t["txid"]] = t
    if len(set(chain_ids)) != len(chain_ids):
        raise Fail("duplicate txid across history pages")
    if len(chain_ids) != cs["tx_count"]:
        issues.append("confirmed history count %d != chain_stats.tx_count %d" % (len(chain_ids), cs["tx_count"]))
    raw = {}
    for k in by:
        if k.startswith("hex:"):
            want = k[4:]
            tx = parse_tx(T(k))
            if tx["txid"] != want:
                raise Fail("recomputed txid %s != requested %s" % (tx["txid"], want))
            raw[want] = tx
    # exact indexed values/scripts vs raw
    for tid, it in index_txs.items():
        if tid not in raw:
            raise Fail("no raw hex for history tx " + tid)
        iv = it.get("vout", [])
        if len(iv) != len(raw[tid]["vout"]):
            raise Fail("index vout count differs from raw for " + tid)
        for i, (a, b) in enumerate(zip(iv, raw[tid]["vout"])):
            if need_int(a.get("value"), "index value") != b["value"] or a.get("scriptpubkey") != b["scriptpubkey"]:
                raise Fail("index value/script differs from raw %s:%d" % (tid, i))
        ivin = [(v.get("txid"), v.get("vout")) for v in it.get("vin", [])]
        if ivin != [(v["txid"], v["vout"]) for v in raw[tid]["vin"]]:
            raise Fail("index vin differs from raw for " + tid)

    def status(tid):
        st = J("status:" + tid)
        if st.get("confirmed") is True:
            h = need_int(st.get("block_height"), "block_height")
            if not is_hex32(st.get("block_hash")):
                raise Fail("bad block_hash")
            return {"confirmed": True, "height": h, "block_hash": st["block_hash"]}
        if st.get("confirmed") is False:
            return {"confirmed": False}
        raise Fail("bad status for " + tid)

    outputs = []
    for tid in sorted(set(chain_ids) | set(mem_ids)):
        st = status(tid)
        if st["confirmed"] != (tid in chain_ids):
            issues.append("tx %s status disagrees with history list" % tid)
        if st["confirmed"] and st["height"] > ta["height"]:
            issues.append("tx %s confirmed above observed tip" % tid)
        outsp = J("outspends:" + tid)
        if not isinstance(outsp, list) or len(outsp) != len(raw[tid]["vout"]):
            raise Fail("outspends length mismatch for " + tid)
        for i, o in enumerate(raw[tid]["vout"]):
            if o["scriptpubkey"] != SCRIPT:
                continue
            e = {"outpoint": "%s:%d" % (tid, i), "txid": tid, "vout": i, "value_sats": o["value"],
                 "funding": st, "spend": None}
            os_ = outsp[i]
            if os_.get("spent") is True:
                sp = os_.get("txid")
                if not is_hex32(sp) or sp not in raw:
                    raise Fail("spending tx raw missing for " + e["outpoint"])
                vi = os_.get("vin")
                rin = raw[sp]["vin"]
                if not is_int(vi) or vi >= len(rin) or rin[vi] != {"txid": tid, "vout": i}:
                    raise Fail("spending tx does not reference " + e["outpoint"])
                e["spend"] = {"txid": sp, "vin": vi, "status": status(sp)}
            elif os_.get("spent") is not False:
                raise Fail("bad outspend for " + e["outpoint"])
            outputs.append(e)
    ops = [e["outpoint"] for e in outputs]
    if len(ops) != len(set(ops)):
        raise Fail("duplicate outpoints")
    conf = [e for e in outputs if e["funding"]["confirmed"]]
    spent_conf = [e for e in conf if e["spend"] and e["spend"]["status"]["confirmed"]]
    if (len(conf), sum(e["value_sats"] for e in conf)) != (cs["funded_txo_count"], cs["funded_txo_sum"]):
        issues.append("confirmed funded outputs do not match chain_stats")
    if (len(spent_conf), sum(e["value_sats"] for e in spent_conf)) != (cs["spent_txo_count"], cs["spent_txo_sum"]):
        issues.append("confirmed spent outputs do not match chain_stats")
    unspent_conf = [e for e in conf if not (e["spend"] and e["spend"]["status"]["confirmed"])]
    pending_spends = [{"outpoint": e["outpoint"], "value_sats": e["value_sats"], "spending_txid": e["spend"]["txid"],
                       "vin": e["spend"]["vin"]} for e in unspent_conf if e["spend"]]
    pending_funding = [{"outpoint": e["outpoint"], "value_sats": e["value_sats"]} for e in outputs
                       if not e["funding"]["confirmed"]]
    # provider's own /utxo vs derived (esplora: excludes mempool-spent, includes mempool-funded)
    pu = J("utxo")
    prov_set = set()
    for u in pu:
        prov_set.add(("%s:%d" % (u["txid"], need_int(u["vout"], "utxo.vout")), need_int(u["value"], "utxo.value")))
    exp_set = {(e["outpoint"], e["value_sats"]) for e in outputs if not e["spend"]}
    if prov_set != exp_set:
        issues.append("provider /utxo differs from set derived from raw txs + outspends")
    utxos = sorted(({"outpoint": e["outpoint"], "txid": e["txid"], "vout": e["vout"], "value_sats": e["value_sats"],
                     "height": e["funding"]["height"], "block_hash": e["funding"]["block_hash"],
                     "pending_spend": bool(e["spend"]), "script_hex": SCRIPT} for e in unspent_conf),
                   key=lambda u: (u["txid"], u["vout"]))
    times = [r["t_start"] for r in pdata["requests"] if "t_start" in r] + \
            [r["t_end"] for r in pdata["requests"] if "t_end" in r]
    return {
        "status": "OK" if not issues else "INCONSISTENT",
        "issues": issues,
        "tip_before": tb, "tip_after": ta, "tip_stable": stable, "tip_after_in_best_chain": tip_active,
        "observed_from": min(times), "observed_until": max(times),
        "requests": len(pdata["requests"]),
        "confirmed_utxos": utxos,
        "confirmed_unspent_sats": sum(u["value_sats"] for u in utxos),
        "spendable_sats_excluding_pending_spends": sum(u["value_sats"] for u in utxos if not u["pending_spend"]),
        "pending_spends": sorted(pending_spends, key=lambda x: x["outpoint"]),
        "pending_funding": sorted(pending_funding, key=lambda x: x["outpoint"]),
        "mempool_tx_count": len(mem_ids),
        "spent_outputs_confirmed": sorted(({"outpoint": e["outpoint"], "value_sats": e["value_sats"],
                                            "spending_txid": e["spend"]["txid"], "height": e["spend"]["status"]["height"]}
                                           for e in spent_conf), key=lambda x: x["outpoint"]),
    }


def derive(bundle):
    man = json.load(open(os.path.join(bundle, "manifest.json")))
    if man.get("schema") != SCHEMA or man.get("address") != ADDRESS:
        raise Fail("manifest schema/address mismatch")
    rounds = []
    for r in man["rounds"]:
        views = {}
        for prov in PROVIDERS:
            pd = r["providers"].get(prov)
            if pd is None:
                views[prov] = {"status": "UNAVAILABLE", "error": "not collected"}
                continue
            try:
                views[prov] = derive_provider(bundle, pd)
            except Fail as e:
                if str(e).startswith("body hash mismatch"):
                    raise
                views[prov] = {"status": "INVALID", "error": str(e)}
        ok = [v for v in views.values() if v["status"] in ("OK", "INCONSISTENT")]
        rec = {"round": r["round"], "providers": views}
        if len(ok) < len(PROVIDERS):
            rec["agreement"] = "UNAVAILABLE"
            rec["anchor"] = None
        else:
            tips = {json.dumps(v["tip_after"], sort_keys=True) for v in ok}
            common = len(tips) == 1 and all(v["tip_stable"] and v["tip_after_in_best_chain"] for v in ok)
            rec["anchor"] = ok[0]["tip_after"] if common else None
            keyf = lambda v: (v["confirmed_utxos"], v["pending_spends"], v["pending_funding"])
            same = all(keyf(v) == keyf(ok[0]) for v in ok)
            if not common:
                rec["agreement"] = "NO_COMMON_TIP"
            elif not same:
                rec["agreement"] = "DISAGREE"
            elif any(v["status"] != "OK" for v in ok):
                rec["agreement"] = "AGREE_WITH_ISSUES"
            else:
                rec["agreement"] = "AGREE"
        rec["needs_repeat"] = rec["agreement"] in ("NO_COMMON_TIP",) or \
            any(v.get("tip_stable") is False for v in views.values())
        rounds.append(rec)
    final = rounds[-1]
    res = {"schema": SCHEMA, "address": ADDRESS, "script_hex": SCRIPT, "collector_sha256": man["collector_sha256"],
           "prior_observation": PRIOR_OBSERVATION, "limitations": LIMITATIONS, "rounds": rounds,
           "result": {"agreement": final["agreement"], "anchor": final["anchor"]}}
    if final["agreement"] in ("AGREE", "AGREE_WITH_ISSUES"):
        v = next(iter(final["providers"].values()))
        times_from = max(x["observed_from"] for x in final["providers"].values())
        times_until = max(x["observed_until"] for x in final["providers"].values())
        res["result"].update({
            "confirmed_unspent_sats": v["confirmed_unspent_sats"],
            "spendable_sats_excluding_pending_spends": v["spendable_sats_excluding_pending_spends"],
            "utxo_count": len(v["confirmed_utxos"]),
            "outpoints": [u["outpoint"] for u in v["confirmed_utxos"]],
            "pending_spends": v["pending_spends"],
            "pending_funding": v["pending_funding"],
            "observed_from": min(x["observed_from"] for x in final["providers"].values()),
            "observed_until": times_until, "latest_provider_start": times_from,
            "differs_from_prior_observation": v["confirmed_unspent_sats"] != PRIOR_OBSERVATION["sats"],
        })
    return res


def claim_input(bundle):
    """Machine-readable interface for a later (private) claim tool. Refuses unless verified + AGREE."""
    verify(bundle)
    s = json.load(open(os.path.join(bundle, "summary.json")))
    r = s["result"]
    if r["agreement"] != "AGREE":
        raise Fail("no agreed state: " + r["agreement"])
    if r["pending_spends"]:
        raise Fail("pending spends present; do not claim")
    final = s["rounds"][-1]
    utxos = next(iter(final["providers"].values()))["confirmed_utxos"]
    return {"schema": SCHEMA + "/claim-input", "address": ADDRESS, "script_hex": SCRIPT, "anchor": r["anchor"],
            "observed_until": r["observed_until"],
            "bundle_sha256sums_sha256": file_sha(os.path.join(bundle, "SHA256SUMS")),
            "utxos": [{k: u[k] for k in ("txid", "vout", "value_sats", "script_hex", "height")} for u in utxos],
            "total_sats": r["spendable_sats_excluding_pending_spends"],
            "warning": "Evidence is stale once any block/broadcast occurs after observed_until; recollect immediately before signing."}


def verify(bundle):
    sums = open(os.path.join(bundle, "SHA256SUMS")).read().splitlines()
    listed = set()
    for line in sums:
        h, rel = line.split("  ", 1)
        if os.path.isabs(rel) or ".." in rel.split("/"):
            raise Fail("unsafe path in SHA256SUMS")
        if file_sha(os.path.join(bundle, rel)) != h:
            raise Fail("SHA256SUMS mismatch: " + rel)
        listed.add(rel)
    for root, _, fs in os.walk(bundle):
        for n in fs:
            rel = os.path.relpath(os.path.join(root, n), bundle)
            if rel != "SHA256SUMS" and rel not in listed:
                raise Fail("unlisted file: " + rel)
    for need in ("manifest.json", "summary.json"):
        if need not in listed:
            raise Fail("missing " + need)
    if canon(derive(bundle)) != open(os.path.join(bundle, "summary.json")).read():
        raise Fail("summary.json does not equal offline re-derivation")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("collect")
    c.add_argument("--out", required=True)
    c.add_argument("--max-requests", type=int, default=200)
    c.add_argument("--timeout", type=float, default=20.0)
    for n in ("derive", "verify", "claim-input"):
        sp.add_parser(n).add_argument("bundle")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "collect":
            t0 = time.monotonic()
            s = collect(a.out, a.max_requests, a.timeout)
            verify(a.out)
            print(json.dumps({"result": s["result"], "elapsed_s": round(time.monotonic() - t0, 3),
                              "sha256sums_sha256": file_sha(os.path.join(a.out, "SHA256SUMS"))}, indent=1))
        elif a.cmd == "derive":
            sys.stdout.write(canon(derive(a.bundle)))
        elif a.cmd == "verify":
            verify(a.bundle)
            print("VERIFIED %s sha256(SHA256SUMS)=%s" % (a.bundle, file_sha(os.path.join(a.bundle, "SHA256SUMS"))))
        elif a.cmd == "claim-input":
            sys.stdout.write(canon(claim_input(a.bundle)))
    except Fail as e:
        print("FAIL: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
