# prize-state — public, read-only prize evidence for 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo

Python 3 standard library only (tested 3.12.3). The address is hard-coded. No keys, no signing, no broadcasting.
Only HTTP GETs to `https://blockstream.info/api` and `https://mempool.space/api` (Esplora), with a request cap
(`--max-requests`, default 200; the live run used 72) and a per-request timeout.

## Commands
    # live, bounded collection (network) into a NEW empty directory; verifies the result before it exits
    python3 -I prize-state/prize_state.py collect --out prize-state/evidence/live-$(date -u +%Y%m%dT%H%M%SZ)
    # offline
    python3 -I prize-state/prize_state.py verify      prize-state/evidence/live-20261124   # exit 0 = verified
    python3 -I prize-state/prize_state.py derive      prize-state/evidence/live-20261124   # re-derived summary
    python3 -I prize-state/prize_state.py claim-input prize-state/evidence/live-20261124   # claim-tool interface
    python3 -I -m unittest discover -s prize-state -p 'test_*.py' -v                       # 17 offline tests

## What collect does (per provider, per round)
Tip height/hash before → `/address` stats → confirmed history (`/txs/chain` pages, max 20) → `/txs/mempool` →
`/utxo` → for every history tx: `/tx/:id/hex`, `/status`, `/outspends`; for every outspend of an address output it
also fetches the spending tx's hex and status → tip hash/height after → `/block/:tip/status` (in_best_chain).
If either provider's tip moved, or the providers ended on different tips, the whole collection is **repeated once**
straight away. It never waits for a block.
Each body is stored byte-for-byte under `raw/`. `manifest.json` records the URL, HTTP status, size, sha256, UTC
start and end time and elapsed ms of every request, plus any error. A failed provider is recorded as UNAVAILABLE.
The tool never silently falls back to the other provider.

## Derivation (pure, offline; `summary.json` must equal it byte-for-byte)
- Every txid is recomputed from raw hex (double SHA-256 of the non-witness serialization). The tool rejects
  truncated or trailing bytes.
- Each index's JSON vout values, scripts and vin outpoints must exactly match the raw tx. Amounts must be integer sats.
  Floats and bools are rejected.
- Address outputs are found from the raw script `76a914ffbb35a7bb9bbe16c1aa2534f7ff11d59c8e3d1a88ac`, which comes from
  the base58check-decoded address.
- Each outspend must point to a fetched tx whose input really spends that outpoint. Spends are split into confirmed
  spends and **pending spends** (spends still in the mempool).
- Results are cross-checked against `chain_stats` (count/sum funded and spent), the history count, and the provider's own `/utxo` endpoint.
- Agreement is one of `AGREE`, `AGREE_WITH_ISSUES`, `DISAGREE`, `NO_COMMON_TIP` or `UNAVAILABLE`. An anchor exists only
  when both providers report the same stable tip that is in the best chain.
- The historical figure 1,400,002,880 sats @ 977345 is kept as `prior_observation` only. It is never used as the current value.

## claim-input (interface for a later private claim tool)
`claim-input` runs only after `verify`, and only when agreement is `AGREE` with no pending spends. It outputs
`{anchor, observed_until, utxos[{txid,vout,value_sats,script_hex,height}], total_sats, bundle_sha256sums_sha256}`.
The UTXOs are sorted and unique. Re-collect immediately before signing.

## Limitations
These are recorded in every summary. Two third-party indexes are not a validating node. Sequential GETs are not atomic.
A common tip does not make the mempools atomic or global. Not seeing a spend in two mempools does not prove that no
spend exists. The evidence goes stale as soon as a new block or broadcast arrives.
