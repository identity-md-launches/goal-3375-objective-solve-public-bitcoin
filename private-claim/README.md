# Bitcoin Puzzle #140 local claim

This component prepares, optionally broadcasts, and independently checks confirmation of a sweep to the fixed recipient. It uses Python 3.10+ on POSIX and an entrant-controlled Bitcoin Core node. RIPEMD-160 uses the platform's `hashlib` when present and falls back to a self-contained implementation in `bitcoin.py`, so no external dependency is required. The RPC interface targets Bitcoin Core 28.1, the version vendored by `regtest-payment/runtime`. Because Core 28.1 does not provide `getdescriptoractivity`, the snapshot reconstructs complete mempool activity for the fixed source script from `getrawmempool` plus `getrawtransaction`: every mempool input is treated as a candidate spend and every mempool output paying the source script as a pending receive. Live regtest integration is exercised end to end by `check_core.py` (see below).

## Private setup

Use your own fully synced, unpruned Bitcoin Core 28.1 node with a synced transaction index (`txindex=1`). Bind RPC to a numeric loopback address. Use a dedicated machine and trust both the process receiving loopback requests and the node's responses. Core receives the WIF in a signing RPC request. Disable request capture and verbose RPC tracing. Python and Core may retain secrets in process memory. The CLI disables its own core dumps.

Supply a candidate stream containing exactly 32 raw big-endian bytes followed by EOF. Supply a separate authentication stream containing ASCII `username:password` followed by EOF, with no newline. Use private files or pipes owned by the entrant. The CLI closes each private descriptor after consumption and on handled failures. The examples name private file paths, which you can replace with your own. Keep those files outside the checkout. A private pipe can avoid writing the candidate to disk.

## Prepare and sign

From the checkout root in a POSIX shell, set `CAP_SATS` to your chosen maximum **total** fee in satoshis and `FEE_TARGET` to your chosen target in blocks (2–1008). Adjust the loopback URL to match your node.

```sh
python3 -B private-claim/claim.py --rpc-url http://127.0.0.1:8332 \
  --rpc-auth-fd 3 --max-fee-sats "${CAP_SATS:?set total fee cap}" \
  claim --candidate-fd 4 --fee-target "${FEE_TARGET:?set fee target}" \
  3< /private/entrant/core-auth 4< /private/entrant/candidate.bin
```

A `prepared` receipt describes a signed transaction that passed local accounting and Core's mempool test. Keep its transaction ID private pending broadcast. Each invocation discovers all outputs matching the fixed source script in the node's active UTXO set and mempool. It excludes mempool-spent outputs and stops for immature matching coinbase outputs, inconsistent views, missing raw prevouts, empty funds, unavailable fee estimates or policy rejection. It checks the raw prevouts against the live unspent outputs twice and checks the chain and mempool state again after the mempool test. Core can still reject a submission if state changes between RPC calls.

The CLI uses the greater of Core's fee estimate, relay floor and mempool floor. It computes the fee in integer satoshis using the signed virtual size and rechecks the fee and output before testing acceptance. A later signing pass can reduce virtual size, in which case the fee can modestly exceed the node-derived minimum while staying under the entrant's cap. RPC failures show the failing method and omit response details.

## Broadcast and verify

After review, run the same command with `--broadcast`. This rebuilds and rechecks a fresh transaction, so use the txid in the broadcast receipt for verification.

```sh
python3 -B private-claim/claim.py --rpc-url http://127.0.0.1:8332 \
  --rpc-auth-fd 3 --max-fee-sats "${CAP_SATS:?set total fee cap}" \
  claim --candidate-fd 4 --fee-target "${FEE_TARGET:?set fee target}" --broadcast \
  3< /private/entrant/core-auth 4< /private/entrant/candidate.bin
```

The CLI emits `broadcast_attempt` before sending and `broadcast_pending` after Core acknowledges the expected txid. If the send returns an error, retain the txid from `broadcast_attempt` and check its status before attempting another send. Use the same fee cap, set `TXID` to the broadcast txid, and choose your minimum confirmation depth in `DEPTH`.

```sh
python3 -B private-claim/claim.py --rpc-url http://127.0.0.1:8332 \
  --rpc-auth-fd 3 --max-fee-sats "${CAP_SATS:?set total fee cap}" \
  verify --txid "${TXID:?set broadcast txid}" --confirmations "${DEPTH:?set depth}" \
  3< /private/entrant/core-auth
```

Only `confirmed` records payment. The verification command checks the raw transaction, its source prevouts, the sole destination, fee and active-chain block at the requested depth. Run it again if the transaction has too few confirmations or the chain moves during verification.

## Offline tests and regtest entrypoint

```sh
python3 -B -m unittest discover -s private-claim -p 'test_*.py' -v
```

The tests use an in-process RPC mock with synthetic data. They exercise the transaction checks, failure paths, receipt states, descriptor closure and RPC redaction. The mock models the mempool through `getrawmempool`/`getrawtransaction`, matching the Core 28.1 snapshot path.

## Real-backend acceptance check

`check_core.py` is the real-backend acceptance gate. It runs the offline suite, then starts a fresh, isolated, networkless regtest Core 28.1 node from the hash-verified runtime vendored in `regtest-payment/runtime`, generates disposable cookie auth, and drives the actual `regtest.py`/`claim.py` CLI over loopback HTTP RPC with private descriptors. It proves real Core signing, mempool admission, broadcast, mining and confirmation verification using only the public synthetic scalar, and the fail-closed rejection paths (no funds, fee cap, wrong candidate, missing fee estimate, wrong network). It confirms Core 28.1 lacks `getdescriptoractivity` and that the mempool-scan snapshot still works. It never spends the production key, address or interval and emits no secret. Set `IMD_CORE_EVIDENCE` to a path to capture the public regtest evidence (receipts, raw sweep, block header) for receipt integration.

```sh
python3 -I -B private-claim/check_core.py
```

For the next integration episode, start a fresh, isolated regtest node with a synced transaction index and an explicitly supplied RPC endpoint. The fixed synthetic source can be printed without RPC.

```sh
PYTHONPATH=private-claim python3 -B -c 'from claim import Claim; print(Claim(None, synthetic=True).source)'
```

Mine one coinbase to that source, then 100 blocks to another regtest address for maturity. Use the following Bash command with an explicit private regtest authentication file. The process substitution supplies the publicly known synthetic scalar. The regtest path accepts only that scalar and the regtest chain.

```bash
python3 -B private-claim/regtest.py --rpc-url http://127.0.0.1:18443 \
  --rpc-auth-fd 3 --max-fee-sats 2000 claim --candidate-fd 4 --fee-target 6 \
  --synthetic-fee-sat-per-kvb 2000 \
  3< /private/entrant/regtest-auth \
  4< <(python3 -B -c 'import sys; sys.stdout.buffer.write((1).to_bytes(32, "big"))')
```

The explicitly supplied synthetic rate is a fallback for an empty regtest fee estimator. Repeat with `--broadcast`, mine one block to another regtest address, then verify the broadcast txid.

```sh
python3 -B private-claim/regtest.py --rpc-url http://127.0.0.1:18443 \
  --rpc-auth-fd 3 --max-fee-sats 2000 verify --txid "${TXID:?set regtest txid}" --confirmations 1 \
  3< /private/entrant/regtest-auth
```

Public references include the [Puzzle #140 record](https://lotterypuzzle.org/puzzles/140/), [BIP 350](https://bips.dev/350/), and Bitcoin Core 28.1's [raw mempool](https://bitcoincore.org/en/doc/28.0.0/rpc/blockchain/getrawmempool/), [signing](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/signrawtransactionwithkey/), and [acceptance](https://bitcoincore.org/en/doc/28.0.0/rpc/rawtransactions/testmempoolaccept/) documentation.
