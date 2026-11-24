# receipt-check — offline payment auditor

Read-only, offline, public records only. Python 3 standard library only (tested on 3.12.3). No keys, no network.
All bundled data is **SYNTHETIC** (fake txids/values).

## Run
    python3 receipt-check/audit.py receipt-check/tests/synthetic_pass.json   # exit 0 = PASS, 1 = FAIL, 2 = bad input
    python3 -m unittest discover -s receipt-check/tests -v                   # 18 tests

## Input JSON
- `tx`: `{"txid", "vin":[{"txid","vout"}], "vout":[{"value_sats","script_hex"}]}`
- `prevouts`: `[{"txid","vout","value_sats","script_hex","authenticated":true}]` (authenticated records supplied by you)
- `snapshot`: `{"address":"1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo","outpoints":[{"txid","vout"}]}`

## Checks
Every snapshot outpoint is spent exactly once; no other or duplicate inputs; each prevout has an authenticated
record, a positive integer value, and the P2PKH script of the prize address; exactly one output, paying the
script of bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx (checksums verified), positive amount,
non-negative fee. Reports `input_sum_sats`, `paid_sats`, `fee_sats` as integers.
`confirmation` is always `NOT ESTABLISHED`: it needs active-chain evidence this tool cannot supply.
