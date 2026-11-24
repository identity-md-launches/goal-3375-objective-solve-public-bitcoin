# Public Bitcoin receipt auditor

The offline auditor checks serialized Bitcoin transactions and accounts for all inputs
against a supplied snapshot. It uses Python 3 and the standard library. Its default
source is `1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo` and its sole recipient is
`bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx`. The auditor
validates the address checksums and derives the required scripts.

## Offline commands

Run from the repository root.

```sh
python3 -B -m unittest discover -s receipt-check/tests -v
python3 -B receipt-check/audit.py --mode synthetic receipt-check/tests/synthetic_pass.json
python3 -B receipt-check/audit.py --mode regtest --max-fee-sats 1000 receipt-check/tests/regtest_synthetic_pass.json
python3 -B receipt-check/audit.py --mode regtest regtest-payment/receipt.json
python3 -B receipt-check/audit.py --mode regtest regtest-payment/claim_receipt.json
python3 -B receipt-check/audit.py /path/to/public-mainnet-v1-receipt.json
```

Exit 0 means byte checks passed. Exit 1 means a rejected receipt or insufficient
evidence. Exit 2 means invalid CLI arguments, unreadable data, or invalid JSON.
Both synthetic fixtures account for 300,000 sats in, 299,000 sats paid,
and 1,000 sats in fees. The regtest fixture command reports `PASS` with
`max_fee_sats: 1000` and `fee_sats: 1000`. Changing the cap to 999 returns
exit 1 and reports the same measured fee with `excessive fee`.
The checked-in `regtest-payment/receipt.json` returns
`INSUFFICIENT` because the available txid, block metadata, and amounts omit raw
spend and funding bytes and a valued snapshot. To audit a future version, export
those bytes and the pre-spend outpoints from the same isolated regtest chain,
and supply the source and recipient addresses in a v1 receipt.

`regtest-payment/claim_receipt.json` is the newer v1 receipt generated through
the landed private-claim CLI. It passes explicit `--mode regtest` and fails the
default mainnet mode. Its paired `claim_evidence.json` carries separate synthetic
admission and chain observations; `regtest-payment/check_claim.py` generates a
fresh disposable-node receipt and checks the pair. The byte auditor's PASS still
leaves `unspent_status` and `confirmation` at `NOT ESTABLISHED`.

## Receipt v1

[The JSON schema](receipt-v1.schema.json) describes the public document shape.
The auditor additionally enforces canonical encodings, exact JSON integer types,
network mode, checksums, and relationships between fields.

- Set `schema` to `receipt-check/v1`. Default mode requires `network: "mainnet"`
  and `synthetic: false`, with the two fixed addresses. Use `--mode synthetic`
  with `network: "mainnet"` and `synthetic: true` to exercise those same scripts
  with generated data. The label is declarative.
- Use `--mode regtest` with `network: "regtest"` and `synthetic: true`. Supply a
  Base58Check P2PKH source using version 111 and a Bech32m Taproot recipient with
  HRP `bcrt`. The source version byte is shared with testnet. Raw Bitcoin
  transactions carry no chain identifier.
- Set `recipient` and `snapshot.address` to the addresses. The
  `snapshot.outpoints` list contains `txid`, zero-based `vout`, and positive
  integer `value_sats` for every selected output.
- Set `tx` to the spend and `prevouts` to one transaction per distinct funding
  txid referenced by the snapshot. Each entry contains `txid` and complete
  serialized `raw_hex`, including witness bytes if present. Use lowercase
  hex with no prefix or whitespace and display-order txids.
- The old decoded-only shape and `authenticated` assertions are rejected.
  Use the v1 raw records and select fixture modes explicitly.

Inputs must match the snapshot exactly, regardless of order. The auditor
recomputes each txid via double SHA-256 of the non-witness serialization and
checks each indexed funding output's script and amount. The spend must have
exactly one positive output paying the recipient script. Input total, payment,
and fee are integer satoshis. The auditor computes the fee from the indexed
funding outputs and the spend output. It accepts fees from zero through the
caller's cap inclusive. The cap defaults to 100,000 sats. The optional
`--max-fee-sats` takes ASCII decimal digits, including zero. Python callers
can pass `max_fee_sats` as a nonnegative integer keyword argument to `audit()`.
Receipt v1 rejects extra fields, including any attempted fee-cap field.

The report includes the applied `max_fee_sats` and, once the payment amounts
have been checked, the measured `fee_sats`, even when the fee violates policy.
A byte-policy `PASS` establishes that the supplied bytes and snapshot satisfy
the selected audit mode and fee cap. Relay policy, mining policy, unspent
status, and confirmation require separate evidence.

## Public evidence needed for a confirmed payment

- **Byte integrity** requires the v1 snapshot, full spend bytes and full bytes
  for every funding transaction. A passing result demonstrates consistency with
  the supplied snapshot. Txids commit to non-witness bytes. The auditor parses
  witness serialization without validating signatures or consensus spendability.
- **Externally observed unspent status** requires a complete inventory of
  confirmed outputs for the fixed source script at a named pre-spend mainnet
  height and block hash, with each outpoint, amount, and script, independently
  reproduced from a fully validated node's UTXO state at that tip. Check funding
  maturity where applicable. Establish whether any competing transaction was
  observed in the mempool separately, with node and observation time. After
  confirmation, these inputs should be spent. A current lookup alone cannot
  reconstruct the earlier inventory.
- **Active-chain confirmation** requires the spend txid, containing block
  hash and height, and a specified confirmation depth at an observed mainnet
  tip hash and height. Obtain the decoded block with the transaction or the
  block header and a txid Merkle inclusion proof. Match the spend to the audited
  transaction, independently verify that the containing block is on the active
  chain of a fully validating mainnet node, and calculate depth as tip height
  minus block height plus one. Recheck membership and depth after a reorg. For
  exact witness bytes, compare the block's full transaction or verify its
  witness commitment as well.

The offline output keeps `unspent_status` and `confirmation` at
`NOT ESTABLISHED`. JSON labels, booleans, heights, and depths are assertions.

## Reproduced baseline failures

At the base commit, invented txids and `authenticated: true` passed. Increasing
a claimed input by one satoshi silently increased the reported fee from 1,000
to 1,001 sats. A 1-sat payment from 300,000 sats of inputs passed with a
299,999-sat fee. Adding `network: "regtest"` and `synthetic: true` to the
receipt still passed the default audit, as did adding an unused funding record.
The v1 tests check each corresponding rejection path.
