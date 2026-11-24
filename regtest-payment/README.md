# regtest-payment — Bitcoin Core regtest payment fixture (SYNTHETIC)

Disposable fixture: fresh regtest datadir in a temp dir, peer networking off
(`-listen=0 -connect=0 -networkactive=0 -dnsseed=0 -fixedseeds=0`), RPC on 127.0.0.1 only.
Creates wallets `miner`, `src`, `dest` for this run only, funds a legacy P2PKH output
(0.5 BTC) in `src`, spends it to one Taproot (bech32m) address from `dest` less a fixed
1000-sat fee, signs with `signrawtransactionwithwallet` inside Core, mines 1 block and checks
the exact input, P2PKH prevout type, output script hex, paid sats and fee (also against
Core's `getrawtransaction ... 2` fee). Every RPC first asserts `chain == regtest`.
The datadir (including wallets) is deleted at exit; the receipt holds only public data.

Prerequisites: Python 3 (stdlib only), Bitcoin Core `bitcoind` + `bitcoin-cli` (tested 28.1,
from https://bitcoincore.org/bin/bitcoin-core-28.1/, SHA256SUMS checked).

    python3 -m unittest discover -s regtest-payment/tests -v   # 5 tests, no Core needed
    python3 regtest-payment/regtest_payment.py --bindir /path/to/bitcoin-28.1/bin \
        --receipt regtest-payment/receipt.json

Expected: exit 0 and a JSON receipt with `"network": "regtest"`, `"height": 103`,
`"depth": 1`, `"input_sats": 50000000`, `"paid_sats": 49999000`, `"fee_sats": 1000`
(txids differ per run). `receipt.json` is a sample from an actual run.
On error it prints `ERROR: ...` to stderr and exits 1.
