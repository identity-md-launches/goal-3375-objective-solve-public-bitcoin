#!/usr/bin/env python3
"""Offline SYNTHETIC seven-input fixture. Never accepts production keys or RPC nodes."""
import argparse
import contextlib
from decimal import Decimal
import hashlib
import json
import lzma
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
PROGRAM = '46bfc36cb0a801aa7d19aff5ceffc6735d461e99bebd4c6c7fa3b2fbae2c0a6f'
MAINNET = 'bc1pg6luxm9s4qq65lge4l6ual7xwdw5v85eh675cmrl5we0ht3vpfhswxu0cx'
SCRIPT = '5120' + PROGRAM
FUND_SATS = 50_000_000
DEFAULT_FEE_SATS = 3000
MAX_FEE_SATS = 10000
MIN_RATE = Decimal('1')
MAX_RATE = Decimal('10')


def btc_to_sats(value):
    n = Decimal(str(value)) * 100000000
    if n != n.to_integral_value():
        raise ValueError('sub-satoshi amount')
    return int(n)


def sats_to_btc(n):
    return format(Decimal(n) / 100000000, '.8f')


def encode_destination(hrp):
    """BIP350 witness-v1 bech32m encoding for the fixed 32-byte program."""
    chars = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    acc = bits = 0
    data = [1]
    for b in bytes.fromhex(PROGRAM):
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data + [0] * 6
    chk = 1
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i, g in enumerate(gen):
            if (top >> i) & 1:
                chk ^= g
    chk ^= 0x2bc830a3
    return hrp + '1' + ''.join(chars[x] for x in data + [(chk >> (5 * (5-i))) & 31 for i in range(6)])


DESTINATION = encode_destination('bcrt')


def assert_regtest_chain(info):
    if info.get('chain') != 'regtest':
        raise RuntimeError('REFUSING: node is not regtest')


def fee_policy(fee, vsize=None):
    if type(fee) is not int or not 0 < fee <= MAX_FEE_SATS:
        raise ValueError('fee outside absolute bounds')
    if vsize is not None and not MIN_RATE <= Decimal(fee) / vsize <= MAX_RATE:
        raise ValueError('fee outside sat/vB bounds')


def verify_spend(tx, prevouts, fee):
    expected = {(p['txid'], p['vout']) for p in prevouts}
    actual = [(v['txid'], v['vout']) for v in tx['vin']]
    if len(expected) != 7 or len(actual) != 7 or set(actual) != expected:
        raise ValueError('expected seven distinct exact inputs')
    if any(p['script_type'] != 'pubkeyhash' for p in prevouts):
        raise ValueError('prevout is not P2PKH')
    if len(tx['vout']) != 1:
        raise ValueError('expected one output, no change')
    output = tx['vout'][0]
    if output['scriptPubKey']['hex'] != SCRIPT or output['scriptPubKey']['type'] != 'witness_v1_taproot':
        raise ValueError('destination mismatch')
    total = sum(p['sats'] for p in prevouts)
    if total - btc_to_sats(output['value']) != fee:
        raise ValueError('fee mismatch')
    fee_policy(fee, tx['vsize'])
    return total


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextlib.contextmanager
def runtime(bindir=None):
    manifest = json.loads((ROOT / 'runtime/manifest.json').read_text())
    with tempfile.TemporaryDirectory(prefix='core-runtime-') as tmp:
        target = Path(bindir) if bindir else Path(tmp)
        for name, entry in manifest['components'].items():
            if not bindir:
                src = ROOT / 'runtime' / (name + '.xz')
                if sha256(src) != entry['compressed_sha256']:
                    raise RuntimeError('compressed runtime hash mismatch: ' + name)
                (target / name).write_bytes(lzma.decompress(src.read_bytes()))
                (target / name).chmod(0o700)
            if sha256(target / name) != entry['sha256']:
                raise RuntimeError('runtime hash mismatch: ' + name)
        yield target


class Node:
    def __init__(self, bindir, datadir):
        self.datadir = Path(datadir)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        # Explicit empty fixture-owned config; default machine config is never read.
        conf = self.datadir / 'bitcoin.conf'
        conf.write_text('')
        self.env = {'HOME': str(self.datadir), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        common = ['-regtest', '-datadir=' + str(self.datadir), '-conf=' + str(conf),
                  '-rpcport=' + str(port), '-rpccookiefile=' + str(self.datadir / 'fixture.cookie')]
        self.base = [str(bindir / 'bitcoin-cli')] + common
        self.proc = subprocess.Popen([str(bindir / 'bitcoind')] + common + [
            '-listen=0', '-connect=0', '-dnsseed=0', '-fixedseeds=0', '-networkactive=0',
            '-upnp=0', '-natpmp=0', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
            '-fallbackfee=0.0001', '-txindex=1', '-daemon=0', '-printtoconsole=0',
            '-debuglogfile=0'], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def cli(self, *args, wallet=None, guard=True):
        if guard and args[0] != 'getblockchaininfo':
            assert_regtest_chain(self.cli('getblockchaininfo'))
        cmd = self.base + (['-rpcwallet=' + wallet] if wallet else []) + list(args)
        result = subprocess.run(cmd, env=self.env, capture_output=True, text=True, timeout=30)
        if result.returncode:
            # Do not echo RPC arguments, wallet responses, or secrets on errors.
            raise RuntimeError('RPC failed: ' + args[0])
        try:
            return json.loads(result.stdout, parse_float=Decimal)
        except ValueError:
            return result.stdout.strip()

    def start(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('Core exited during startup')
            try:
                info = self.cli('getblockchaininfo')
                assert_regtest_chain(info)
                if info['blocks'] != 0:
                    raise RuntimeError('fixture is not fresh')
                return
            except RuntimeError:
                time.sleep(.05)
        raise RuntimeError('Core startup timeout')

    def close(self):
        if self.proc.poll() is None:
            try:
                self.cli('stop', guard=False)
            except Exception:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def run(receipt_path, fee_sats=DEFAULT_FEE_SATS, bindir=None, signer=None, hold_at=None, ready=None, work_root=None):
    """Integration seam: signer(node, unsigned_hex, public_prevouts) -> signed hex.

    Only generated regtest sources are passed. No external signer ships here; callers
    must independently test their adapter. Receipt is written only after verification.
    """
    fee_policy(fee_sats)
    if encode_destination('bc') != MAINNET:
        raise RuntimeError('mainnet recipient/program checksum mismatch')
    started = time.monotonic()
    with runtime(bindir) as binaries, tempfile.TemporaryDirectory(prefix='synthetic-regtest-', dir=work_root) as datadir:
        node = Node(binaries, datadir)
        try:
            node.start()
            network = node.cli('getnetworkinfo')
            if network['networkactive'] or network['connections']:
                raise RuntimeError('networking enabled')
            for w in ('miner', 'src'):
                node.cli('createwallet', w)
            mine = node.cli('getnewaddress', '', 'bech32', wallet='miner')
            node.cli('generatetoaddress', '101', mine)
            addresses = [node.cli('getnewaddress', '', 'legacy', wallet='src') for _ in range(7)]
            funding_id = node.cli('sendmany', '', json.dumps({a: sats_to_btc(FUND_SATS) for a in addresses}), wallet='miner')
            funding_block = node.cli('generatetoaddress', '1', mine)[0]
            funding_raw = node.cli('getrawtransaction', funding_id, 'false', funding_block)
            funding = node.cli('decoderawtransaction', funding_raw)
            prevouts = []
            for v in funding['vout']:
                if v['scriptPubKey'].get('address') in addresses:
                    if node.cli('gettxout', funding_id, str(v['n'])) is None:
                        raise RuntimeError('funding output unavailable')
                    prevouts.append({'txid': funding_id, 'vout': v['n'], 'sats': btc_to_sats(v['value']),
                                     'script_hex': v['scriptPubKey']['hex'], 'script_type': v['scriptPubKey']['type']})
            if len(prevouts) != 7:
                raise RuntimeError('expected seven funded sources')
            total = sum(p['sats'] for p in prevouts)
            validation = node.cli('validateaddress', DESTINATION)
            if not validation['isvalid'] or validation['scriptPubKey'] != SCRIPT:
                raise RuntimeError('Core destination validation mismatch')
            unsigned = node.cli('createrawtransaction', json.dumps([{'txid': p['txid'], 'vout': p['vout']} for p in prevouts]),
                                json.dumps([{DESTINATION: sats_to_btc(total-fee_sats)}]))
            if signer:
                signed_hex = signer(node, unsigned, prevouts)
            else:
                signed = node.cli('signrawtransactionwithwallet', unsigned, wallet='src')
                if not signed['complete']:
                    raise RuntimeError('incomplete signature')
                signed_hex = signed['hex']
            tx = node.cli('decoderawtransaction', signed_hex)
            verify_spend(tx, prevouts, fee_sats)
            if hold_at == 'signed':
                if ready is None:
                    raise ValueError('hold requires ready path')
                Path(ready).write_text(json.dumps({'phase': 'signed', 'node_pid': node.proc.pid, 'datadir': datadir}))
                while True:
                    signal.pause()
            accept = node.cli('testmempoolaccept', json.dumps([signed_hex]))[0]
            if not accept.get('allowed') or btc_to_sats(accept['fees']['base']) != fee_sats or accept['vsize'] != tx['vsize']:
                raise RuntimeError('mempool admission/fee/vsize mismatch')
            txid = node.cli('sendrawtransaction', signed_hex)
            blockhash = node.cli('generatetoaddress', '1', mine)[0]
            node.cli('generatetoaddress', '1', mine)
            verbose = node.cli('getrawtransaction', txid, '2', blockhash)
            if btc_to_sats(verbose['fee']) != fee_sats or not verbose['in_active_chain']:
                raise RuntimeError('confirmed fee/chain mismatch')
            header = node.cli('getblockheader', blockhash)
            tip = node.cli('getblockchaininfo')
            if header['confirmations'] != 2 or node.cli('getblockhash', str(header['height'])) != blockhash:
                raise RuntimeError('active-chain depth mismatch')
            for vin, prev in zip(verbose['vin'], prevouts):
                rawprev = vin['prevout']
                if btc_to_sats(rawprev['value']) != prev['sats'] or rawprev['scriptPubKey']['hex'] != prev['script_hex']:
                    raise RuntimeError('Core raw prevout mismatch')
            receipt = {
                'synthetic': True, 'label': 'SYNTHETIC', 'network': 'regtest', 'objectiveStatus': 'INCOMPLETE',
                'core_version': network['subversion'], 'networkactive': False, 'connections': 0,
                'source_count': 7, 'destination': DESTINATION, 'destination_script_hex': SCRIPT,
                'input_sats': total, 'paid_sats': total-fee_sats, 'fee_sats': fee_sats,
                'vsize': tx['vsize'], 'fee_rate_sat_vB': str(Decimal(fee_sats)/tx['vsize']),
                'fee_policy': {'max_sats': MAX_FEE_SATS, 'min_sat_vB': str(MIN_RATE), 'max_sat_vB': str(MAX_RATE)},
                'prevouts': prevouts, 'funding_raw': funding_raw, 'funding_txid': funding_id,
                'funding_blockhash': funding_block, 'funding_block_raw': node.cli('getblock', funding_block, '0'),
                'sweep_raw': signed_hex, 'txid': txid, 'output_count': 1,
                'mempool': accept, 'blockhash': blockhash, 'block_header_raw': node.cli('getblockheader', blockhash, 'false'),
                'block_raw': node.cli('getblock', blockhash, '0'), 'height': header['height'], 'depth': header['confirmations'],
                'active_tip': tip['bestblockhash'], 'active_height': tip['blocks'],
                'active_tip_header_raw': node.cli('getblockheader', tip['bestblockhash'], 'false'),
                'elapsed_seconds': round(time.monotonic()-started, 6),
                'signer': 'external adapter' if signer else 'Core generated regtest wallet',
            }
        finally:
            node.close()
    # Datadir and runtime removed before publishing public allowlisted fields.
    receipt['disposable_secrets_removed'] = True
    path = Path(receipt_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as out:
        tmp = Path(out.name)
        json.dump(receipt, out, indent=2, default=str)
        out.write('\n')
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, help='optional exact hash-verified Core 28.1 binaries')
    parser.add_argument('--receipt', type=Path, default=ROOT / 'receipt.json')
    parser.add_argument('--fee-sats', type=int, default=DEFAULT_FEE_SATS)
    parser.add_argument('--hold-at', choices=['signed'], help=argparse.SUPPRESS)
    parser.add_argument('--ready', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--work-root', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = run(args.receipt, args.fee_sats, args.bindir, hold_at=args.hold_at, ready=args.ready, work_root=args.work_root)
        print(json.dumps({k: result[k] for k in ('label', 'txid', 'fee_sats', 'vsize', 'depth', 'elapsed_seconds')}))
        return 0
    except KeyboardInterrupt:
        print('SYNTHETIC fixture interrupted; disposable node cleaned', file=sys.stderr)
        return 130
    except Exception as exc:
        print('SYNTHETIC fixture failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
