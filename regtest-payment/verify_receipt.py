#!/usr/bin/env python3
"""Independent public-byte consistency verifier; Core tests enforce script validity.

This is not a general consensus implementation, nor proof of production payment.
"""
import hashlib
import json
from pathlib import Path
import sys
from decimal import Decimal
import regtest_payment as rp


def require(ok, message):
    if not ok:
        raise ValueError(message)


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        require(0 <= count <= len(self.data)-self.pos, 'truncated serialization')
        result = self.data[self.pos:self.pos+count]
        self.pos += count
        return result

    def integer(self, count):
        return int.from_bytes(self.take(count), 'little')

    def compact(self):
        n = self.integer(1)
        if n < 253:
            return n
        size = {253: 2, 254: 4, 255: 8}[n]
        value = self.integer(size)
        require(value >= {2: 253, 4: 65536, 8: 4294967296}[size], 'noncanonical CompactSize')
        return value

    def varbytes(self):
        return self.take(self.compact())


def transaction(reader):
    start = reader.pos
    version = reader.take(4)
    witness = reader.data[reader.pos:reader.pos+2] == b'\x00\x01'
    if witness:
        reader.take(2)
    body_start = reader.pos
    inputs = []
    for _ in range(reader.compact()):
        inputs.append({'txid': reader.take(32)[::-1].hex(), 'vout': reader.integer(4),
                       'script': reader.varbytes().hex(), 'sequence': reader.integer(4)})
    outputs = []
    for _ in range(reader.compact()):
        outputs.append({'sats': reader.integer(8), 'script': reader.varbytes().hex()})
    body = reader.data[body_start:reader.pos]
    if witness:
        for _ in inputs:
            for _ in range(reader.compact()):
                reader.varbytes()
    locktime = reader.take(4)
    stripped = version + body + locktime
    raw = reader.data[start:reader.pos]
    weight = len(stripped)*3 + len(raw)
    return {'txid': hash256(stripped)[::-1].hex(), 'inputs': inputs, 'outputs': outputs,
            'vsize': (weight+3)//4, 'raw': raw.hex(), 'witness': witness}


def decode_tx(raw):
    r = Reader(bytes.fromhex(raw))
    tx = transaction(r)
    require(r.pos == len(r.data), 'trailing transaction data')
    return tx


def header_info(raw):
    require(len(raw) == 80, 'header size')
    bits = int.from_bytes(raw[72:76], 'little')
    require(bits == 0x207fffff, 'not fixture regtest difficulty')
    target = (bits & 0x7fffff) << (8*((bits >> 24)-3))
    require(int.from_bytes(hash256(raw), 'little') <= target, 'invalid proof of work')
    return {'hash': hash256(raw)[::-1].hex(), 'previous': raw[4:36][::-1].hex()}


def block(raw):
    r = Reader(bytes.fromhex(raw))
    header = r.take(80)
    info = header_info(header)
    txs = [transaction(r) for _ in range(r.compact())]
    require(r.pos == len(r.data) and txs, 'block serialization')
    level = [bytes.fromhex(tx['txid'])[::-1] for tx in txs]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hash256(level[i]+level[i+1]) for i in range(0, len(level), 2)]
    require(level[0] == header[36:68], 'merkle root mismatch')
    return info, txs


def verify(receipt):
    r = receipt
    require(r['synthetic'] is True and r['label'] == 'SYNTHETIC' and r['network'] == 'regtest', 'synthetic label')
    require(r['objectiveStatus'] == 'INCOMPLETE', 'objective must remain incomplete')
    require(r['destination'] == rp.DESTINATION and rp.encode_destination('bc') == rp.MAINNET, 'recipient/checksum')
    require(r['destination_script_hex'] == rp.SCRIPT, 'receipt destination script')
    require(r['networkactive'] is False and r['connections'] == 0, 'network isolation report')
    require(r['disposable_secrets_removed'] is True, 'cleanup report')
    fund = decode_tx(r['funding_raw'])
    sweep = decode_tx(r['sweep_raw'])
    require(fund['txid'] == r['funding_txid'] and sweep['txid'] == r['txid'], 'transaction ID')
    require(len(sweep['inputs']) == 7 and not sweep['witness'], 'seven legacy inputs')
    require(len(sweep['outputs']) == r['output_count'] == 1, 'one output')
    require(sweep['outputs'][0]['script'] == rp.SCRIPT, 'raw output script')
    require(r['source_count'] == len(r['prevouts']) == 7, 'prevout count')
    expected = {(p['txid'], p['vout']) for p in r['prevouts']}
    actual = {(v['txid'], v['vout']) for v in sweep['inputs']}
    require(len(actual) == len(expected) == 7 and actual == expected, 'exact prevouts')
    total = 0
    for p in r['prevouts']:
        require(p['txid'] == fund['txid'], 'funding reference')
        output = fund['outputs'][p['vout']]
        script = bytes.fromhex(output['script'])
        require(len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac', 'P2PKH prevout')
        require(p['script_type'] == 'pubkeyhash' and p['script_hex'] == script.hex() and p['sats'] == output['sats'], 'prevout metadata')
        total += output['sats']
    fee = total - sweep['outputs'][0]['sats']
    rp.fee_policy(fee, sweep['vsize'])
    require(total == r['input_sats'] and sweep['outputs'][0]['sats'] == r['paid_sats'] and fee == r['fee_sats'], 'amount accounting')
    require(sweep['vsize'] == r['vsize'], 'raw vsize')
    require(Decimal(r['fee_rate_sat_vB']) == Decimal(fee)/sweep['vsize'], 'fee rate')
    admission = r['mempool']
    require(admission['allowed'] is True and admission['txid'] == sweep['txid'] and admission['vsize'] == sweep['vsize'] and rp.btc_to_sats(admission['fees']['base']) == fee, 'mempool report')
    funding_header, funding_txs = block(r['funding_block_raw'])
    sweep_header, sweep_txs = block(r['block_raw'])
    tip = header_info(bytes.fromhex(r['active_tip_header_raw']))
    require(any(tx['raw'] == r['funding_raw'] for tx in funding_txs), 'funding inclusion')
    require(any(tx['raw'] == r['sweep_raw'] for tx in sweep_txs), 'sweep inclusion')
    require(r['block_raw'][:160] == r['block_header_raw'], 'header bytes')
    require(funding_header['hash'] == r['funding_blockhash'], 'funding block hash')
    require(sweep_header['hash'] == r['blockhash'] and sweep_header['previous'] == funding_header['hash'], 'funding to sweep linkage')
    require(tip['hash'] == r['active_tip'] and tip['previous'] == sweep_header['hash'], 'sweep to tip linkage')
    require(r['depth'] == 2 and r['height'] == 103 and r['active_height'] == 104, 'fixture heights/depth')
    return {'synthetic': True, 'inputs': 7, 'outputs': 1, 'fee_sats': fee, 'vsize': sweep['vsize'], 'depth': 2}


if __name__ == '__main__':
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else rp.ROOT / 'receipt.json'
    print(json.dumps(verify(json.loads(path.read_text()))))
