"""Regenerate public oracle answers from a prebuilt secp-oracle library, from repository root.

Usage: python3 -I -B public-verify-bench/gen_oracle_answers.py PATH/TO/oracle.so
"""
import sys, json, hashlib
from pathlib import Path
sys.path[:0]=['secp-oracle','public-verify-bench']
import oracle, secp256k1_verify as sk
if len(sys.argv) != 2:
 raise SystemExit(__doc__)
O=oracle.Oracle(Path(sys.argv[1]))
rows=[]
seed=b'public-verify-bench/secp256k1/synthetic-kat/v1'
fixtures=json.loads(Path('public-verify-bench/fixtures/vectors.json').read_text())['vectors']
for row in fixtures:
 scalar=int.from_bytes(hashlib.sha256(seed+b':'+str(row['index']).encode()).digest(),'big')%sk.N or 1
 msg=bytes.fromhex(row['msg_hex']); digest=hashlib.sha256(msg).digest()
 sig=O.sign(scalar,digest); pub=O.point(scalar)[0]
 rows.append({'scalar':format(scalar,'064x'),'message':msg.hex(),'pub':pub.hex(),'signature':sig.hex(),'valid':O.verify(pub,digest,sig),'wrong_message_valid':O.verify(pub,hashlib.sha256(msg+b'\x00').digest(),sig),'zero_r_valid':O.verify(pub,digest,bytes(32)+sig[32:])})
for row in json.loads(Path('public-verify-bench/fixtures/rfc6979.json').read_text()):
 scalar=int(row['scalar_hex'],16); msg=bytes.fromhex(row['message_hex']); digest=hashlib.sha256(msg).digest(); sig=O.sign(scalar,digest); pub=O.point(scalar)[0]
 rows.append({'scalar':format(scalar,'064x'),'message':msg.hex(),'pub':pub.hex(),'signature':sig.hex(),'valid':O.verify(pub,digest,sig),'wrong_message_valid':O.verify(pub,hashlib.sha256(msg+b'\x00').digest(),sig),'zero_r_valid':O.verify(pub,digest,bytes(32)+sig[32:])})
O.lib.oracle_close(O.ctx)
Path('public-verify-bench/fixtures/oracle-answers.json').write_text(json.dumps({'provenance':'libsecp256k1 v0.6.0, secp-oracle commit 0cdc758a56360bf58a851fe91085a327ec97685a; generated from baseline and RFC6979 inputs','cases':rows},indent=2)+'\n')
