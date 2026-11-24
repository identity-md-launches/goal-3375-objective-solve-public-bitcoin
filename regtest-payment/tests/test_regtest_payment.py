"""Default suite includes real bundled Core; never downloads or mocks executables."""
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import regtest_payment as rp
import verify_receipt as vr


class PublicChecks(unittest.TestCase):
    def test_amounts(self):
        self.assertEqual(rp.btc_to_sats('0.5'), 50000000)
        self.assertEqual(rp.sats_to_btc(49999000), '0.49999000')
        with self.assertRaises(ValueError):
            rp.btc_to_sats('0.000000001')

    def test_recipient_checksum_and_program(self):
        self.assertEqual(rp.encode_destination('bc'), rp.MAINNET)
        self.assertTrue(rp.DESTINATION.startswith('bcrt1p'))
        self.assertEqual(len(bytes.fromhex(rp.PROGRAM)), 32)

    def test_chain_guard(self):
        rp.assert_regtest_chain({'chain': 'regtest'})
        for chain in ['main', 'test', 'signet', None]:
            with self.assertRaises(RuntimeError):
                rp.assert_regtest_chain({'chain': chain})

    def test_fee_bounds(self):
        for fee in [-1, 0, 10001, 350000000, True]:
            with self.assertRaises(ValueError):
                rp.fee_policy(fee)
        for fee in [1, 10000]:
            with self.assertRaises(ValueError):
                rp.fee_policy(fee, 500)
        rp.fee_policy(1000, 1000)
        rp.fee_policy(10000, 1000)

    def test_delivered_receipt(self):
        vr.verify(json.loads((rp.ROOT / 'receipt.json').read_text()))

    def test_tampered_receipt(self):
        receipt = json.loads((rp.ROOT / 'receipt.json').read_text())
        for key, value in [('fee_sats', 1), ('depth', 0), ('destination', rp.MAINNET),
                           ('output_count', 2), ('vsize', 1), ('synthetic', False),
                           ('blockhash', 'ff'*32), ('active_tip_header_raw', '00'*80)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                vr.verify(dict(receipt, **{key: value}))
        altered = copy.deepcopy(receipt)
        altered['prevouts'][0]['sats'] += 1
        with self.assertRaises(ValueError):
            vr.verify(altered)


class RealCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing executables are a failure, never a mocked pass or silent skip.
        cls.tmp = tempfile.TemporaryDirectory(prefix='offline-core-tests-')
        cls.root = Path(cls.tmp.name)
        cls.context = rp.runtime()
        try:
            cls.bindir = cls.context.__enter__()
        except Exception:
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)
        cls.tmp.cleanup()

    def test_seven_input_sweep(self):
        dest = self.root / 'receipt.json'
        work = self.root / 'success'
        work.mkdir()
        receipt = rp.run(dest, bindir=self.bindir, work_root=work)
        self.assertEqual(vr.verify(receipt)['depth'], 2)
        self.assertEqual(list(work.iterdir()), [])
        self.assertEqual(receipt['core_version'], '/Satoshi:28.1.0/')

    def test_fee_rejection_before_broadcast(self):
        for fee in [0, 10001, 1]:
            with self.subTest(fee=fee):
                work = self.root / ('fee-' + str(fee))
                work.mkdir()
                receipt = self.root / ('rejected-' + str(fee) + '.json')
                with self.assertRaisesRegex(ValueError, 'fee outside'):
                    rp.run(receipt, fee, bindir=self.bindir, work_root=work)
                self.assertFalse(receipt.exists())
                self.assertEqual(list(work.iterdir()), [])

    def test_core_rejects_unsigned_sweep(self):
        # An actual unsigned raw transaction is offered to Core, without mocks.
        def invalid_signer(node, unsigned, prevouts):
            result = node.cli('testmempoolaccept', json.dumps([unsigned]))[0]
            self.assertFalse(result['allowed'])
            self.assertTrue(result.get('reject-reason'))
            raise ValueError('unsigned rejected by Core')
        work = self.root / 'unsigned'
        work.mkdir()
        receipt = self.root / 'unsigned.json'
        with self.assertRaisesRegex(ValueError, 'unsigned rejected by Core'):
            rp.run(receipt, bindir=self.bindir, signer=invalid_signer, work_root=work)
        self.assertFalse(receipt.exists())
        self.assertEqual(list(work.iterdir()), [])

    def test_sigterm_and_sigint_cleanup(self):
        for sig in [signal.SIGTERM, signal.SIGINT]:
            with self.subTest(signal=sig):
                work = self.root / ('interrupt-' + str(sig))
                work.mkdir()
                receipt, ready = work / 'receipt.json', work / 'ready.json'
                proc = subprocess.Popen([sys.executable, '-B', str(rp.ROOT / 'regtest_payment.py'),
                    '--bindir', str(self.bindir), '--receipt', str(receipt), '--hold-at', 'signed',
                    '--ready', str(ready), '--work-root', str(work)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 30
                    while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
                        time.sleep(.05)
                    self.assertTrue(ready.exists(), 'Core must reach signed phase')
                    state = json.loads(ready.read_text())
                    self.assertTrue(Path(state['datadir']).exists())
                    proc.send_signal(sig)
                    out, err = proc.communicate(timeout=25)
                    self.assertEqual(proc.returncode, 130, err)
                    self.assertFalse(receipt.exists())
                    self.assertFalse(Path(state['datadir']).exists())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(state['node_pid'], 0)
                    self.assertNotIn('signed', out)
                    ready.unlink()
                    self.assertEqual(list(work.iterdir()), [])
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()


if __name__ == '__main__':
    unittest.main()
