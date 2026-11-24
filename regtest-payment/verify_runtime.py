#!/usr/bin/env python3
"""Verify vendored hashes offline; optionally verify pinned release signature (GPG)."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import re
import tempfile
import regtest_payment as rp

FINGERPRINT = '152812300785C96444D3334D17565732E08E5E41'


def verify(signature=False):
    root = rp.ROOT / 'runtime'
    manifest = json.loads((root / 'manifest.json').read_text())
    for name, expected in manifest['provenance_files'].items():
        if rp.sha256(root / name) != expected:
            raise ValueError('provenance hash mismatch: ' + name)
    upstream = manifest['upstream_url'].rsplit('/', 1)[-1]
    entries = {line.split()[-1]: line.split()[0] for line in (root / 'SHA256SUMS').read_text().splitlines()}
    if entries[upstream] != manifest['upstream_sha256']:
        raise ValueError('release archive hash mismatch')
    with rp.runtime() as binaries:
        for name in manifest['components']:
            if (binaries / name).stat().st_size != manifest['components'][name]['bytes']:
                raise ValueError('installed size mismatch')
    result = {'runtime_hashes': 'PASS', 'installed_bytes': sum(v['bytes'] for v in manifest['components'].values()),
              'compressed_bytes': sum(v['compressed_bytes'] for v in manifest['components'].values()),
              'signature': 'not requested (use --signature)'}
    if signature:
        # Extract the second OpenPGP packet from the original multi-signer release
        # signature. Other signers' keys are deliberately not required or claimed.
        blocks = re.findall(r'-----BEGIN PGP SIGNATURE-----(.*?)-----END PGP SIGNATURE-----',
                            (root / 'SHA256SUMS.asc').read_text(), re.S)
        packets = b''.join(base64.b64decode(''.join(line for line in block.splitlines()
                          if line and not line.startswith(('=', 'Version:', 'Comment:')))) for block in blocks)
        packet = packets[310:893]
        if packet[:3] != bytes.fromhex('890244'):
            raise ValueError('unexpected release signature packet framing')
        with tempfile.TemporaryDirectory(prefix='release-verification-') as tmp:
            directory = Path(tmp)
            sig = directory / 'release.sig'
            sig.write_bytes(packet)
            env = {'HOME': tmp, 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
            base = ['gpg', '--no-options', '--homedir', tmp, '--batch', '--no-autostart']
            keyring = directory / 'release-key.gpg'
            subprocess.run(base + ['--dearmor', '--output', str(keyring), str(root / 'achow101.gpg')],
                           env=env, capture_output=True, check=True)
            base += ['--no-default-keyring', '--keyring', str(keyring)]
            check = subprocess.run(base + ['--status-fd', '1', '--verify', str(sig), str(root / 'SHA256SUMS')],
                                   env=env, capture_output=True, text=True, check=True)
            if '[GNUPG:] VALIDSIG ' + FINGERPRINT + ' ' not in check.stdout:
                raise ValueError('pinned signer fingerprint mismatch')
        result['signature'] = 'PASS: ' + FINGERPRINT
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signature', action='store_true')
    print(json.dumps(verify(parser.parse_args().signature), indent=2))
