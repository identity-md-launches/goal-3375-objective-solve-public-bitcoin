#!/usr/bin/env python3
"""Reproduce the two .xz payloads from a locally supplied official archive. No downloads.

The pinned manifest is an input, never regenerated from unverified archive contents.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import tarfile
import regtest_payment as rp


def package(archive, output):
    manifest = json.loads((rp.ROOT / 'runtime/manifest.json').read_text())
    if rp.sha256(archive) != manifest['upstream_sha256']:
        raise ValueError('archive does not match pinned official SHA256SUMS')
    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as source:
        for name, entry in manifest['components'].items():
            # Read only named members, never extract archive paths or symlinks.
            member = source.getmember(entry['archive_member'])
            if not member.isfile() or member.size != entry['bytes']:
                raise ValueError('unexpected archive member')
            data = source.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise ValueError('official component hash mismatch')
            packed = lzma.compress(data, preset=9)
            if hashlib.sha256(packed).hexdigest() != entry['compressed_sha256']:
                raise ValueError('compressed bytes differ; compare liblzma version, do not overwrite pin')
            (output / (name + '.xz')).write_bytes(packed)
    print('PASS: two exact official components; compressed hashes reproduced')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package(args.archive, args.output)
