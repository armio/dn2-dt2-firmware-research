#!/usr/bin/env python3
"""Validate private T1E2 build inputs without modifying or copying them."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(path, expected, label):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.stat().st_size != expected['bytes']:
        raise ValueError(f'{label}: expected {expected["bytes"]} bytes')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != expected['sha256']:
        raise ValueError(f'{label}: SHA-256 mismatch; expected {expected["sha256"]}, got {digest}')
    return path


def inputs(dn2, dt2, sample_bank):
    release = json.loads((ROOT / 'releases/t1e2.json').read_text())
    supplied = dict(dn2=dn2, dt2=dt2, sample_bank=sample_bank)
    return {key: verify(supplied[key], expected, key)
            for key, expected in release['inputs'].items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dn2', type=Path, required=True)
    parser.add_argument('--dt2', type=Path, required=True)
    parser.add_argument('--sample-bank', type=Path, required=True)
    args = parser.parse_args()
    try:
        inputs(args.dn2, args.dt2, args.sample_bank)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'{exc}\n')
    print('All three private inputs match T1E2. No files changed.')


if __name__ == '__main__':
    main()
