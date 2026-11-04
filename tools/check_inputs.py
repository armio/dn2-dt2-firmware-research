#!/usr/bin/env python3
"""Validate the two official R012/R013/R014 OS inputs, or historical release inputs."""
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


def inputs(dn2, dt2, sample_bank=None, *, target='T1E2'):
    if target not in ('T1E2', 'R003', 'R008', 'R011', 'R012', 'R013', 'R014'):
        raise ValueError('Unknown build target')
    if target in ('R012', 'R013', 'R014') and sample_bank is not None:
        raise ValueError(f'{target} does not use --sample-bank; supply only the two official OS files')
    if target not in ('R012', 'R013', 'R014') and sample_bank is None:
        raise ValueError(f'{target} requires --sample-bank for exact historical reproduction')
    release = json.loads((ROOT / 'releases' / f'{target.lower()}.json').read_text())
    supplied = dict(dn2=dn2, dt2=dt2, sample_bank=sample_bank)
    return {key: verify(supplied[key], expected, key)
            for key, expected in release['inputs'].items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dn2', type=Path, required=True)
    parser.add_argument('--dt2', type=Path, required=True)
    parser.add_argument('--sample-bank', type=Path, help='Required only for historical targets')
    parser.add_argument('--target', choices=('T1E2', 'R003', 'R008', 'R011', 'R012', 'R013', 'R014'), default='R014')
    args = parser.parse_args()
    try:
        checked = inputs(args.dn2, args.dt2, args.sample_bank, target=args.target)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'{exc}\n')
    print(f'All {len(checked)} inputs match {args.target}. No files changed.')


if __name__ == '__main__':
    main()
