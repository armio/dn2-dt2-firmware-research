#!/usr/bin/env python3
"""Rebuild the historical filesystem baseline from private official inputs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PROOF = Path('firmware/ghidra/storage-proof')


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    return result


def verify(path, digest):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise ValueError(f'{path}: expected {digest}, got {actual}')


def build(args):
    root = HERE.parents[1]
    sys.path.insert(0, str(root/'tools'))
    from check_inputs import inputs
    private = inputs(args.dn2, args.dt2, args.sample_bank)
    args.dn2, args.dt2, args.sample_bank = (private[k] for k in ('dn2', 'dt2', 'sample_bank'))
    sys.path.insert(0, str(args.dnfw_src.resolve()))
    from dnfw.firmware.load import load
    work = args.work.resolve()
    if work == root or root in work.parents:
        raise ValueError('--work must be outside the source repository')
    work.mkdir(parents=True, exist_ok=False)
    for source in (HERE / 'fs-tree').rglob('*'):
        if source.is_file():
            dest = work / source.relative_to(HERE / 'fs-tree')
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(source.read_text().replace('@WORKSPACE@', str(work)))
    lib = work / 'firmware/ghidra/oneshot-proof/v7-source/src'
    lib.parent.mkdir(parents=True)
    lib.symlink_to(args.dnfw_src.resolve(), target_is_directory=True)
    proof = work / PROOF
    combined = proof / 'combined-vfs-lru-candidate'
    dn2 = load(args.dn2.read_bytes()).container.find(3).unpack()
    dt2 = load(args.dt2.read_bytes()).container.find(3).unpack()
    (combined/'inputs/dn2-1.11-main-os.bin').write_bytes(dn2)
    (combined/'inputs/dt2-1.16-main-os.bin').write_bytes(dt2)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(args.dnfw_src.resolve()))

    def run(script, *argv):
        script = work / script
        with script.with_suffix('.build.log').open('w') as log:
            subprocess.run([sys.executable, str(script), *map(str, argv)], cwd=work,
                           env=env, stdout=log, stderr=subprocess.STDOUT, check=True)

    def copy(source, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)

    run(PROOF/'combined-vfs-lru-candidate/candidate/build_graft.py', '--write', '--console', '--fmt-cmd')
    verify(combined/'candidate/main-os.bin', 'c4f4dcc9a03dca1f0f28185fa7c7b7eca384e941fe6b72043cd690abf344ea57')
    run('scripts/build_dn2_drive_io_guard.py')
    stage = proof/'manual-fs-stage-candidate'
    for src, name in [
        (combined/'candidate/main-os.bin', 'combined-main-os.bin'),
        (combined/'candidate/fn_new_map.txt', 'combined-fn-map.txt'),
        (combined/'candidate/ram_map.txt', 'combined-ram-map.txt'),
        (combined/'candidate/graft_report.txt', 'combined-graft-report.txt'),
        (combined/'inputs/dt2_closure.log', 'dt2-closure.log'),
        (combined/'inputs/dn2-1.11-main-os.bin', 'stock-dn2-main.bin'),
        (proof/'io-guard-candidate/patch-report.json', 'io-patch-report.json'),
        (args.dnfw_src/'dnfw/patch/coldfire.py', 'coldfire.py'),
        (work/'scripts/build_dn2_drive_status_v2_patch.py', 'native-isa-validator.py'),
    ]:
        copy(src, stage/'inputs'/name)
    run(PROOF/'manual-fs-stage-candidate/src/build_stage_v2.py')
    reader = proof/'v7-drive-status-v2'
    reader.mkdir()
    code, _ = module(work/'scripts/build_dn2_drive_status_v2_patch.py').make_code()
    (reader/'handler.bin').write_bytes(code)
    composed = proof/'composed-03'
    run('scripts/compose_dn2_fs_trial.py', '--output-dir', composed)
    tiny = proof/'tiny-file-v1'
    for src, name in [
        (composed/'main-os.bin', 'composed-03-main-os.bin'),
        (composed/'fn_new_map.txt', 'prior-fn-map.txt'),
        (composed/'ram_map.txt', 'prior-ram-map.txt'),
        (combined/'candidate/graft_report.txt', 'prior-graft-report.txt'),
        (combined/'inputs/dn2-1.11-main-os.bin', 'dn2-stock-main-os.bin'),
        (combined/'inputs/dt2-1.16-main-os.bin', 'dt2-main-os.bin'),
        (args.dnfw_src/'dnfw/patch/coldfire.py', 'coldfire.py'),
        (work/'scripts/build_dn2_drive_status_v2_patch.py', 'native-isa-validator.py'),
    ]:
        copy(src, tiny/'inputs'/name)
    run(PROOF/'tiny-file-v1/src/build_tiny_file.py')
    verify(tiny/'candidate/main-os.bin', '60229ed6654a8a3d4aa3df7df40f6491d4e088ca264b254ca7205918ec0c8e2d')
    sample = proof/'sample-file-v1'
    for src, name in [
        (tiny/'candidate/main-os.bin', 'tiny-main-os.bin'),
        (tiny/'candidate/build-receipt.json', 'tiny-build-receipt.json'),
        (tiny/'candidate/fn_new_map.txt', 'tiny-fn_new_map.txt'),
        (tiny/'candidate/ram_map.txt', 'tiny-ram_map.txt'),
        (args.dnfw_src/'dnfw/patch/coldfire.py', 'coldfire.py'),
        (work/'scripts/build_dn2_drive_status_v2_patch.py', 'native-isa-validator.py'),
    ]:
        copy(src, sample/'inputs'/name)
    # The first sample is identical in both historical banks. Reconstruct the
    # one-slot header, zero guards and original synthetic storage-test tail.
    bank = args.sample_bank.read_bytes()
    single = struct.pack('<5I', 0x3142534f, 1, 0x311814, 2708, 48000)
    single += bytes(4096) + bank[4140:9556]
    single += bytes(32768-len(single))
    single += bytes(((i*73)^(i>>8)^0xa5)&255 for i in range(32768, 47104))
    (sample/'assets').mkdir()
    (sample/'assets/sample-bank.bin').write_bytes(single)
    run(PROOF/'sample-file-v1/src/build_sample_file.py')
    verify(sample/'candidate/main-os.bin', '769860b6360e67a20c4147acf6f8e1c365dc94f12c8c1f1bbcdafb8ac8b7379c')
    multi = proof/'sample-bank-multi-v2'
    shutil.copytree(sample/'inputs', multi/'inputs')
    (multi/'src').mkdir()
    (multi/'assets').mkdir()
    (multi/'assets/sample-bank.bin').write_bytes(bank)
    protocol = json.loads((sample/'protocol.json').read_text())
    protocol['bank_sha256'] = hashlib.sha256(bank).hexdigest()
    (multi/'protocol.json').write_text(json.dumps(protocol))
    source = (sample/'src/build_sample_file.py').read_text()
    source = source.replace('/sample_808_snare_20261008_v1.osb', '/sample_bank_3slot_20261008_v1.osb')
    (multi/'src/build_sample_file.py').write_text(source)
    run(PROOF/'sample-bank-multi-v2/src/build_sample_file.py')
    verify(multi/'candidate/main-os.bin', '5bc68e15565634a6bfacfafbe2eedbc49c170aaeb0deb03e63cf5e20a837ae90')
    print(f'Filesystem baseline rebuilt: {sample / "candidate/main-os.bin"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dn2', 'dt2', 'sample-bank', 'work', 'dnfw-src'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args()
    build(args)


if __name__ == '__main__':
    main()
