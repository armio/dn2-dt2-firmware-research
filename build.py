#!/usr/bin/env python3
"""Reproduce T1E2 (stable) or R003 (experimental) locally; never flash a device."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tools.check_inputs import inputs, verify

ROOT = Path(__file__).resolve().parent


def build(args):
    private = inputs(args.dn2, args.dt2, args.sample_bank)
    stable = json.loads((ROOT/'releases/t1e2.json').read_text())
    release = json.loads((ROOT/'releases'/f'{args.target.lower()}.json').read_text())
    paths = json.loads(args.toolchain.read_text())
    if 'binutils_prefix' not in paths:
        raise ValueError('Missing binutils_prefix; rerun port/tools/bootstrap.py')
    for key in ('digikit', 'selas', 'binutils_build', 'container_tool'):
        if not Path(paths[key]).exists():
            raise ValueError(f'Missing tool dependency {key}; rerun port/tools/bootstrap.py')
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        raise ValueError('--out must be outside the source repository')
    if out.exists():
        raise FileExistsError(f'Refusing to overwrite {out}')
    if args.work:
        work = args.work.resolve()
        if work == ROOT or ROOT in work.parents:
            raise ValueError('--work must be outside the source repository')
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix=f'dn2-{args.target.lower()}-'))
    print(f'Private build directory: {work}', flush=True)
    dnfw = ROOT/'port/tools/dnfw/src'

    def run(label, script, *arguments):
        print(label, flush=True)
        log = work/(label.split()[0]+'.log')
        with log.open('w') as stream:
            completed = subprocess.run([sys.executable, '-B', str(ROOT/script), *map(str, arguments)],
                                       cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        if completed.returncode:
            raise RuntimeError(f'{label} failed; inspect {log}')

    run('01-DSP rebuilding', 'port/dsp/build.py',
        '--dn2', private['dn2'], '--dt2', private['dt2'], '--work', work/'dsp',
        '--dnfw-src', dnfw, '--digikit', paths['digikit'], '--selas', paths['selas'])
    run('02-Filesystem rebuilding', 'port/bootstrap/fs.py',
        '--dn2', private['dn2'], '--dt2', private['dt2'], '--sample-bank', private['sample_bank'],
        '--work', work/'bootstrap', '--dnfw-src', dnfw)
    proof = work/'bootstrap/firmware/ghidra/storage-proof'
    official = proof/'combined-vfs-lru-candidate/inputs'
    dn2_main = official/'dn2-1.11-main-os.bin'
    dt2_main = official/'dt2-1.16-main-os.bin'
    run('03-V7-MAIN rebuilding', 'port/tools/build_v7_main.py',
        '--dn2-main', dn2_main, '--dt2-main', dt2_main,
        '--binutils-prefix', paths['binutils_prefix'],
        '--output', work/'v7/main.bin', '--shims-output', work/'v7/oneshot_code.json')
    run('04-Early-GUI rebuilding', 'port/dsp/main_baseline.py',
        '--workspace', work/'bootstrap', '--v7-main', work/'v7/main.bin',
        '--v7-dsp', work/'dsp/firmware/ghidra/oneshot-proof/v7-source/out/os1handoff-v7/section_7.bin',
        '--v7-shims', work/'v7/oneshot_code.json', '--binutils-build', paths['binutils_build'],
        '--dnfw-src', dnfw)
    baseline = work/'bootstrap/output/dn2-research/oneshot-drive-v3-m3b-rev3-stackfix-20261009'
    run('05-MAIN rebuilding', 'port/main/build.py',
        '--work', work/'main', '--dn2-main', dn2_main, '--dt2-main', dt2_main,
        '--baseline-dir', baseline, '--maps', baseline,
        '--worker-symbols', proof/'oneshot-storage-merge-v2/runtime-candidate/worker-symbols.json',
        '--dsp', work/'dsp/section_7.bin', '--dnfw-src', dnfw,
        '--digikit', paths['digikit'], '--binutils-prefix', paths['binutils_prefix'])
    main = work/'main/result/main-os.bin'
    dsp = work/'dsp/section_7.bin'
    for path, expected in ((main, stable['outputs']['main_sha256']),
                           (dsp, stable['outputs']['dsp_sha256'])):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Stable section hash mismatch: {path}')
    if args.target == 'R003':
        run('06-Experimental-Recorder rebuilding', 'port/recorder/build.py',
            '--stable-work', work, '--work', work/'recorder',
            '--toolchain', args.toolchain.resolve())
        main = work/'recorder/main/main-os.bin'
        dsp = work/'recorder/dsp/section_7.bin'
    for path, expected in ((main, release['outputs']['main_sha256']),
                           (dsp, release['outputs']['dsp_sha256'])):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'{args.target} final section hash mismatch: {path}')
    result = work/f'{args.target}.syx'
    print(f'Packaging exact {args.target}', flush=True)
    with (work/'packaging.log').open('w') as log:
        subprocess.run([paths['container_tool'], '-i', str(private['dn2']),
                        '-c', '3', str(main), '-c', '7', str(dsp), '-o', str(result)],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    verify(result, {'bytes': release['outputs']['sysex_bytes'],
                    'sha256': release['outputs']['sysex_sha256']}, f'{args.target} output')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('xb') as target, result.open('rb') as source:
        shutil.copyfileobj(source, target)
    print(f'Exact {args.target} verified: {out}')
    print(f'SHA-256: {release["outputs"]["sysex_sha256"]}')
    print(f'Private intermediate files and logs retained at {work}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dn2', 'dt2', 'sample-bank', 'out'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--target', choices=('T1E2', 'R003'), default='T1E2',
                        help='T1E2 remains the stable default; R003 adds experimental Recorder support')
    parser.add_argument('--toolchain', type=Path, default=ROOT/'.toolchain/paths.json')
    parser.add_argument('--work', type=Path, help='Fresh directory outside the source tree; default: system temporary directory')
    args = parser.parse_args()
    try:
        build(args)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
