#!/usr/bin/env python3
"""Extend a reproduced T1E2 private work tree with the experimental R003 Recorder.

Uses only reviewed source, validated T1E2 intermediates and original donor
extracts. No device access, flashing or publication is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STABLE_MAIN = '4f2cea43e6a70ae922dc58ac7c02cfb91f72fdeaa4b4146ba72e2007a2c39f96'
STABLE_DSP = '409811b1776c9a2cf1c73e5fce2f5dbcf7378c9fd6f835f45ba1a0e97c1a3cc3'
FINAL_MAIN = 'd40f7aedf48ecd31de0fdb179dc73184fc2a3c0641242d4976a37a94dbe7ff67'
FINAL_DSP = 'c03f91a0ebda33b22a2c71432ccba4069d9155523d7ebe1751b0bfc4fedfcda8'
STABLE_FOLDER = 'dn2-sampler-ui-slices-t1e2-20261015'
BACKPORT = Path('output/dn2-research/recorder-stable-backport-20261031')
REOPEN = Path('output/dn2-research/recorder-reopen-r002-20261031')


def checked(path, expected):
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f'Input/output identity mismatch: {path}')


def link(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(source.resolve(), target_is_directory=source.is_dir())


def materialize(source, target, work, digikit):
    for path in sorted(source.rglob('*')):
        if not path.is_file():
            continue
        output = target / path.relative_to(source)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(path.read_text().replace('@WORKSPACE@', str(work))
                          .replace('@DIGIKIT@', str(digikit)))


def build(args):
    stable, work = args.stable_work.resolve(), args.work.resolve()
    if work == ROOT or ROOT in work.parents:
        raise ValueError('--work must be outside the public repository')
    if work.exists():
        raise FileExistsError(f'Choose a fresh work directory: {work}')
    paths = json.loads(args.toolchain.read_text())
    digikit = Path(paths['digikit']).resolve()
    dnfw = ROOT / 'port/tools/dnfw/src'
    checked(stable/'main/result/main-os.bin', STABLE_MAIN)
    checked(stable/'dsp/section_7.bin', STABLE_DSP)
    main_stage = stable/'main/output/dn2-research'/STABLE_FOLDER
    checked(main_stage/'main-os.bin', STABLE_MAIN)
    for path, digest in (
        (stable/'main/firmware/dn2-1.11/section_3_MAIN_OS.bin', '57b06a7960b7c3dc9803bde6b31896b89a2fbdcc404a932ff503f3856d4d7a61'),
        (stable/'main/firmware/dt2-1.16/section_3_MAIN_OS.bin', '57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'),
        (stable/'dsp/firmware/dt2-1.16/section_7_blob.bin', '0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2')):
        checked(path, digest)
    work.mkdir(parents=True)
    materialize(ROOT/'port/main/tree', work, work, digikit)
    materialize(ROOT/'port/main/metadata', work, work, digikit)
    materialize(ROOT/'port/dsp/sources/scripts', work/'scripts', work, digikit)
    materialize(HERE/'tree', work, work, digikit)
    link(dnfw, work/'firmware/ghidra/oneshot-proof/v7-source/src')
    binroot = work/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/toolchain/build'
    for relative, suffix in (('gas/as-new','as'), ('ld/ld-new','ld'),
                             ('binutils/objcopy','objcopy'), ('binutils/nm-new','nm'),
                             ('binutils/objdump','objdump')):
        executable = Path(paths['binutils_prefix'] + suffix)
        if not executable.is_file():
            raise ValueError(f'Missing tool: {executable}')
        link(executable, binroot/relative)
    for relative in ('firmware/dn2-1.11/section_3_MAIN_OS.bin',
                     'firmware/dt2-1.16/section_3_MAIN_OS.bin'):
        link(stable/'main'/relative, work/relative)
    link(stable/'dsp/firmware/dt2-1.16/section_7_blob.bin', work/'firmware/dt2-1.16/section_7_blob.bin')
    research = work/'output/dn2-research'
    link(stable/'main/firmware/dt2-1.16/section_3_MAIN_OS.bin',
         research/'dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin')
    link(stable/'main/output/dn2-research/dt2-browser-runtime-map-20261009',
         research/'dt2-browser-runtime-map-20261009')
    link(main_stage, research/STABLE_FOLDER)
    dsp_stage = stable/'dsp/output/dn2-research/dt2-dsp-usb-multitrack-tap-20261012'
    checked(dsp_stage/'section_7.bin', STABLE_DSP)
    link(dsp_stage, research/'dt2-dsp-usb-multitrack-tap-20261012')
    # The historical reservation check needs only this public identity field.
    (work/'firmware/Digitone_II_OS1.11_DT2_SAMPLERS_T1E2_STABLE.manifest.json').write_text(
        json.dumps({'main_sha256': STABLE_MAIN})+'\n')
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE':'1', 'DIGIKIT':str(digikit),
           'SELAS':str(Path(paths['selas']).resolve()),
           'DSP_RELEASE_SELAS':str(Path(paths['selas']).resolve()),
           'PYTHONPATH':os.pathsep.join(map(str, [dnfw, digikit, ROOT/'port/dsp/support',
                                                ROOT/'research/audits', work/'scripts']))}

    def run(label, relative, *arguments):
        print(label, flush=True)
        log = work/(label+'.log')
        with log.open('w') as output:
            result = subprocess.run([sys.executable, '-B', str(work/relative), *map(str, arguments)],
                                    cwd=work, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f'{label} failed; inspect {log}')

    run('01-recorder-main', BACKPORT/'main-src/build_main.py', '--out', work/BACKPORT/'main-build')
    run('02-recorder-dsp', BACKPORT/'dsp-src/build_recording_dsp.py', '--out', work/'dsp')
    checked(work/'dsp/section_7.bin', FINAL_DSP)
    run('03-reopen', REOPEN/'src/build_main.py', '--out', work/REOPEN/'main')
    run('04-tail', Path('scripts/build_dn2_recovery_tail.py'), '--parent', work/REOPEN/'main', '--out', work/'main')
    checked(work/'main/main-os.bin', FINAL_MAIN)
    (work/'rebuild.json').write_text(json.dumps({
        'schema':'r003-recorder-source-rebuild-v1', 'build':'R003',
        'main_sha256':FINAL_MAIN, 'dsp_sha256':FINAL_DSP,
        'baseline':'T1E2', 'hardware_access':False,
        'experimental':True, 'private_sample_bank_required':True}, indent=2)+'\n')
    print('Exact R003 MAIN and DSP verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stable-work','work','toolchain'):
        parser.add_argument('--'+name, type=Path, required=True)
    build(parser.parse_args())
