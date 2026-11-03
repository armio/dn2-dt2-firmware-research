#!/usr/bin/env python3
"""Rebuild R008 or stable R011 from reproduced T1E2/R003 private intermediates."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT/'port/recorder'))
from build import checked, link, materialize

OUTPUTS = {
    'R008': ('e048626f25be1cdbbb02f83f892f6f70f876b655d5e45659fc3dc6c1abfa4cc8',
             '7613f501bcf71c8e8a8d99a1976a549baf8f8b2df7dc30a8a88baa2dc08da7ff'),
    'R011': ('a71a42b5d95eca1bfa5416cd7ffe7959687529383a5b7967ac57ab7c4a59f8e5',
             '495a2de2cee75d5c7c9f61e2fb28daed3a40cadf0223de3f57ff24238664f58e'),
}
R003_MAIN = 'd40f7aedf48ecd31de0fdb179dc73184fc2a3c0641242d4976a37a94dbe7ff67'
R003_DSP = 'c03f91a0ebda33b22a2c71432ccba4069d9155523d7ebe1751b0bfc4fedfcda8'


def build(args):
    stable, recorder, work = (p.resolve() for p in
                              (args.stable_work, args.recorder_work, args.work))
    if work == ROOT or ROOT in work.parents:
        raise ValueError('--work must be outside the public repository')
    if work.exists():
        raise FileExistsError(f'Choose a fresh work directory: {work}')
    checked(recorder/'main/main-os.bin', R003_MAIN)
    checked(recorder/'dsp/section_7.bin', R003_DSP)
    paths = json.loads(args.toolchain.read_text())
    digikit = Path(paths['digikit']).resolve()
    work.mkdir(parents=True)
    materialize(ROOT/'port/main/tree', work, work, digikit)
    materialize(ROOT/'port/main/metadata', work, work, digikit)
    materialize(ROOT/'port/dsp/sources/scripts', work/'scripts', work, digikit)
    materialize(ROOT/'port/recorder/tree/scripts', work/'scripts', work, digikit)
    materialize(HERE/'tree', work, work, digikit)
    src = work/'firmware/ghidra/oneshot-proof/v7-source'
    link(ROOT/'port/tools/dnfw/src', src/'src')
    link(digikit, src/'toolchains/digikit')
    binroot = work/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/toolchain/build'
    for relative, suffix in (('gas/as-new','as'), ('ld/ld-new','ld'),
                            ('binutils/objcopy','objcopy'), ('binutils/nm-new','nm'),
                            ('binutils/objdump','objdump')):
        executable = Path(paths['binutils_prefix'] + suffix)
        if not executable.is_file():
            raise ValueError(f'Missing tool: {executable}')
        link(executable, binroot/relative)
    for family, digest in (
            ('dn2-1.11', '336e340aa0cdcd34e314cfa44849f709a3134f6bd4cd57dfc7e15702c83115e2'),
            ('dt2-1.16', '0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2')):
        source = stable/'dsp/firmware'/family/'section_7_blob.bin'
        checked(source, digest)
        link(source, work/'firmware'/family/'section_7_blob.bin')
    research = work/'output/dn2-research'
    link(recorder/'dsp', research/'recorder-stable-backport-20261031/dsp')
    link(recorder/'output/dn2-research/recorder-reopen-r002-20261031/main',
         research/'recorder-reopen-r002-20261031/main')
    for folder in ('dt2-stereo-pan-20261009', 'dt2-stereo-balance-20261009',
                   'dt2-output-hook-20261009'):
        link(stable/'dsp/output/dn2-research'/folder, research/folder)
    # Optional execution fixtures read earlier, already reproduced DSP stages.
    for stage in sorted((stable/'dsp/output/dn2-research').iterdir()):
        if not (research/stage.name).exists():
            link(stage, research/stage.name)
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE':'1', 'DIGIKIT':str(digikit),
           'SELAS':paths['selas'], 'DSP_RELEASE_SELAS':paths['selas'],
           'PYTHONPATH':os.pathsep.join(map(str, [src/'src', digikit/'tools',
                ROOT/'port/dsp/support', ROOT/'research/audits', work/'scripts']))}

    def run(label, script, *arguments):
        print(label, flush=True)
        log = work/(label+'.log')
        with log.open('w') as output:
            result = subprocess.run([sys.executable, '-B', str(work/'scripts'/script),
                                     *map(str, arguments)], cwd=work, env=env,
                                    stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f'{label} failed; inspect {log}')

    r004 = research/'buffer-phase-r004/dsp'
    r005 = research/'sample-scratch-r005-20261101/dsp'
    r007 = research/'usb-guard-r007-20261101/dsp'
    r008 = research/'usb-guard-r008-20261102'
    r008_main = work/'main' if args.target == 'R008' else r008/'main'
    r008_dsp = work/'dsp' if args.target == 'R008' else r008/'dsp'
    run('01-phase-accounting', 'build_dt2_buffer_phase_accounting.py', '--out', r004)
    run('02-scratch-efficiency', 'build_dt2_dsp_scratch_efficiency.py', r004, '--out', r005)
    checked(r005/'section_7.bin', '57be61eb71d41dcb164ecedbb32ea7fd92eae493512d737260466865f5a32e0c')
    run('03-guarded-publication', 'build_dt2_usb_guarded_publication.py', '--out', r007)
    checked(r007/'section_7.bin', '681a0800b66fb046407b6cf8730cf66de7f1a7640ba7bb78cc9e4e15dab0103b')
    run('04-guard-reasons', 'build_dt2_usb_guard_reasons.py', '--out', r008_dsp)
    checked(r008_dsp/'section_7.bin', OUTPUTS['R008'][1])
    run('05-main-marker', 'build_dn2_recovery_tail.py', '--build', 'R008',
        '--parent', research/'recorder-reopen-r002-20261031/main', '--out', r008_main)
    checked(r008_main/'main-os.bin', OUTPUTS['R008'][0])
    if args.target == 'R011':
        r009 = research/'usb-frame-recorder-r009-20261102'
        r010 = research/'usb-retained-r010-20261102'
        run('06-frame-recorder', 'build_dn2_frame_recorder.py', '--out', r009/'main-flat')
        # This published fixture receipt is reused, not a fresh emulator run.
        # The staging builder binds it to the exact reproduced MAIN hash.
        materialize(HERE/'metadata', work, work, digikit)
        run('07-frame-recorder-tail', 'build_dn2_recovery_r009.py',
            '--parent', r009/'main-flat', '--out', r009/'main')
        run('08-retained-main', 'build_dn2_recovery_r010.py', '--out', r010/'main')
        run('09-retained-dsp', 'build_dt2_usb_retained.py', '--out', r010/'dsp')
        run('10-publication-main', 'build_dn2_recovery_r011.py', '--out', work/'main')
        run('11-publication-dsp', 'build_dt2_usb_spi_publication.py', '--out', work/'dsp')
    main_sha, dsp_sha = OUTPUTS[args.target]
    checked(work/'main/main-os.bin', main_sha)
    checked(work/'dsp/section_7.bin', dsp_sha)
    (work/'rebuild.json').write_text(json.dumps({
        'schema':'usb-source-rebuild-v2', 'build':args.target,
        'main_sha256':main_sha, 'dsp_sha256':dsp_sha,
        'baseline':'R003', 'hardware_access':False,
        'fresh_native_execution':False,
        'private_sample_bank_required':True}, indent=2)+'\n')
    print(f'Exact {args.target} MAIN and DSP verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=OUTPUTS, default='R011')
    for name in ('stable-work', 'recorder-work', 'work', 'toolchain'):
        parser.add_argument('--'+name, type=Path, required=True)
    build(parser.parse_args())
