#!/usr/bin/env python3
"""Rebuild experimental R008 from reproduced T1E2/R003 private intermediates."""
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

FINAL_MAIN = 'e048626f25be1cdbbb02f83f892f6f70f876b655d5e45659fc3dc6c1abfa4cc8'
FINAL_DSP = '7613f501bcf71c8e8a8d99a1976a549baf8f8b2df7dc30a8a88baa2dc08da7ff'
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
    run('01-phase-accounting', 'build_dt2_buffer_phase_accounting.py', '--out', r004)
    run('02-scratch-efficiency', 'build_dt2_dsp_scratch_efficiency.py', r004, '--out', r005)
    checked(r005/'section_7.bin', '57be61eb71d41dcb164ecedbb32ea7fd92eae493512d737260466865f5a32e0c')
    run('03-guarded-publication', 'build_dt2_usb_guarded_publication.py', '--out', r007)
    checked(r007/'section_7.bin', '681a0800b66fb046407b6cf8730cf66de7f1a7640ba7bb78cc9e4e15dab0103b')
    run('04-guard-reasons', 'build_dt2_usb_guard_reasons.py', '--out', work/'dsp')
    checked(work/'dsp/section_7.bin', FINAL_DSP)
    run('05-main-marker', 'build_dn2_recovery_tail.py', '--build', 'R008',
        '--parent', research/'recorder-reopen-r002-20261031/main', '--out', work/'main')
    checked(work/'main/main-os.bin', FINAL_MAIN)
    (work/'rebuild.json').write_text(json.dumps({
        'schema':'r008-usb-source-rebuild-v1', 'build':'R008',
        'main_sha256':FINAL_MAIN, 'dsp_sha256':FINAL_DSP,
        'baseline':'R003', 'hardware_access':False, 'experimental':True,
        'usb_fault_resolved':False, 'private_sample_bank_required':True}, indent=2)+'\n')
    print('Exact R008 MAIN and DSP verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stable-work', 'recorder-work', 'work', 'toolchain'):
        parser.add_argument('--'+name, type=Path, required=True)
    build(parser.parse_args())
