#!/usr/bin/env python3
"""Continue a privately rebuilt FS workspace through exact six-machine MAIN base.

Consumes only freshly generated prerequisites. No firmware is distributed here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from gui_metadata import WIDGET_TWINS, CONTROL_TWINS

HERE = Path(__file__).resolve().parent
PORT = HERE.parent
PROOF = Path('firmware/ghidra/storage-proof')
RESEARCH = Path('output/dn2-research')
V7 = Path('firmware/ghidra/oneshot-proof/v7-source')
BASE = 0x40000400
FINAL_SHA = '205673af2a58674bb239195d4d40a5084d22d626aab59ca11547a31a0d7b0c64'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(path, expected):
    data = path.read_bytes()
    if sha(data) != expected:
        raise ValueError(f'{path}: {sha(data)}, expected {expected}')
    return data


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def dump(path, value):
    write(path, (json.dumps(value, indent=2) + '\n').encode())


def copy(src, dst):
    write(dst, src.read_bytes())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'v7-main', 'v7-dsp', 'v7-shims', 'binutils-build'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--dnfw-src', type=Path, default=PORT/'tools/dnfw/src')
    args = p.parse_args()
    work = args.workspace.resolve()
    if PORT.parent == work or PORT.parent in work.parents:
        p.error('workspace must be outside release tree')
    proof, research = work/PROOF, work/RESEARCH
    verify(proof/'sample-file-v1/candidate/main-os.bin', '769860b6360e67a20c4147acf6f8e1c365dc94f12c8c1f1bbcdafb8ac8b7379c')
    verify(proof/'sample-bank-multi-v2/candidate/main-os.bin', '5bc68e15565634a6bfacfafbe2eedbc49c170aaeb0deb03e63cf5e20a837ae90')
    verify(args.v7_main, '6b2e91a3e237674a6ba6cd0b8b1ae633ec195fc7fa5037e7030dd3b36c4a440d')
    v7dsp = verify(args.v7_dsp, 'b5b568a86d93041a0110a8df83cf17ad5a586d9b93c40882da40fb622a01bcb9')
    v1, v2, v3 = [proof/f'oneshot-storage-merge-v{i}' for i in (1, 2, 3)]
    if any(x.exists() for x in (v1, v2, v3)):
        p.error('bootstrap output exists; use a freshly rebuilt FS workspace')
    source_tree = PORT/'main/tree'
    relative_dirs = [PROOF/f'oneshot-storage-merge-v{i}/src' for i in (1, 2, 3)]
    relative_dirs += [RESEARCH/n for n in ('oneshot-gui-native-v1', 'oneshot-gui-controls-20261008',
                     'oneshot-gui-composition-20261008', 'oneshot-gui-page-v1', 'oneshot-native-bounds-cf-20261008')]
    for relative in relative_dirs:
        for source in (source_tree/relative).rglob('*'):
            if source.is_file():
                target = work/source.relative_to(source_tree)
                write(target, source.read_text().replace('@WORKSPACE@', str(work)).encode())
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(args.dnfw_src.resolve()))

    def run(script, *argv):
        with script.with_suffix('.build.log').open('w') as log:
            result = subprocess.run([sys.executable, '-B', str(script), *map(str, argv)],
                                    cwd=script.parent, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f'{script} failed; see {script.with_suffix(".build.log")}')

    stock = proof/'combined-vfs-lru-candidate/inputs/dn2-1.11-main-os.bin'
    donor_path = proof/'combined-vfs-lru-candidate/inputs/dt2-1.16-main-os.bin'
    donor = donor_path.read_bytes()
    archive_sha = json.loads((PORT/'tools/dependencies.json').read_text())['binutils']['sha256']
    for job, sample in ((v1, 'sample-file-v1'), (v2, 'sample-bank-multi-v2')):
        for name in ('inputs', 'candidate', 'assembly', 'copy-only', 'toolchain'):
            (job/name).mkdir(exist_ok=True)
        (job/'toolchain/build').symlink_to(args.binutils_build.resolve(), target_is_directory=True)
        for src, name in [(stock, 'stock-main.bin'), (donor_path, 'dt2-main.bin'),
                          (proof/'tiny-file-v1/candidate/main-os.bin', 'tiny-main.bin')]:
            copy(src, job/'inputs'/name)
        for name in ('fn_new_map.txt', 'ram_map.txt'):
            copy(proof/sample/'candidate'/name, job/'inputs'/name)
        local_v7 = job/'inputs/v7-source'
        shutil.copytree(args.dnfw_src, local_v7/'src', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(PORT/'tools/dnfw/csrc/usbprobe', local_v7/'csrc/usbprobe')
        probe = (PORT/'tools/gen_usbprobe.py').read_text().replace(
            'SRC = Path(__file__).resolve().parent / "dnfw/csrc/usbprobe"',
            'SRC = Path(__file__).resolve().parents[1] / "csrc/usbprobe"')
        write(local_v7/'scripts/gen_usbprobe_code.py', probe.encode())
        copy(args.v7_main, local_v7/'out/os1handoff-v7/section_3_MAIN_OS.bin')
        copy(args.v7_dsp, local_v7/'out/os1handoff-v7/section_7.bin')
        copy(args.v7_shims, local_v7/'src/dnfw/mods/oneshot_code.json')
        # Archive identity is metadata, not a required downloaded build input.
        builder = job/'src/build_merge.py'
        text = builder.read_text()
        old = "SHA((JOB/'toolchain/binutils-2.43.1.tar.xz').read_bytes())"
        if text.count(old) != 1:
            raise ValueError('Unexpected merge source')
        builder.write_text(text.replace(old, repr(archive_sha)))
        dump(job/'host-protocol.json', {'purpose': 'Source rebuild metadata; no hardware evidence',
                                      'sample_bank': sample})
        run(builder)
        shutil.copytree(job/'candidate', job/'copy-only/candidate')
        run(job/'src/build_runtime.py')
        print(f'{job.name}: {sha((job/"runtime-candidate/main-os.bin").read_bytes())}', flush=True)
    verify(v1/'runtime-candidate/main-os.bin', 'a44c4584e82e0e5bedcdc5a46a479ecd70c74c6b21340d58e73a5aa44634c77a')

    dump(research/'oneshot-gui-dt2-20261008/widget-twins.json', WIDGET_TWINS)
    dump(research/'oneshot-gui-navigation-20261008/control-twins.json', CONTROL_TWINS)
    # Recreate the original chirp cache from our freshly built V7 DSP.
    sys.path.insert(0, str(args.dnfw_src.resolve()))
    from dnfw.image import bootstream
    block = next(x for x in bootstream.walk(v7dsp).blocks if x.target == 0x28310800)
    head = struct.unpack_from('<5I', v7dsp, block.payload_at)
    assert head == (0x3142534f, 1, 0x311814, 7200, 48000)
    pcm_at = block.payload_at + head[2] - 0x310800
    pcm = v7dsp[pcm_at:pcm_at+14400]
    samples = struct.unpack('<7200h', pcm)
    cache = bytearray(401)
    for x in range(96):
        vals = [v >> 8 for v in samples[x*7200//96:(x+1)*7200//96]]
        cache[0x10+x] = max([0]+vals) & 255
        cache[0x70+x] = min([0]+vals) & 255
    ref = research/'oneshot-gui-reference-20261008'
    dump(ref/'builtin-chirp.json', {'dsp_sha256': sha(v7dsp), 'header_file_offset': hex(block.payload_at),
         'bank_header': list(head), 'pcm_file_offset': hex(pcm_at), 'pcm_sha256': sha(pcm), 'cache_sha256': sha(cache)})
    write(ref/'builtin-chirp-native-cache.bin', cache)
    write(v1/'package-final/native-extracted-7', v7dsp)
    gui = research/'oneshot-gui-native-v1'
    controls = research/'oneshot-gui-controls-20261008'
    run(gui/'build.py')
    run(controls/'build.py')
    composition = research/'oneshot-gui-composition-20261008'
    run(composition/'build_gui_main.py', '--gui-bin', gui/'widget.bin', '--gui-symbols', gui/'build.json',
        '--gui-receipt', gui/'build.json', '--controls-bin', controls/'controls.bin',
        '--controls-receipt', controls/'build.json', '--extra-source', research/'oneshot-gui-page-v1/page.S')
    main = verify(composition/'candidate/main-os.bin', 'c0c796196792c817a18c98ba4ccfbf5acae4116bd7213220bebb7a5068d930a8')
    at = 0x402cf884 - BASE
    assert main[at:at+16] == b'os1fs-gui-v1'.ljust(16, b'\0')
    main = main[:at] + b'os1keys-v1'.ljust(16, b'\0') + main[at+16:]
    assert sha(main) == '18963ebb2a9b0f546a80ad9f11f7a27963a14d831ac26f2d5bfa7b747d627854'
    bounds = research/'oneshot-native-bounds-cf-20261008'
    run(bounds/'build_widget.py')
    widget = (bounds/'widget.bin').read_bytes()
    recipe = json.loads((bounds/'build.json').read_text())
    assert recipe['sha256'] == sha(widget) and len(widget) <= 0x1000 and len(widget) % 4 == 0
    assert int(recipe['symbols']['os_wave_cache_poll'], 0) == 0x47a52a00
    assert int(recipe['symbols']['os_wave_draw'], 0) == 0x47a52c20
    region = 0x40330ec0 - BASE
    assert main[region:region+0x1000] == (gui/'widget.bin').read_bytes().ljust(0x1000, b'\0')
    main = bytearray(main)
    main[region:region+0x1000] = widget.ljust(0x1000, b'\0')
    main[at:at+16] = b'os1bounds-v1'.ljust(16, b'\0')
    bounds_main = research/'oneshot-native-bounds-main-source/main-os.bin'
    write(bounds_main, main)
    verify(bounds_main, '99fd5e67aa0fdd8449d4debbd43877b6db00ead5af126ef5836634a61771c476')
    print('GUI, keyboard identity and native bounds match', flush=True)

    # Extract the full donor helper; the historical staging helper cut it short.
    d = research/'dt2-donor-main/section_3_MAIN_OS.bin'
    for name, lo, hi in [('helper', 0x400164e0, 0x40016560), ('helper_full', 0x400164e0, 0x40016576),
                         ('clamp', 0x401997a8, 0x401997b8), ('lookup', 0x401537a8, 0x401537b8)]:
        write(d/(name+'.bin'), donor[lo-BASE:hi-BASE])
    run(v3/'src/build_m3b_chain.py')
    src = v3/'src'
    tool = args.binutils_build.resolve()
    for argv in ([tool/'gas/as-new', '-mcpu=5475', src/'samp_fmt.S', '-o', src/'samp_fmt.o'],
                 [tool/'ld/ld-new', '-Ttext=0x47a52968', '-e', '0', '--no-warn-rwx-segments', src/'samp_fmt.o', '-o', src/'samp_fmt.elf'],
                 [tool/'binutils/objcopy', '-O', 'binary', '-j', '.text', src/'samp_fmt.elf', src/'samp_fmt.bin']):
        subprocess.run(list(map(str, argv)), check=True, capture_output=True)
    runtime = src/'build_runtime_v3.py'
    text = runtime.read_text()
    old = 'raw = bytearray(load(N_SYX.read_bytes()).container.find(3).unpack())'
    assert text.count(old) == 1
    runtime.write_text(text.replace(old, 'raw = bytearray((ROOT/'+repr(str(bounds_main.relative_to(work)))+').read_bytes())'))
    run(runtime)
    final = verify(v3/'runtime-candidate/main-os.bin', FINAL_SHA)
    target = research/'oneshot-drive-v3-m3b-rev3-stackfix-20261009'
    write(target/'main-os.bin', final)
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        copy(v3/'runtime-candidate'/name, target/name)
        copy(v3/'runtime-candidate'/name, src/name)
    dump(target/'source-rebuild.json', {'main_sha256': FINAL_SHA, 'hardware_access': False,
         'scope': 'Exact original FS/GUI/keyboard/native-bounds/M3b MAIN source rebuild'})
    print(f'Exact sampler baseline MAIN: {target/"main-os.bin"}', flush=True)


if __name__ == '__main__':
    main()
