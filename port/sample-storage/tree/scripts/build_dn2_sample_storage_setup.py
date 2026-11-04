#!/usr/bin/env python3
"""Append explicit sample-storage setup to exact R012; never access hardware."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re
import shutil
import struct

import build_dt2_sampler_runtime as A
import build_dn2_recovery_tail as T

ROOT = Path(__file__).resolve().parents[1]
PARENT_MAIN = '2fca25ae4f90ceb71d357d693a9c75348f1a3b459113c1cdb2b6deacd6b54755'
PARENT_FLAT = 'd8476fa547eb0c1fcdd47bc67a88556e850556d0b701b626984e2e98718d30f4'
PARENT_RUNTIME = '2e4ea75c61e072b148515db93abc7559b658275e40a8a91e2bb7147345c0cf83'
BE = lambda v: struct.pack('>I', v)
SHA = lambda data: hashlib.sha256(data).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def build(parent, out):
    staged = (parent/'main-os.bin').read_bytes()
    raw = bytearray((parent/'expanded/main-os.bin').read_bytes())
    runtime = bytearray((parent/'runtime.bin').read_bytes())
    doc = json.loads((parent/'build-receipt.json').read_text())
    need(doc['build'] == 'R012' and SHA(staged) == PARENT_MAIN
         and SHA(raw) == PARENT_FLAT and SHA(runtime) == PARENT_RUNTIME,
         'Requires exact two-OS R012 parent and expanded projection')
    old = copy.deepcopy(doc)
    region = doc['runtime_copy']
    src, base = int(region['source'], 16), int(region['destination'], 16)
    need(len(runtime) == region['bytes'] and
         raw[src-T.BASE:src-T.BASE+len(runtime)] == runtime,
         'Parent runtime extent or copy differs')
    need(T.aplib.depack(staged[T.CUT-T.BASE+8:]) == bytes(raw[T.CUT-T.BASE:]),
         'Parent staged tail does not match expanded image')
    out.mkdir(parents=True, exist_ok=False)
    constants = dict(FS_STATUS=0x47a9cd7c, FS_RESULT=0x47a9cd80,
                     FS_MOUNTED=0x46b9608c, FS_FORMAT=0x468028e8,
                     FS_MOUNT=0x46802bc0, FS_HASH=0x4680304e,
                     PROJECT_LOCK=0x47a9d99c, PROJECT_EPOCH=0x47a9d9ac)
    sources = [ROOT/'scripts/asm/dn2_sample_storage_ui.S',
               ROOT/'scripts/asm/dn2_sample_storage_worker.S']
    source = ''.join(f'.equ {name},{value:#x}\n' for name, value in constants.items())
    source += '\n'.join(p.read_text() for p in sources)
    start = base+len(runtime)
    extension = A.assemble(source, start, out, 'sample-storage')
    nm = A.T.run([A.T.BIN/'binutils/nm-new', '-n', out/'sample-storage.elf'])
    symbols = {m[2]: int(m[1], 16) for m in
               re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$', nm)}
    runtime.extend(extension)
    need(len(runtime) % 4 == 0 and base+len(runtime) <= int(doc['runtime_limit'], 16),
         'Sample setup exceeds existing runtime reservation')
    marker = 0x47aa5a0c-base
    need(runtime[marker:marker+4] == b'R012', 'Parent identity differs')
    runtime[marker:marker+4] = b'R013'
    image = bytearray(raw[:src-T.BASE])+runtime
    patches = []

    def patch(va, before, after, why):
        offset = va-T.BASE
        need(len(before) == len(after) and image[offset:offset+len(before)] == before,
             f'Unexpected parent instruction at {va:#x}')
        image[offset:offset+len(after)] = after
        patches.append(dict(address=hex(va), before=before.hex(), after=after.hex(), why=why))

    # Native System menu constructor: preserve its following feature check.
    patch(0x4010bcd0, bytes.fromhex('4eb94012c140'),
          b'\x4e\xb9'+BE(symbols['storage_ui_menu_hook']), 'Add explicit sample-storage format entry')
    # Format must not publish a fresh filesystem to stale host/UI consumers.
    # The separate boot mount remains unchanged and enables it after restart.
    fs_region = next(c for c in doc['copies'] if int(c['destination'],16) == 0x46800000)
    fs_publish = int(fs_region['source'],16)+0x2ae4
    patch(fs_publish, bytes.fromhex('7001'), bytes.fromhex('7000'),
          'Keep filesystem unavailable after format until reboot; runtime 0x46802ae4')
    bootstrap_at = T.BASE+len(image)
    bootstrap = (parent/'bootstrap.S').read_text()
    old_count = f'#{region["bytes"]//4},%d1'
    need(bootstrap.count(old_count) == 1, 'Parent bootstrap count differs')
    bootstrap = bootstrap.replace(old_count, f'#{len(runtime)//4},%d1')
    image.extend(A.assemble(bootstrap, bootstrap_at, out, 'bootstrap'))
    patch(T.BASE+0xb2, b'\x4e\xf9'+BE(int(old['bootstrap'], 16)),
          b'\x4e\xf9'+BE(bootstrap_at), 'Copy appended setup runtime during existing startup')
    tail = bytes(image[T.CUT-T.BASE:])
    blob = T.compress(3, T.CUT, tail).stored
    need(len(blob) <= len(runtime) and T.aplib.depack(blob[8:]) == tail,
         'New boot tail exceeds scratch or does not roundtrip')
    wrapper = T.wrapper_bytes(len(blob), len(tail))
    need(len(wrapper) <= T.CAVE_BYTES, 'Boot wrapper exceeds original cave')
    image[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    expanded = bytes(image)
    staged = expanded[:T.CUT-T.BASE]+blob
    metadata = doc['boot_tail']
    metadata.update(scratch_bytes=len(runtime), stored_bytes=len(blob),
        expanded_tail_bytes=len(tail), stored_sha256=SHA(blob), tail_sha256=SHA(tail),
        wrapper_bytes=len(wrapper), wrapper_sha256=SHA(wrapper),
        expanded_main_sha256=SHA(expanded), expanded_main_bytes=len(expanded),
        main_behavior_unchanged=False)
    doc.update(build='R013', baseline_sha256=PARENT_MAIN, main_sha256=SHA(staged),
        bytes=len(staged), runtime_copy={**region, 'bytes':len(runtime)},
        runtime_sha256=SHA(runtime), bootstrap=hex(bootstrap_at),
        bootstrap_bytes=len(expanded)-(bootstrap_at-T.BASE), flash_ready=False)
    doc['sample_storage_setup'] = dict(parent='R012', parent_sha256=PARENT_MAIN,
        methods={name:hex(value) for name,value in symbols.items()},
        constants={name:hex(value) for name,value in constants.items()}, patches=patches,
        source_sha256={p.name:SHA(p.read_bytes()) for p in sources},
        automatic_format=False, explicit_confirmation=True, requires_restart_after_format=True,
        sample_region_lba=['0x5d8000','0x2df0180'], end_exclusive=True,
        dsp_changed=False, hardware_validated=False)
    for p in doc['frame_recorder']['patches']:
        if p['name'] == 'identity':
            p['after'] = b'R013'.hex()
    for name,data in [('main-os.bin',staged),('runtime.bin',runtime),('tail.aplib',blob)]:
        (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    flat = out/'expanded'; flat.mkdir()
    flat_doc = copy.deepcopy(doc); flat_doc.pop('boot_tail')
    flat_doc.update(main_sha256=SHA(expanded), bytes=len(expanded), staged_main_sha256=SHA(staged))
    (flat/'main-os.bin').write_bytes(expanded)
    (flat/'runtime.bin').write_bytes(runtime)
    (flat/'build-receipt.json').write_text(json.dumps(flat_doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(parent/name,out/name)
    for name in ('fn_new_map.txt','ram_map.txt','bootstrap.S'):
        shutil.copyfile(out/name,flat/name)
    print(json.dumps(dict(build='R013',main_sha256=SHA(staged),
        added_runtime_bytes=len(extension),runtime_end=hex(base+len(runtime)),
        output=str(out)),indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a = p.parse_args()
    build(a.parent,a.out)
