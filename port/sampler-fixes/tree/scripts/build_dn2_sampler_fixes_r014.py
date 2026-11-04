#!/usr/bin/env python3
"""Restage the three checked sampler-control fixes; no DSP or device access."""
from pathlib import Path
import argparse
import copy
import json
import shutil
import struct

import build_dn2_recovery_tail as T

R013_MAIN = 'cd61af42d601faa24b18245ddaeba15724776df2f327be12b5f19751a1c70173'
R013_FLAT = 'c928d2b30522dbd5c4bb385d883ac3149d44d0decb4ab64f5b455a1c1e36b684'
R013_RUNTIME = '88bd465ee60339fb6f55746db71103a9a4132863c4479f8332543fcf3f743137'
BANK_FREE_TAIL_PARENT = 'd70fb90475d9daa914608f7adf2c9e80918dcee29eeef4d71190f81b4b170c1f'
FUNC_CODE_SHA = '465f2e918b5637948eef14195f5c6fe3669682c7390ce0ce5393ec620f71813f'
MARKER, GETTER, SLICE_GATE = 0x47aa5a0c, 0x400c2418, 0x47a93260
BE = lambda v: struct.pack('>I', v)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def verify_projection(expanded, doc):
    """Reverse every allowed edit to recover the exact expanded R013 image."""
    cfg = doc['sampler_fixes_r014']
    parent = Path(cfg['parent'])
    prior = json.loads((parent/'build-receipt.json').read_text())
    old = (parent/'expanded/main-os.bin').read_bytes()
    old_runtime = (parent/'runtime.bin').read_bytes()
    need(T.sha((parent/'main-os.bin').read_bytes()) == R013_MAIN and
         T.sha(old) == R013_FLAT and T.sha(old_runtime) == R013_RUNTIME,
         'R013 parent identity differs')
    need(doc['build'] == 'R014' and doc['copies'] == prior['copies'],
         'Unexpected build or legacy copies')
    region, previous = doc['runtime_copy'], prior['runtime_copy']
    need(region['source'] == previous['source'] and
         region['destination'] == previous['destination'], 'Runtime moved')
    src, base = int(region['source'],16), int(region['destination'],16)
    n = region['bytes']
    need(base+n <= int(doc['runtime_limit'],16), 'Runtime reservation exceeded')
    runtime = expanded[src-T.BASE:src-T.BASE+n]
    need(n == len(old_runtime)+84 and T.sha(runtime) == doc['runtime_sha256'],
         'Unexpected runtime extent or identity')
    need(T.sha(runtime[len(old_runtime):]) == cfg['func_code_sha256'] == FUNC_CODE_SHA,
         'FUNC adapter differs from checked component')
    snap, ui = doc['sampler_func_snapping'], doc['sampler_ui_actions']
    need(snap['parent_sha256'] == R013_FLAT and
         int(snap['entry'],16) == base+len(old_runtime), 'FUNC ancestry/layout differs')
    need({r['native_id'] for r in snap['rows']} == {1,323,341,350,359},
         'Unexpected FUNC parameter coverage')
    vtable = next(s for s in prior['source_view']['spans'] if s['name']=='source_vtables')
    clear_site = int(vtable['runtime'],16)+8+0xdc
    need(int(ui['clear_vtable_site'],16) == clear_site and
         ui['native_clear'] == '0x40018532' and not ui['samp_browser_changed'],
         'Unexpected UI edit')
    undo = bytearray(runtime[:len(old_runtime)])
    for at, before, after in (
        (MARKER, b'R013', b'R014'),
        (clear_site, BE(int(ui['previous_clear'],16)), BE(0x40018532)),
        (SLICE_GATE, bytes.fromhex('673a'), bytes.fromhex('4e71')),
    ):
        off = at-base
        need(old_runtime[off:off+len(before)] == before and
             undo[off:off+len(after)] == after, 'Runtime patch differs')
        undo[off:off+len(before)] = before
    need(bytes(undo) == old_runtime, 'Unrelated inherited runtime changed')
    new_boot, old_boot = src+n, int(prior['bootstrap'],16)
    need(int(doc['bootstrap'],16) == new_boot, 'Bootstrap position differs')
    old_code = old[old_boot-T.BASE:]
    count = BE(len(old_runtime)//4)
    need(old_code.count(count) == 1 and
         expanded[new_boot-T.BASE:] == old_code.replace(count, BE(n//4)),
         'Bootstrap changed beyond runtime copy count')
    prefix = bytearray(expanded[:src-T.BASE])
    for at, after in (
        (GETTER, b'\x4e\xf9'+BE(base+len(old_runtime))),
        (T.BASE+0xb2, b'\x4e\xf9'+BE(new_boot)),
        (T.CAVE, T.wrapper_bytes(doc['boot_tail']['stored_bytes'],
                               doc['boot_tail']['expanded_tail_bytes'])),
    ):
        off = at-T.BASE
        need(prefix[off:off+len(after)] == after, 'Native hook/wrapper differs')
        prefix[off:off+len(after)] = old[off:off+len(after)]
    need(bytes(prefix) == old[:src-T.BASE], 'Unrelated native code/data changed')
    return expanded


def build(parent, patched, out):
    prior = json.loads((parent/'build-receipt.json').read_text())
    doc = json.loads((patched/'build-receipt.json').read_text())
    raw = bytearray((patched/'main-os.bin').read_bytes())
    runtime = bytearray((patched/'runtime.bin').read_bytes())
    need('boot_tail' not in doc and T.sha(raw) == doc['main_sha256'] and
         T.sha(runtime) == doc['runtime_sha256'], 'Requires verified expanded input')
    need(all(k in doc for k in ('sampler_func_snapping','sampler_ui_actions',
                                'slice_frame_isolation')), 'Missing fix stage')
    region = doc['runtime_copy']
    src, base = int(region['source'],16), int(region['destination'],16)
    need(len(runtime) == region['bytes'] and
         raw[src-T.BASE:src-T.BASE+len(runtime)] == runtime, 'Runtime projection differs')
    marker = MARKER-base
    need(runtime[marker:marker+4] == b'R013', 'Unexpected build marker')
    runtime[marker:marker+4] = b'R014'
    raw[src-T.BASE:src-T.BASE+len(runtime)] = runtime
    tail = bytes(raw[T.CUT-T.BASE:])
    blob = T.compress(3, T.CUT, tail).stored
    need(len(blob) <= len(runtime) and T.aplib.depack(blob[8:]) == tail,
         'Tail exceeds scratch or fails roundtrip')
    wrapper = T.wrapper_bytes(len(blob),len(tail))
    need(len(wrapper) == prior['boot_tail']['wrapper_bytes'] <= T.CAVE_BYTES,
         'Boot wrapper extent changed')
    raw[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    expanded = bytes(raw)
    staged = expanded[:T.CUT-T.BASE]+blob
    metadata = copy.deepcopy(prior['boot_tail'])
    metadata.update(scratch_bytes=len(runtime),stored_bytes=len(blob),
        expanded_tail_bytes=len(tail),stored_sha256=T.sha(blob),tail_sha256=T.sha(tail),
        wrapper_bytes=len(wrapper),wrapper_sha256=T.sha(wrapper),
        expanded_main_sha256=T.sha(expanded),expanded_main_bytes=len(expanded),
        main_behavior_unchanged=False)
    doc['sampler_fixes_r014'] = dict(parent=str(parent.resolve()),
        parent_main_sha256=R013_MAIN,patched_input_sha256=doc['main_sha256'],
        func_code_sha256=T.sha(runtime[prior['runtime_copy']['bytes']:]),
        changes=['TUNE FUNC octave snapping','SYN current-page clear','Held SLICE marker publication'],
        dsp_changed=False,usb_changed=False,hardware_validated=False)
    doc.update(build='R014',main_sha256=T.sha(staged),bytes=len(staged),
               runtime_sha256=T.sha(runtime),boot_tail=metadata,flash_ready=False)
    doc.pop('staged_main_sha256',None)
    for patch in doc['frame_recorder']['patches']:
        if patch['name']=='identity': patch['after']=b'R014'.hex()
    verify_projection(expanded,doc)
    need(T.expand_verified(staged,doc) == expanded, 'Staged projection differs')
    out.mkdir(parents=True,exist_ok=False)
    for name,data in [('main-os.bin',staged),('runtime.bin',runtime),('tail.aplib',blob)]:
        (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    flat=out/'expanded';flat.mkdir()
    flat_doc=copy.deepcopy(doc);flat_doc.pop('boot_tail')
    flat_doc.update(main_sha256=T.sha(expanded),bytes=len(expanded),staged_main_sha256=T.sha(staged))
    (flat/'main-os.bin').write_bytes(expanded);(flat/'runtime.bin').write_bytes(runtime)
    (flat/'build-receipt.json').write_text(json.dumps(flat_doc,indent=2)+'\n')
    for name in ('bootstrap.S','fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(patched/name,out/name);shutil.copyfile(patched/name,flat/name)
    print(json.dumps(dict(build='R014',main_sha256=doc['main_sha256'],
                         runtime_sha256=doc['runtime_sha256'],output=str(out))))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent',type=Path,required=True)
    p.add_argument('--patched',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.parent,a.patched,a.out)
