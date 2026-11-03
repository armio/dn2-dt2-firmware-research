#!/usr/bin/env python3
"""Stage the R009 recorder using the existing audited MAIN-tail loader."""
from pathlib import Path
import copy
import json
import shutil

import build_dn2_recovery_tail as T

SCHEMA = 'dn2-recovery-frame-recorder-r009-1'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def verify_flat(raw, doc, runtime):
    import build_dn2_frame_recorder as B
    need(doc.get('build') == 'R009', 'expected R009 recorder build')
    need(T.sha(raw) == doc['main_sha256'] and T.sha(runtime) == doc['runtime_sha256'],
         'R009 flat input hash mismatch')
    scope = B.verify_scope(raw, doc, runtime)
    need(scope['exact_parent_reversal'], 'R009 failed exact R008 scope reversal')
    return dict(schema=SCHEMA, flat_main_sha256=T.sha(raw), runtime_sha256=T.sha(runtime),
                parent_main_sha256=B.MAIN_SHA, parent_runtime_sha256=B.RUNTIME_SHA,
                exact_parent_reversal=True)


def verify_projection(expanded, doc):
    import build_dn2_frame_recorder as B
    parent = (B.PARENT/'main-os.bin').read_bytes()
    need(T.sha(parent) == B.MAIN_SHA, 'R008 parent changed')
    cfg = doc['boot_tail']
    cave = slice(T.CAVE-T.BASE, T.CAVE-T.BASE+T.CAVE_BYTES)
    expected = bytearray(parent[cave])
    wrapper = T.wrapper_bytes(cfg['stored_bytes'], cfg['expanded_tail_bytes'])
    expected[:len(wrapper)] = wrapper
    need(expanded[cave] == expected, 'R009 recovery wrapper differs')
    flat = bytearray(expanded)
    flat[cave] = parent[cave]
    c = doc['runtime_copy']
    off, size = int(c['source'], 16)-T.BASE, c['bytes']
    normalized = dict(doc, main_sha256=T.sha(flat))
    proof = verify_flat(bytes(flat), normalized, bytes(flat[off:off+size]))
    need(cfg.get('observer_profile') == proof, 'R009 recorder provenance differs')
    return bytes(flat)


def build(folder, out):
    raw = bytearray((folder/'main-os.bin').read_bytes())
    runtime = (folder/'runtime.bin').read_bytes()
    doc = json.loads((folder/'build-receipt.json').read_text())
    profile = verify_flat(raw, doc, runtime)
    check = json.loads((folder/'frame-recorder-check.json').read_text())
    need(check.get('ok') is True and check.get('main_sha256') == T.sha(raw),
         'native R009 recorder checks missing or for another image')
    tail = bytes(raw[T.CUT-T.BASE:])
    blob = T.compress(3, T.CUT, tail).stored
    need(len(blob) <= len(runtime) and T.SCRATCH+len(blob) <= int(doc['runtime_limit'], 16),
         'compressed tail exceeds existing scratch reservation')
    need(T.aplib.depack(blob[8:]) == tail, 'inner compression roundtrip failed')
    out.mkdir(parents=True, exist_ok=False)
    from build_dt2_sampler_runtime import assemble
    wrapper = assemble(T.wrapper_source(len(blob), len(tail)), T.CAVE, out, 'recovery-tail-entry')
    need(len(wrapper) <= T.CAVE_BYTES and wrapper == T.wrapper_bytes(len(blob), len(tail)),
         'R009 wrapper differs from audited encoding')
    raw[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    expanded = bytes(raw)
    staged = expanded[:T.CUT-T.BASE]+blob
    metadata = dict(schema='dn2-main-tail-1', cutoff=hex(T.CUT), entry=hex(T.CAVE),
        original_entry=hex(T.ENTRY), depacker=hex(T.DEPACK), scratch=hex(T.SCRATCH),
        scratch_bytes=len(runtime), stored_bytes=len(blob), expanded_tail_bytes=len(tail),
        stored_sha256=T.sha(blob), tail_sha256=T.sha(tail), wrapper_bytes=len(wrapper),
        wrapper_sha256=T.sha(wrapper), expanded_main_sha256=T.sha(expanded),
        expanded_main_bytes=len(expanded), parent_main_sha256=T.PARENT_SHA,
        before_initializers=True, dsp_and_runtime_behavior_unchanged=False,
        observer_profile=profile)
    doc.update(build='R009', main_sha256=T.sha(staged), bytes=len(staged), boot_tail=metadata)
    need(T.expand_verified(staged, doc) == expanded, 'staged R009 projection differs')
    for name, data in [('main-os.bin', staged), ('runtime.bin', runtime), ('tail.aplib', blob)]:
        (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    projection = out/'expanded'
    projection.mkdir()
    flat_doc = copy.deepcopy(doc)
    flat_doc.pop('boot_tail')
    flat_doc.update(main_sha256=T.sha(expanded), bytes=len(expanded), staged_main_sha256=T.sha(staged))
    (projection/'main-os.bin').write_bytes(expanded)
    (projection/'runtime.bin').write_bytes(runtime)
    (projection/'build-receipt.json').write_text(json.dumps(flat_doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S'):
        shutil.copyfile(folder/name, out/name)
        shutil.copyfile(folder/name, projection/name)
    shutil.copyfile(folder/'frame-recorder-check.json', out/'frame-recorder-check.json')
    print(json.dumps(dict(build='R009', main_sha256=T.sha(staged),
        expanded_main_sha256=T.sha(expanded), stored_tail_bytes=len(blob),
        restored_tail_bytes=len(tail), wrapper_bytes=len(wrapper))))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    build(a.parent, a.out)
