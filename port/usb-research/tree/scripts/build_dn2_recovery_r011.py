#!/usr/bin/env python3
"""Stage R011 MAIN: exact R010 behavior with a new display identifier."""
from pathlib import Path
import argparse
import copy
import json
import shutil

import build_dn2_recovery_tail as T

PARENT = T.ROOT/'output/dn2-research/usb-retained-r010-20261102/main'
MAIN_SHA = '0c597b03a12b071a542048476b250ce8d10c170ad8310d9f9645300b37e8ced6'
EXPANDED_SHA = '99abe93c21694963756e884c675d0e23d21e968983babeaf9fcc3e8af73e5412'
RUNTIME_SHA = '52939a8df0c15605af55cda1d3326249c664c0a3eec0f89d25135c35639784ba'
MARKER = 0x47aa5a0c
PROFILE = dict(schema='dn2-r011-main-identity-1', parent_build='R010',
               parent_main_sha256=MAIN_SHA, parent_expanded_sha256=EXPANDED_SHA,
               parent_runtime_sha256=RUNTIME_SHA, marker_address=hex(MARKER),
               before='R010', after='R011', behavior_unchanged=True)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def parent_image(folder=PARENT):
    staged = (folder/'main-os.bin').read_bytes()
    runtime = (folder/'runtime.bin').read_bytes()
    doc = json.loads((folder/'build-receipt.json').read_text())
    need(doc.get('build') == 'R010' and T.sha(staged) == MAIN_SHA and
         T.sha(runtime) == RUNTIME_SHA, 'requires exact staged R010 parent')
    expanded = T.expand_verified(staged, doc)
    need(T.sha(expanded) == EXPANDED_SHA, 'R010 expanded parent differs')
    return expanded, runtime, doc


def verify_projection(expanded, doc):
    parent, runtime, original = parent_image()
    need(doc.get('build') == 'R011' and doc['runtime_copy'] == original['runtime_copy'],
         'R011 runtime layout differs')
    cfg = doc['boot_tail']
    need(cfg.get('identity_profile') == PROFILE, 'R011 identity provenance differs')
    expected = bytearray(parent)
    offset = int(doc['runtime_copy']['source'], 16)-T.BASE+MARKER-T.SCRATCH
    need(expected[offset:offset+4] == b'R010', 'R010 parent marker missing')
    expected[offset:offset+4] = b'R011'
    wrapper = T.wrapper_bytes(cfg['stored_bytes'], cfg['expanded_tail_bytes'])
    expected[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    need(bytes(expected) == expanded, 'R011 MAIN contains changes beyond identity and loader operands')
    changed_runtime = bytearray(runtime)
    changed_runtime[MARKER-T.SCRATCH:MARKER-T.SCRATCH+4] = b'R011'
    need(doc['runtime_sha256'] == T.sha(changed_runtime), 'R011 runtime identity mismatch')
    return expanded


def build(folder, out):
    expanded, runtime, doc = parent_image(folder)
    check = json.loads((folder/'main-identity-check.json').read_text())
    need(check.get('ok') is True and check.get('runtime_sha256') == RUNTIME_SHA,
         'R010 identity check missing or for another runtime')
    doc = copy.deepcopy(doc)
    raw, runtime = bytearray(expanded), bytearray(runtime)
    marker = MARKER-T.SCRATCH
    source = int(doc['runtime_copy']['source'], 16)-T.BASE
    need(raw[source:source+len(runtime)] == runtime and runtime[marker:marker+4] == b'R010',
         'R010 embedded runtime differs')
    runtime[marker:marker+4] = b'R011'
    raw[source:source+len(runtime)] = runtime
    tail = bytes(raw[T.CUT-T.BASE:])
    blob = T.compress(3, T.CUT, tail).stored
    need(len(blob) <= len(runtime) and T.SCRATCH+len(blob) <= int(doc['runtime_limit'], 16),
         'compressed tail exceeds existing scratch reservation')
    need(T.aplib.depack(blob[8:]) == tail, 'tail compression roundtrip differs')
    out.mkdir(parents=True, exist_ok=False)
    from build_dt2_sampler_runtime import assemble
    wrapper = assemble(T.wrapper_source(len(blob), len(tail)), T.CAVE, out, 'recovery-tail-entry')
    need(len(wrapper) <= T.CAVE_BYTES and wrapper == T.wrapper_bytes(len(blob), len(tail)),
         'R011 wrapper differs from audited encoding')
    raw[T.CAVE-T.BASE:T.CAVE-T.BASE+len(wrapper)] = wrapper
    expanded = bytes(raw)
    staged = expanded[:T.CUT-T.BASE]+blob
    metadata = dict(schema='dn2-main-tail-1', cutoff=hex(T.CUT), entry=hex(T.CAVE),
        original_entry=hex(T.ENTRY), depacker=hex(T.DEPACK), scratch=hex(T.SCRATCH),
        scratch_bytes=len(runtime), stored_bytes=len(blob), expanded_tail_bytes=len(tail),
        stored_sha256=T.sha(blob), tail_sha256=T.sha(tail), wrapper_bytes=len(wrapper),
        wrapper_sha256=T.sha(wrapper), expanded_main_sha256=T.sha(expanded),
        expanded_main_bytes=len(expanded), parent_main_sha256=T.PARENT_SHA,
        before_initializers=True, main_behavior_unchanged=True, identity_profile=PROFILE)
    doc.update(build='R011', main_sha256=T.sha(staged), bytes=len(staged),
               runtime_sha256=T.sha(runtime), boot_tail=metadata, main_identity_only=PROFILE)
    for patch in doc['frame_recorder']['patches']:
        if patch['name'] == 'identity':
            patch['after'] = b'R011'.hex()
    need(T.expand_verified(staged, doc) == expanded, 'R011 staged projection differs')
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
    shutil.copyfile(folder/'parent-frame-recorder-check.json', out/'parent-frame-recorder-check.json')
    proof = dict(ok=True, main_sha256=T.sha(staged), expanded_main_sha256=T.sha(expanded),
                 runtime_sha256=T.sha(runtime), **PROFILE)
    (out/'main-identity-check.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent', type=Path, default=PARENT)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    build(a.parent, a.out)
