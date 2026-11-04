#!/usr/bin/env python3
"""Pack the approved MAIN tail separately, before the original startup.

R003–R005 and R007–R008 require exact R002; later variants use pinned profiles.
Protected loader sections and DSP are unchanged by this MAIN-only builder.
The temporary staging region is the existing sampler runtime reservation, used
before the original bootstrap installs that runtime. No extra RAM is reserved.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.container.section import compress
from dnfw.codec import aplib

BASE, CUT, CAVE, CAVE_BYTES = 0x40000400, 0x402faf54, 0x4028da70, 136
ENTRY, DEPACK, SCRATCH = 0x400004e8, 0x40136540, 0x47a58000
PARENT_SHA = 'c76eee3632de5fa63bf1bb367d9a2973807dfba992091848a9e8b67ad8988199'
sha = lambda data: hashlib.sha256(data).hexdigest()


def wrapper_bytes(stored_bytes, expanded_bytes):
    """Exact independently assembled OS 1.11 entry, with two length operands."""
    if stored_bytes <= 8 or stored_bytes % 4 or not 0 < expanded_bytes <= 0x800000:
        raise ValueError('invalid tail lengths')
    code = bytearray.fromhex(
        '4fefffc448d77fff41f9402faf5443f947a58000203c00000000'
        '22d8538066fa4879402faf54487947a580004eb940136540508f'
        '0c8000000000660e4cd77fff4fef003c4ef9400004e84ac860fc0000')
    struct.pack_into('>I',code,22,stored_bytes//4)
    struct.pack_into('>I',code,54,expanded_bytes)
    return bytes(code)


def expand_verified(raw, doc):
    """Validate and project a staged image; does not claim native execution."""
    from audit_dn2_recovery import decode_with_margin
    m = doc['boot_tail']
    expected = dict(schema='dn2-main-tail-1', cutoff=hex(CUT), entry=hex(CAVE),
        original_entry=hex(ENTRY), depacker=hex(DEPACK), scratch=hex(SCRATCH),
        parent_main_sha256=PARENT_SHA)
    if doc.get('build') == 'R014':
        from build_dn2_sampler_fixes_r014 import BANK_FREE_TAIL_PARENT
        expected['parent_main_sha256'] = BANK_FREE_TAIL_PARENT
    if any(m.get(k) != v for k,v in expected.items()) or sha(raw) != doc['main_sha256']:
        raise ValueError('unrecognized tail profile or MAIN identity')
    blob = raw[CUT-BASE:]
    size = len(blob)
    if (size != m['stored_bytes'] or size > m['scratch_bytes']
            or m['scratch_bytes'] != doc['runtime_copy']['bytes']
            or int(doc['runtime_copy']['destination'],16) != SCRATCH
            or SCRATCH+size > int(doc['runtime_limit'],16)
            or sha(blob) != m['stored_sha256']):
        raise ValueError('tail identity or scratch extent mismatch')
    tail, _ = decode_with_margin(blob)
    if len(tail) != m['expanded_tail_bytes'] or sha(tail) != m['tail_sha256']:
        raise ValueError('expanded tail identity mismatch')
    wrapper = wrapper_bytes(size,len(tail))
    if (raw[:4] != struct.pack('>I',CAVE)
            or raw[CAVE-BASE:CAVE-BASE+len(wrapper)] != wrapper
            or len(wrapper) != m['wrapper_bytes'] or sha(wrapper) != m['wrapper_sha256']):
        raise ValueError('entry wrapper mismatch')
    expanded = raw[:CUT-BASE] + tail
    if len(expanded) != m['expanded_main_bytes'] or sha(expanded) != m['expanded_main_sha256']:
        raise ValueError('expanded MAIN identity mismatch')
    if doc.get('build') == 'R006':
        from build_dn2_recovery_r006 import verify_projection
        verify_projection(expanded,doc)
    elif doc.get('build') == 'R009':
        from build_dn2_recovery_r009 import verify_projection
        verify_projection(expanded,doc)
    elif doc.get('build') == 'R010':
        from build_dn2_recovery_r010 import verify_projection
        verify_projection(expanded,doc)
    elif doc.get('build') == 'R011':
        from build_dn2_recovery_r011 import verify_projection
        verify_projection(expanded,doc)
    elif doc.get('build') == 'R014':
        from build_dn2_sampler_fixes_r014 import verify_projection
        verify_projection(expanded,doc)
    return expanded


def wrapper_source(stored_bytes, expanded_bytes):
    if stored_bytes <= 8 or stored_bytes % 4 or expanded_bytes <= 0:
        raise ValueError('invalid tail lengths')
    return f'''/* Before original entry: preserve caller registers/stack and boot flags. */
.text
.global recovery_tail_entry
recovery_tail_entry:
 lea -60(%sp),%sp
 movem.l %d0-%d7/%a0-%a6,(%sp)
 lea {CUT:#x},%a0
 lea {SCRATCH:#x},%a1
 move.l #{stored_bytes//4},%d0
copy_tail:
 move.l (%a0)+,(%a1)+
 subq.l #1,%d0
 bne.s copy_tail
 pea {CUT:#x}
 pea {SCRATCH:#x}
 jsr {DEPACK:#x}
 addq.l #8,%sp
 cmpi.l #{expanded_bytes},%d0
 bne.s invalid_length
 movem.l (%sp),%d0-%d7/%a0-%a6
 lea 60(%sp),%sp
 jmp {ENTRY:#x}
invalid_length:
 halt
 bra.s invalid_length
.balign 4
'''


def build(parent, out, build_id='R003'):
    if build_id == 'R011':
        from build_dn2_recovery_r011 import build as build_identity
        return build_identity(parent,out)
    if build_id == 'R010':
        from build_dn2_recovery_r010 import build as build_identity
        return build_identity(parent,out)
    if build_id == 'R009':
        from build_dn2_recovery_r009 import build as build_recorder
        return build_recorder(parent,out)
    if build_id == 'R006':
        from build_dn2_recovery_r006 import build as build_observer
        return build_observer(parent,out)
    if build_id not in ('R003', 'R004', 'R005', 'R007', 'R008'):
        raise ValueError('unsupported build identifier')
    raw = bytearray((parent/'main-os.bin').read_bytes())
    doc = json.loads((parent/'build-receipt.json').read_text())
    runtime = bytearray((parent/'runtime.bin').read_bytes())
    if sha(raw) != PARENT_SHA or doc['main_sha256'] != PARENT_SHA:
        raise ValueError('requires exact R002 MAIN')
    if sha(runtime) != doc['runtime_sha256']:
        raise ValueError('R002 runtime identity mismatch')
    copy = doc['runtime_copy']
    source = int(copy['source'], 16)-BASE
    if (int(copy['destination'],16) != SCRATCH or len(runtime) != copy['bytes']
            or raw[source:source+len(runtime)] != runtime
            or raw[:4] != struct.pack('>I', ENTRY)
            or any(raw[CAVE-BASE:CAVE-BASE+CAVE_BYTES])):
        raise ValueError('unexpected R002 startup layout')
    # Change only the displayed build identifier in the existing runtime.
    marker = 0x47aa5a0c-SCRATCH
    if runtime[marker:marker+4] != b'R002':
        raise ValueError('unexpected version marker')
    runtime[marker:marker+4] = build_id.encode('ascii')
    raw[source:source+len(runtime)] = runtime
    tail = bytes(raw[CUT-BASE:])
    blob = compress(3, CUT, tail).stored
    if len(blob) > len(runtime) or SCRATCH+len(blob) > int(doc['runtime_limit'],16):
        raise ValueError('compressed tail exceeds existing runtime scratch')
    if aplib.depack(blob[8:]) != tail:
        raise ValueError('tail compression roundtrip failed')
    out.mkdir(parents=True, exist_ok=False)
    from build_dt2_sampler_runtime import assemble
    wrapper = assemble(wrapper_source(len(blob), len(tail)), CAVE, out, 'recovery-tail-entry')
    if len(wrapper) > CAVE_BYTES or wrapper != wrapper_bytes(len(blob),len(tail)):
        raise ValueError('entry wrapper exceeds cave or differs from audited encoding')
    raw[CAVE-BASE:CAVE-BASE+len(wrapper)] = wrapper
    raw[:4] = struct.pack('>I', CAVE)
    expanded = bytes(raw)
    staged = expanded[:CUT-BASE] + blob
    metadata = dict(schema='dn2-main-tail-1', cutoff=hex(CUT), entry=hex(CAVE),
        original_entry=hex(ENTRY), depacker=hex(DEPACK), scratch=hex(SCRATCH),
        scratch_bytes=len(runtime), stored_bytes=len(blob), expanded_tail_bytes=len(tail),
        stored_sha256=sha(blob), tail_sha256=sha(tail), wrapper_bytes=len(wrapper),
        wrapper_sha256=sha(wrapper), expanded_main_sha256=sha(expanded),
        expanded_main_bytes=len(expanded), parent_main_sha256=PARENT_SHA,
        before_initializers=True, dsp_and_runtime_behavior_unchanged=True)
    doc.update(build=build_id, baseline_sha256=PARENT_SHA, main_sha256=sha(staged),
        runtime_sha256=sha(runtime), bytes=len(staged), boot_tail=metadata)
    if expand_verified(staged,doc) != expanded:
        raise ValueError('verified expansion differs from intended MAIN')
    (out/'main-os.bin').write_bytes(staged)
    (out/'runtime.bin').write_bytes(runtime)
    (out/'tail.aplib').write_bytes(blob)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S'):
        shutil.copyfile(parent/name,out/name)
    # Runtime checks consume the exact expanded memory projection. The native
    # dual-loader check separately proves that the packaged entry produces it.
    projection = out/'expanded'
    projection.mkdir()
    flat_doc = dict(doc, main_sha256=sha(expanded), bytes=len(expanded))
    flat_doc.pop('boot_tail')
    flat_doc['staged_main_sha256'] = sha(staged)
    (projection/'main-os.bin').write_bytes(expanded)
    (projection/'runtime.bin').write_bytes(runtime)
    (projection/'build-receipt.json').write_text(json.dumps(flat_doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt','bootstrap.S'):
        shutil.copyfile(out/name,projection/name)
    print(json.dumps(dict(build=build_id,main_sha256=sha(staged),
        expanded_main_sha256=sha(expanded),stored_tail_bytes=len(blob),
        restored_tail_bytes=len(tail),wrapper_bytes=len(wrapper)),indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--build',choices=('R003','R004','R005','R006','R007','R008','R009','R010','R011'),default='R003')
    args = parser.parse_args()
    build(args.parent,args.out,args.build)
