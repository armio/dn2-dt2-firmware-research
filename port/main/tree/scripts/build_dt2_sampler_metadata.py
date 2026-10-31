#!/usr/bin/env python3
"""Relocate DT2's WERP segment clock and SLICE marker selection into DN2.

The exported wrapper takes a DN2 voice mirror, elapsed musical-clock units
and a fresh-note mask. ISR invocation and DSP transport are subsequent work.
"""
from pathlib import Path
import argparse
import json
import struct

import build_dt2_sampler_runtime as R

T, BASE, BE = R.T, R.BASE, R.BE
INPUT = T.ROOT/'output/dn2-research/dt2-sampler-runtime-20261009'
INPUT_SHA = 'bc09972c147dc9714ff4533b90521956e1385ddb709ba972ffcb18651c32e639'
DONOR = T.ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin'
FIRST, LAST = 0x40015c20, 0x40015dec


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes()
    report = json.loads((INPUT/'build-receipt.json').read_text())
    donor = DONOR.read_bytes()
    inventory = json.loads((T.ROOT/'output/dn2-research/oneshot-native-machine-inventory-20261008/inventory.json').read_text())
    assert T.SHA(raw) == INPUT_SHA
    assert T.SHA(donor) == inventory['dt2_main_sha256']
    out.mkdir(parents=True, exist_ok=False)
    copy = report['runtime_copy']
    source, runtime = int(copy['source'], 16), int(copy['destination'], 16)
    original_end = source+copy['bytes']
    assert original_end == int(report['bootstrap'], 16)
    payload = bytearray(raw[source-BASE:original_end-BASE])

    def put(data):
        at = runtime+len(payload)
        payload.extend(data)
        return at

    state = put(bytes(20*16))
    types = put(bytes(16))
    bars = put(donor[0x401ed340-BASE:0x401ed350-BASE])
    segments = put(donor[0x401ed350-BASE:0x401ed35c-BASE])
    native_at = runtime+len(payload)
    native = bytearray(donor[FIRST-BASE:LAST-BASE])
    changes = []

    def patch(at, old, new, reason):
        offset = at-FIRST
        assert native[offset:offset+len(old)] == old, hex(at)
        assert len(old) == len(new)
        native[offset:offset+len(old)] = new
        changes.append(dict(donor=hex(at), runtime=hex(native_at+offset),
                            before=old.hex(), after=new.hex(), reason=reason))

    for at in (0x40015c2c, 0x40015c84):
        patch(at, BE(0x47db41d0), BE(state), 'Private 16 x 20-byte segment states')
    patch(0x40015c90, BE(0x401360ac), BE(0x40134490), 'DN2 native memcpy')
    patch(0x40015cf4, BE(0x401ed340), BE(bars), 'Copied native BARS shift table')
    patch(0x40015d1c, BE(0x401ed350), BE(segments), 'Copied native SEG shift table')
    patch(0x40015dd4, struct.pack('>H', 142), struct.pack('>H', 202), 'DN2 mirror parameter stride')
    put(native)
    update = native_at+0x40015c6e-FIRST
    wrapper_at = runtime+len(payload)
    wrapper = f'''.text
.global sampler_werp_update
sampler_werp_update:
 link.w %fp,#-16
 movem.l %d2-%d3/%a2-%a3,(%sp)
 move.l 8(%fp),%a2
 move.l 16(%fp),%d2
 lea {types:#x},%a3
 moveq #0,%d3
type_loop:
 btst %d3,%d2
 beq.s type_next
 mvz.b 3468(%a2),%d0
 cmpi.l #6,%d0
 seq %d0
 andi.l #1,%d0
 move.b %d0,(%a3,%d3.l)
type_next:
 lea 153(%a2),%a2
 addq.l #1,%d3
 cmpi.l #16,%d3
 bne.s type_loop
 move.l %d2,-(%sp)
 move.l 12(%fp),-(%sp)
 pea {types:#x}
 move.l 8(%fp),-(%sp)
 jsr {update:#x}
 lea 16(%sp),%sp
 movem.l (%sp),%d2-%d3/%a2-%a3
 unlk %fp
 rts
.balign 4
'''
    put(R.assemble(wrapper, wrapper_at, out, 'werp-wrapper'))
    # Native SLICE selection and full-width marker packing from the DT2 frame
    # builder. Its surrounding caller supplied A0 (sample object); all branches
    # within this range are local. Supply a callable boundary after the block.
    slice_first, slice_last = 0x4002ec28, 0x4002ecd8
    slice_at = runtime+len(payload)
    slice_code = donor[slice_first-BASE:slice_last-BASE]
    assert len(slice_code) == 176
    put(slice_code+b'\x4e\x75\x4e\x71')
    slice_wrapper_at = runtime+len(payload)
    slice_wrapper = f'''.text
.global sampler_slice_markers
sampler_slice_markers:
 link.w %fp,#-160
 lea -40(%sp),%sp
 movem.l %d2-%d7/%a2-%a5,(%sp)
 move.l 8(%fp),%a0
 move.l 12(%fp),%a5
 move.l 16(%fp),%d6
 move.l 20(%fp),%a4
 jsr {slice_at:#x}
 movem.l (%sp),%d2-%d7/%a2-%a5
 lea 40(%sp),%sp
 unlk %fp
 rts
.balign 4
'''
    put(R.assemble(slice_wrapper, slice_wrapper_at, out, 'slice-wrapper'))
    assert runtime+len(payload) <= R.LIMIT
    image = bytearray(raw[:source-BASE])+payload
    bootstrap_at = BASE+len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text()
    bootstrap = bootstrap.replace(f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    image.extend(R.assemble(bootstrap, bootstrap_at, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+BE(bootstrap_at)
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'werp-native.bin').write_bytes(native)
    (out/'slice-native.bin').write_bytes(slice_code)
    (out/'werp-native.asm').write_text(T.run([T.BIN/'binutils/objdump', '-D', '-b', 'binary', '-m', 'm68k',
                                           f'--adjust-vma={native_at:#x}', out/'werp-native.bin']))
    receipt = {**report, 'baseline_sha256':INPUT_SHA, 'main_sha256':T.SHA(image), 'bytes':len(image),
               'runtime_copy':{**copy, 'bytes':len(payload)}, 'runtime_sha256':T.SHA(payload),
               'bootstrap':hex(bootstrap_at), 'bootstrap_bytes':len(image)-(bootstrap_at-BASE),
               'werp':dict(donor_sha256=T.SHA(donor), donor_start=hex(FIRST), donor_end=hex(LAST),
                           native_start=hex(native_at), update=hex(update), reset=hex(native_at),
                           reset_all=hex(native_at+0x30), wrapper=hex(wrapper_at), state=hex(state),
                           latched_types=hex(types), state_stride=20, bars=hex(bars), segments=hex(segments),
                           patches=changes, native_sha256=T.SHA(native)),
               'slice':dict(donor_start=hex(slice_first), donor_end=hex(slice_last),
                            native_start=hex(slice_at), native_sha256=T.SHA(slice_code),
                            wrapper=hex(slice_wrapper_at),
                            args=['Native sample metadata object (count at +316, START/END/LOOP triples at +320)',
                                  'Voice parameter mirror base (slot N at +34+2*N)',
                                  'Current note in signed Q8', 'Voice frame base (slot 25 at +218)']),
               'flash_ready':False,
               'remaining':['Invoke WERP update with the DN2 musical clock and fresh voice-note mask',
                            'Transport segment position and segment-retrigger events to DSP without retriggering envelopes',
                            'Invoke SLICE marker selection with native sample metadata and active voice note',
                            'SLICE marker editor and persistent metadata', 'Native browser and persistent sample pool',
                            'Hardware validation']}
    (out/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'], runtime_bytes=len(payload),
                          native_werp_bytes=len(native), wrapper=hex(wrapper_at), flash_ready=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    build(parser.parse_args().output)
