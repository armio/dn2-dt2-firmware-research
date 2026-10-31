#!/usr/bin/env python3
"""Connect the native WERP clock to CF frame serialization and DSP playback."""
from pathlib import Path
import argparse
import json

import build_dt2_sampler_metadata as M

R, T, BASE, BE = M.R, M.T, M.BASE, M.BE
INPUT = T.ROOT/'output/dn2-research/dt2-sampler-metadata-v2-20261009'
INPUT_SHA = '831d11a7a55e3fd2aec24e9b8d1393e6844de5d1782485af30068f91ef4d6b47'


# Historical DSP branch is built independently by port/dsp.

def build(out):
    raw = (INPUT/'main-os.bin').read_bytes()
    receipt = json.loads((INPUT/'build-receipt.json').read_text())
    assert T.SHA(raw) == INPUT_SHA
    out.mkdir(parents=True, exist_ok=False)
    copy = receipt['runtime_copy']
    source, runtime = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray(raw[source-BASE:source-BASE+copy['bytes']])
    hook = runtime+len(payload)
    state = int(receipt['werp']['state'], 16)
    update = int(receipt['werp']['update'], 16)
    types = int(receipt['werp']['latched_types'], 16)
    asm = f'''.text
.global werp_frame_hook,werp_reset_hook
werp_frame_hook:
 lea -32(%sp),%sp
 movem.l %d0-%d3/%a0-%a3,(%sp)
 mvz.w 0x80005e82,%d2
 moveq #0,%d3
 lea 0x8000487c,%a1
 lea {types:#x},%a3
type_loop:
 btst %d3,%d2
 beq.s type_next
 mvz.b (%a1),%d0
 cmpi.l #6,%d0
 seq %d0
 andi.l #1,%d0
 move.b %d0,(%a3,%d3.l)
type_next:
 lea 153(%a1),%a1
 addq.l #1,%d3
 cmpi.l #16,%d3
 bne.s type_loop
 move.l %d2,-(%sp)
 move.l 0x402a0dec,-(%sp)
 pea {types:#x}
 move.l %a2,-(%sp)
 jsr {update:#x}
 lea 16(%sp),%sp
 move.l %d0,%d2
 moveq #0,%d3
 move.l %a2,%a0
 lea 0x8000487c,%a1
 lea {state+8:#x},%a3
voice_loop:
 mvz.b (%a1),%d0
 cmpi.l #6,%d0
 bne.s voice_next
 move.l (%a3),%d0
 move.w %d0,118(%a0)
 swap %d0
 move.w %d0,116(%a0)
 moveq #0,%d0
 btst %d3,%d2
 sne %d0
 andi.l #1,%d0
 move.w %d0,120(%a0)
voice_next:
 lea 202(%a0),%a0
 lea 153(%a1),%a1
 lea 20(%a3),%a3
 addq.l #1,%d3
 cmpi.l #16,%d3
 bne.s voice_loop
 movem.l (%sp),%d0-%d3/%a0-%a3
 lea 32(%sp),%sp
 lea 0x80005e60,%a3
 jmp 0x400274c0
werp_reset_hook:
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 jsr {int(receipt['werp']['reset_all'],16):#x}
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 16(%sp),%sp
 jmp 0x4002a4d2
.balign 4
'''
    code = R.assemble(asm, hook, out, 'werp-live')
    symbols = {}
    for line in T.run([T.BIN/'binutils/nm-new', '--defined-only', out/'werp-live.elf']).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    payload.extend(code)
    assert runtime+len(payload) <= R.LIMIT
    image = bytearray(raw[:source-BASE])+payload
    patches = []
    for at, expected, replacement in (
            (0x400274ba, bytes.fromhex('47f980005e60'), b'\x4e\xf9'+BE(hook)),
            (0x40027402, bytes.fromhex('4eb94002a4d2'), b'\x4e\xb9'+BE(symbols['werp_reset_hook']))):
        assert image[at-BASE:at-BASE+6] == expected
        image[at-BASE:at-BASE+6] = replacement
        patches.append(dict(address=hex(at), before=expected.hex(), after=replacement.hex()))
    bootstrap_at = BASE+len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    image.extend(R.assemble(bootstrap, bootstrap_at, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+BE(bootstrap_at)
    (out/'runtime.bin').write_bytes(payload)
    (out/'main-os.bin').write_bytes(image)
    # DSP builds independently; these historical receipt fields never enter MAIN.
    dsp = {'section7_sha256': '50e7581ba00998a24196a1454e05ce0ae1792d859a545c29b89e5d38e4f5710c', 'remaining': ['DSP is built by the separate source-only DSP pipeline']}
    receipt.update(baseline_sha256=INPUT_SHA, main_sha256=T.SHA(image), bytes=len(image),
                   runtime_copy={**copy, 'bytes':len(payload)}, runtime_sha256=T.SHA(payload),
                   bootstrap=hex(bootstrap_at), bootstrap_bytes=len(image)-(bootstrap_at-BASE),
                   werp_live=dict(symbols={k:hex(v) for k,v in symbols.items()}, patches=patches,
                                  clock='0x402a0dec', note_mask='Frame header 34 at 0x80005e82',
                                  metadata_slots=[41,42,43], source='Post-modulation live voice mirror in A2',
                                  machine_types='Native type mirror 0x8000487c + 153*voice, separately from A2',
                                  dsp_sha256=dsp['section7_sha256']),
                   remaining=dsp['remaining'], flash_ready=False)
    (out/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'], dsp_sha256=dsp['section7_sha256'], runtime_bytes=len(payload))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    build(parser.parse_args().output)
