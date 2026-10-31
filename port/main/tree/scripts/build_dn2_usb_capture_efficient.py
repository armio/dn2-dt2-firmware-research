#!/usr/bin/env python3
"""Remove redundant USB42 Q31 conversion in the shared audio/sequencer ISR."""
from pathlib import Path
import argparse
import json
import re

import build_dn2_usb_fullmix as F

B, P = F.B, F.P
INPUT = B.T.ROOT / 'output/dn2-research/dn2-browser-performance-t1e1-20261013'
SHA = '866e2a6c3ac602e1dfd8f75aa685631a500d7a061a00ae77c26be7b41eb59a64'
STAGE, FRAME_BYTES, FRAMES = F.STAGE, 126, 32


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy, full = doc['runtime_copy'], doc['usb_fullmix']
    source, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray(raw[source-B.BASE:source-B.BASE+copy['bytes']])
    previous_end = base + len(payload)
    payload.extend(bytes(-len(payload) % 4))
    entry = base + len(payload)
    native = (P.INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(native) == P.SHA
    assert full['stage'] == hex(STAGE) and full['frame_bytes'] == FRAME_BYTES

    # Native input is already signed24. The old MSAC by -1/MOVCLR and
    # high24 extraction form the identity on all these integer samples.
    # Keep byte reads on packed SRAM and word/long reads aligned on TDM.
    tdm = ''' move.l (%a0)+,%d0
 move.b %d0,(%a4)+
 lsr.l #8,%d0
 .word 0x02c0
 swap %d0
 move.w %d0,(%a4)+
'''
    pair = ''' move.b 2(%a1),(%a4)+
 move.b 1(%a1),(%a4)+
 move.b (%a1),(%a4)+
 move.b 5(%a1),(%a4)+
 move.b 4(%a1),(%a4)+
 move.b 3(%a1),(%a4)+
 lea 6(%a1),%a1
'''
    writer = {
        0x40003dbe: ' moveq #10,%d5', 0x40003dc0: ' lsl.l %d5,%d1',
        0x40003dc2: '', 0x40003dc4: '', 0x40003dc6: f' addi.l #{F.RING:#x},%d1',
        0x40003dd2: F.scale('%d0', FRAME_BYTES),
        0x40003dde: F.scale('%d0', FRAME_BYTES),
        0x40003de8: ''' move.l %d0,-(%sp)
 move.l %d3,%d0
''' + F.scale('%d0', FRAME_BYTES) + '''
 movea.l 40(%sp),%a0
 adda.l %d0,%a0
 move.l %a0,-(%sp)
 move.l %d1,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
 bra.w usb_native_40003e14''',
        0x40003e3a: F.scale('%d1', FRAME_BYTES),
        0x40003e50: ' move.l %d1,%d4', 0x40003e52: ' swap %d4',
        0x40003e6a: ' bsr.w usb_queue_capture',
    }
    # These source instructions belong entirely to the replaced conversion loop.
    for at in (0x40003dea,0x40003dec,0x40003dee,0x40003df0,0x40003df2,
               0x40003df4,0x40003df8,0x40003dfa,0x40003dfc,0x40003dfe,
               0x40003e00,0x40003e02,0x40003e04,0x40003e06,0x40003e08,0x40003e0a):
        writer[at] = ''
    asm = f'''.text
.global usb_capture_collect_packed
usb_capture_collect_packed:
 tst.l 0x4058dee8
 beq.w usb_collect_inactive
 lea -56(%sp),%sp
 movem.l %d0-%d7/%a0-%a5,(%sp)
 lea {STAGE:#x},%a4
 tst.b 0x80005362
 beq.w usb_collect_zero
 move.l -56(%fp),%d0
 moveq #11,%d1
 lsl.l %d1,%d0
 lea 0x4e6df100,%a0
 adda.l %d0,%a0
 lea 0x800053c0,%a1
 moveq #32,%d5
usb_collect_frame:
''' + tdm * 14 + ' lea 8(%a0),%a0\n' + pair * 14 + f''' subq.l #1,%d5
 bne.w usb_collect_frame
 bra.w usb_collect_send
usb_collect_zero:
 pea {FRAME_BYTES*FRAMES}
 pea {STAGE:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
usb_collect_send:
 pea 32
 pea {STAGE:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
 movem.l (%sp),%d0-%d7/%a0-%a5
 lea 56(%sp),%sp
usb_collect_inactive:
 jmp 0x400279a2

.global usb_capture_silence_packed
usb_capture_silence_packed:
 tst.l 0x4058dee8
 beq.w usb_silence_inactive
 pea {FRAME_BYTES*FRAMES}
 pea {STAGE:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
 pea 32
 pea {STAGE:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
usb_silence_inactive:
 jmp 0x40027a4e
usb_queue_capture:
 jmp 0x40005a86
.global usb_native_40003d00
''' + P.native_clone(native, 0x40003d00, 0x40003ede, writer) + '.balign 4\n'
    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(asm, entry, out, 'usb-capture-efficient')
    payload.extend(code)
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new', '-n', out/'usb-capture-efficient.elf']))}
    assert base + len(payload) <= int(doc['runtime_limit'], 16)
    assert payload[0x47AA5A0C-base:0x47AA5A10-base] == b'T1E1'
    payload[0x47AA5A0F-base] = ord('2')
    image = bytearray(raw[:source-B.BASE]) + payload
    patches = []
    for name, at, prior, new, suffix in (
        ('collect',0x400276b2,'usb_fullmix_collect','usb_capture_collect_packed',b''),
        ('silence',0x400279ba,'usb_fullmix_silence','usb_capture_silence_packed',b''),
        ('writer',0x40003d00,'usb_native_40003d00','usb_native_40003d00',b'\x4e\x71')):
        before = b'\x4e\xf9' + B.BE(int(full['methods'][prior],16)) + suffix
        after = b'\x4e\xf9' + B.BE(symbols[new]) + suffix
        offset = at-B.BASE
        assert image[offset:offset+len(before)] == before
        image[offset:offset+len(before)] = after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    boot = B.BASE + len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text().replace(
        f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    assert bootstrap != (INPUT/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    cfg = dict(base=str(INPUT/'main-os.bin'),base_sha256=SHA,
        code=hex(entry),code_bytes=len(code),previous_runtime_end=hex(previous_end),
        methods={k:hex(v) for k,v in symbols.items()},patches=patches,
        identity=dict(address='0x47aa5a0c',before='T1E1',after='T1E2'),
        stage=hex(STAGE),stage_bytes=FRAME_BYTES*FRAMES,stage_frame_bytes=FRAME_BYTES,
        wire_frame_bytes=FRAME_BYTES,channels=42,format='signed24 little endian',
        copy_routine='0x40134490',tdm_channels=14,packed_channels=28,frames=32,
        preserves='All42channel/order/format descriptors, startup, SRAM ring, feedback, host return, MIDI, DSP and sequencer scheduling unchanged.',
        limits=['Instruction count is not hardware elapsed time.','Hardware sequencer responsiveness with USB capture remains pending.'])
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['usb_capture_efficient'] = cfg
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        (out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],usb_capture_efficient=cfg),indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
