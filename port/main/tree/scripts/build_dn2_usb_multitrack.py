#!/usr/bin/env python3
"""Widen native UAC2 capture to MAIN plus sixteen stereo tracks; no device I/O."""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_sample_preview as P
import dn2_usb_multitrack_descriptors as D

B = P.B
INPUT = B.T.ROOT/'output/dn2-research/dn2-codec-stage-commit-identity-20261012'
SHA = 'b23354cb00a8b55677ed1edb6ebe133f3c33ef48ebb1ce0d8033fb56d77a07e8'
FRAME_BYTES, FRAMES, CHANNELS = 136, 32, 34


def native_clone(raw, start, end, changes):
    """Relocate a bounded native routine, retaining its branches and operations."""
    exe = B.T.BIN/'binutils/objdump'
    dump = B.T.run([exe, '-D', '-b', 'binary', '-m', 'm68k', '--adjust-vma=0x40000400',
                   f'--start-address={start:#x}', f'--stop-address={end:#x}', INPUT/'main-os.bin'])
    rows = []
    for line in dump.splitlines():
        m = re.match(r'^([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+([^\s]+)\s*(.*)$', line)
        if not m:
            continue
        at, hx, op, args = int(m[1],16), m[2], m[3], m[4]
        assert raw[at-B.BASE:at-B.BASE+len(bytes.fromhex(hx))] == bytes.fromhex(hx)
        rows.append((at,op,args))
        last_end=at+len(bytes.fromhex(hx))
    assert rows[0][0] == start and last_end == end
    lines=[]
    for at,op,args in rows:
        lines.append(f'usb_native_{at:x}:')
        if at in changes:
            lines.append(changes[at]);continue
        args=re.sub(r'%pc@\((0x[0-9a-f]+)\)',r'\1',args)
        if op=='byterev':
            lines.append(f' .word {int.from_bytes(raw[at-B.BASE:at-B.BASE+2],"big"):#x}')
            continue
        # Every internal control transfer is relinked, not copied as old displacement.
        if op.startswith('b') and re.fullmatch(r'0x[0-9a-f]+',args):
            dest=int(args,16)
            if start<=dest<end:
                op=op[:-1]+'.w' if op[-1] in 'sw' else op
                args=f'usb_native_{dest:x}'
            else:
                assert op in ('bras','braw'),(hex(at),op,args)
                op='jmp'
        lines.append(f' {op} {args}')
    assert set(changes)<=set(x[0] for x in rows)
    return '\n'.join(lines)+'\n'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    original_end=base+len(payload)
    # Dedicated whole cache lines; each DMA payload occupies one 1KiB slot.
    payload.extend(bytes(-(base+len(payload))%1024));ring=base+len(payload)
    payload.extend(bytes(16*1024));stage=base+len(payload)
    payload.extend(bytes(FRAME_BYTES*FRAMES));entry=base+len(payload)
    startup={
        0x40003b86:' moveq #10,%d0\n lsl.l %d0,%d2',
        0x40003b88:'',0x40003b8a:' pea 816',0x40003b8e:'',0x40003b90:'',
        0x40003b92:f' addi.l #{ring:#x},%d2',
        0x40003bae:' move.l #0x03300080,%d0',0x40003bb4:' move.l #816,%d1',
        0x40003be2:' bsr.w usb_queue_capture',
    }
    def scale(reg):
        return f' move.l %d6,-(%sp)\n move.l #136,%d6\n mulu.l %d6,{reg}\n move.l (%sp)+,%d6'
    writer={
        0x40003dbe:' moveq #10,%d5',0x40003dc0:' lsl.l %d5,%d1',
        0x40003dc2:'',0x40003dc4:'',0x40003dc6:f' addi.l #{ring:#x},%d1',
        0x40003dd2:scale('%d0'),0x40003dde:scale('%d0'),
        0x40003df2:scale('%d5'),0x40003e3a:scale('%d1'),
        0x40003e50:' move.l %d1,%d4',0x40003e52:' swap %d4',
        0x40003e6a:' bsr.w usb_queue_capture',
    }
    asm=f'''.text
.global usb_multitrack_collect
usb_multitrack_collect:
 lea -56(%sp),%sp
 movem.l %d0-%d7/%a0-%a5,(%sp)
 lea {stage:#x},%a4
 tst.b 0x80005362
 beq.w usb_collect_zero
 move.l #0x80000000,%d3
 clr.l %d2
usb_collect_frame:
 clr.l %d5
usb_collect_channel:
 move.l %d2,-(%sp)
 move.l %d5,-(%sp)
 lea -56(%fp),%a1
 jsr 0x400253d0
 addq.l #8,%sp
 /* Exact native CC full-level EMAC operation, followed by MOVCLR ACC0,D0. */
 .long 0xa0030900
 .word 0xa1c0
 move.l %d0,(%a4)+
 addq.l #1,%d5
 cmpi.l #34,%d5
 bne.w usb_collect_channel
 addq.l #1,%d2
 cmpi.l #32,%d2
 bne.w usb_collect_frame
 bra.w usb_collect_send
usb_collect_zero:
 pea {FRAME_BYTES*FRAMES}
 pea {stage:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
usb_collect_send:
 pea 32
 pea {stage:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
 movem.l (%sp),%d0-%d7/%a0-%a5
 lea 56(%sp),%sp
 jmp 0x400279a2

.global usb_multitrack_silence
usb_multitrack_silence:
 pea {FRAME_BYTES*FRAMES}
 pea {stage:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
 pea 32
 pea {stage:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
 jmp 0x40027a4e

.global usb_multitrack_postfader
usb_multitrack_postfader:
 lea -12(%sp),%sp
 movem.l %d1/%a0-%a1,(%sp)
 jsr 0x40006c4a
 cmpi.l #5,%d0
 beq.w usb_postfader_force
 move.b 0x8000536a,%d0
 bra.w usb_postfader_done
usb_postfader_force:
 moveq #1,%d0
usb_postfader_done:
 movem.l (%sp),%d1/%a0-%a1
 lea 12(%sp),%sp
 jmp 0x4002767a

/* Same stack ABI as40005A86. Descriptor and both arguments stay intact. */
usb_queue_capture:
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 movea.l 24(%sp),%a1
 movea.l 8(%a1),%a0
 move.l 32(%a1),%d0
 addi.l #15,%d0
 andi.l #0xfffffff0,%d0
 movea.l %a0,%a1
 adda.l %d0,%a1
usb_packet_flush:
 cpushl %dc,(%a0)
 lea 16(%a0),%a0
 cmpa.l %a1,%a0
 bcs.w usb_packet_flush
 nop
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 16(%sp),%sp
 jmp 0x40005a86

.global usb_native_40003b32
'''+native_clone(raw,0x40003b32,0x40003c02,startup)+'''
.global usb_native_40003d00
'''+native_clone(raw,0x40003d00,0x40003ede,writer)+'.balign 4\n'
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(asm,entry,out,'usb-multitrack'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'usb-multitrack.elf']))}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    identity=0x47aa5a0c
    assert payload[identity-base:identity-base+4]==b'T1DT'
    payload[identity-base+3]=ord('U')
    image=bytearray(raw[:src-B.BASE])+payload
    patches=[]
    def patch(name,at,before,after):
        offset=at-B.BASE;assert image[offset:offset+len(before)]==before,(name,hex(at))
        assert len(before)==len(after)
        image[offset:offset+len(before)]=after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    for name,at,hx,target in (
        ('collect',0x400276b2,'49f94664b074','usb_multitrack_collect'),
        ('silence',0x400279ba,'4878010048794664b074','usb_multitrack_silence'),
        ('postfader',0x40027674,'10398000536a','usb_multitrack_postfader'),
        ('startup',0x40003b32,'4fefffe47001','usb_native_40003b32'),
        ('writer',0x40003d00,'4fefffe048d73c3c','usb_native_40003d00')):
        before=bytes.fromhex(hx)
        patch(name,at,before,b'\x4e\xf9'+B.BE(symbols[target])+b'\x4e\x71'*((len(before)-6)//2))
    patch('capture_qh',0x400040e8,bytes.fromhex('40380000'),bytes.fromhex('43b80000'))
    image,descriptor=D.transform_main(bytes(image));image=bytearray(image)
    boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(INPUT/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['usb_multitrack']=dict(base=str(INPUT/'main-os.bin'),base_sha256=SHA,
        capture_channels=CHANNELS,return_channels=2,sample_rate=48000,frame_bytes=FRAME_BYTES,
        channel_order=list(D.CHANNEL_ORDER),max_frames=7,max_packet_bytes=952,nominal_packet_bytes=816,
        ring=hex(ring),ring_slots=16,ring_stride=1024,stage=hex(stage),stage_bytes=4352,
        code=hex(entry),code_bytes=base+len(payload)-entry,previous_runtime_end=hex(original_end),
        methods={k:hex(v) for k,v in symbols.items()},patches=patches,descriptors=descriptor,
        clone_source_ranges=[[hex(0x40003b32),hex(0x40003c02)],[hex(0x40003d00),hex(0x40003ede)]],
        identity=dict(address=hex(identity),before='T1DT',after='T1DU',changed_bytes=1),
        cache='Each queued capture packet: CPUSHL DC over its16-byte-rounded payload, then NOP before native endpoint queue; native ACR/CACR unchanged.',
        limits=['Physical USB timing/enumeration not tested.','Internal track export must be post-fader stereo; command bit forced only in class-compliant mode5.',
                'Hardware enumeration and sustained recording remain pending.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]: (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'): (out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],usb_multitrack=doc['usb_multitrack']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
