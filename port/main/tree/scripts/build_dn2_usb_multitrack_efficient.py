#!/usr/bin/env python3
"""Reduce class-compliant multitrack interrupt work; no device I/O."""
from pathlib import Path
import argparse, json, re
import build_dn2_usb_multitrack as P
B=P.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-usb-multitrack-20261012'
SHA='acb2d713c89ae21b2190f20e482aa78da34a27fdd68c75898b0400f6624d5228'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes(); assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text()); c=doc['runtime_copy']; cfg=doc['usb_multitrack']
    src,base=int(c['source'],16),int(c['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']]); end=base+len(payload)
    payload.extend(bytes(-len(payload)%16)); entry=base+len(payload)
    stage=int(cfg['stage'],16); methods={k:int(v,16) for k,v in cfg['methods'].items()}
    # Every source access is the same aligned32/16-bit access used by400253D0.
    mac=' .long 0xa0030900\n .word 0xa1c0\n move.l %d0,(%a4)+\n'
    tdm=' move.l (%a0)+,%d0\n lsl.l #8,%d0\n'+mac
    pair=''' move.w (%a1)+,%d0
 swap %d0
 clr.w %d0
 move.w (%a1)+,%d1
 move.l %d1,%d2
 andi.l #0xff00,%d2
 or.l %d2,%d0
'''+mac+''' swap %d1
 clr.w %d1
 move.w (%a1)+,%d0
 andi.l #0xffff,%d0
 or.l %d1,%d0
 lsl.l #8,%d0
'''+mac
    asm=f'''.text
.global usb_multitrack_collect_efficient
usb_multitrack_collect_efficient:
 tst.l 0x4058dee8
 beq.w usb_collect_inactive
 lea -56(%sp),%sp
 movem.l %d0-%d7/%a0-%a5,(%sp)
 lea {stage:#x},%a4
 tst.b 0x80005362
 beq.w usb_collect_zero
 move.l #0x80000000,%d3
 move.l -56(%fp),%d0
 moveq #11,%d1
 lsl.l %d1,%d0
 lea 0x4e6df100,%a0
 adda.l %d0,%a0
 lea 0x800053c0,%a1
 moveq #32,%d5
usb_collect_frame:
'''+tdm*14+''' lea 8(%a0),%a0
'''+pair*10+''' lea 24(%a1),%a1
 subq.l #1,%d5
 bne.w usb_collect_frame
 bra.w usb_collect_send
usb_collect_zero:
 pea 4352
'''+f''' pea {stage:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
usb_collect_send:
 pea 32
 pea {stage:#x}
 jsr {methods['usb_native_40003d00']:#x}
 addq.l #8,%sp
 movem.l (%sp),%d0-%d7/%a0-%a5
 lea 56(%sp),%sp
usb_collect_inactive:
 jmp 0x400279a2

.global usb_multitrack_silence_efficient
usb_multitrack_silence_efficient:
 tst.l 0x4058dee8
 beq.w usb_silence_inactive
 jmp {methods['usb_multitrack_silence']:#x}
usb_silence_inactive:
 jmp 0x40027a4e
.balign 4
'''
    out.mkdir(parents=True,exist_ok=False)
    code=B.R.assemble(asm,entry,out,'usb-multitrack-efficient'); payload.extend(code)
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'usb-multitrack-efficient.elf']))}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    assert payload[0x47aa5a0c-base:0x47aa5a10-base]==b'T1DU'; payload[0x47aa5a0f-base]=ord('V')
    image=bytearray(raw[:src-B.BASE])+payload; patches=[]
    for name,at,target in [('collect',0x400276b2,'usb_multitrack_collect_efficient'),('silence',0x400279ba,'usb_multitrack_silence_efficient')]:
        before=b'\x4e\xf9'+B.BE(methods['usb_multitrack_'+name]); after=b'\x4e\xf9'+B.BE(symbols[target]); i=at-B.BASE
        assert image[i:i+6]==before;image[i:i+6]=after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(INPUT/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),runtime_copy={**c,'bytes':len(payload)},bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['usb_multitrack_efficient']=dict(base=str(INPUT/'main-os.bin'),base_sha256=SHA,methods={k:hex(v) for k,v in symbols.items()},
        patches=patches,code=hex(entry),code_bytes=len(code),previous_runtime_end=hex(end),
        identity=dict(address='0x47aa5a0c',before='T1DU',after='T1DV',changed_bytes=1),
        capture_enabled='0x4058dee8',source_getter_reference='0x400253d0',tdm_channels=14,packed_channels=20,frames=32,
        preserves='T1DU packetizer, startup, cache flush, descriptors, return, feedback and POST flag are byte-identical.',
        limits=['Workload correction; hardware cause of T1DU boot/sample-loading failure remains unconfirmed.','Instruction counts are not hardware cycles.','No hardware test or flash performed.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]: (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'): (out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],usb_multitrack_efficient=doc['usb_multitrack_efficient']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
