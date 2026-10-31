#!/usr/bin/env python3
"""Connect original DT2 slice marker packing to the DN2 frame producer."""
from pathlib import Path
import argparse,json,re
import build_dt2_slice_storage as S
B=S.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-slice-storage-20261009'
SHA='01d7f1775f3eec06319f08c2d01eb52619ee6ff77ce3681e28d851fa1b6363de'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());c=doc['runtime_copy']
    src,base=int(c['source'],16),int(c['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']]);out.mkdir(parents=True,exist_ok=False)
    snapshot=base+len(payload);payload.extend(bytes(16*S.SIZE))
    entry=base+len(payload)
    asm=f'''.text
.global slice_capture_hook,slice_frame_hook
/* Native Sound-to-track mirror copy has already validated A2 and D2.
 * Snapshot temporary note sounds too: native caller clears its pointer cache
 * after using them. Persistent sounds are read directly at frame time. */
slice_capture_hook:
 lea -60(%sp),%sp
 movem.l %d0-%d7/%a0-%a6,(%sp)
 mvz.b 222(%a2),%d0
 cmpi.l #10,%d0
 bne.s capture_done
 move.l %d2,%d0
 move.l #{S.SIZE},%d1
 mulu.l %d1,%d0
 lea {snapshot:#x},%a0
 adda.l %d0,%a0
 pea {S.SIZE}
 pea 375(%a2)
 move.l %a0,-(%sp)
 jsr 0x40134490
 lea 12(%sp),%sp
capture_done:
 movem.l (%sp),%d0-%d7/%a0-%a6
 lea 60(%sp),%sp
 move.l %a2,(%a0,%d0.l*4)
 move.l #202,%d0
 jmp 0x400254de
/* The native loop has just copied this track's controls to its frame.
 * D2 is twice (track+1), A3 points at its note, A5 at its live controls,
 * A4 at its frame. Keep DT2's fresh-note gate, including NOTE slice mode. */
slice_frame_hook:
 lea -60(%sp),%sp
 movem.l %d0-%d7/%a0-%a6,(%sp)
 movea.l %d3,%a0
 mvz.b 3468(%a0),%d0
 cmpi.l #10,%d0
 bne.s frame_done
 move.l %d2,%d0
 lsr.l #1,%d0
 subq.l #1,%d0
 mvz.w 0x80005e82,%d1
 btst %d0,%d1
 beq.s frame_done
 lea 0x800052a8,%a0
 movea.l (%a0,%d0.l*4),%a0
 tst.l %a0
 beq.s frame_snapshot
 lea 59(%a0),%a0
 bra.s frame_pack
frame_snapshot:
 move.l #{S.SIZE},%d1
 mulu.l %d1,%d0
 lea {snapshot-316:#x},%a0
 adda.l %d0,%a0
frame_pack:
 mvs.w (%a3),%d0
 move.l %a4,-(%sp)
 move.l %d0,-(%sp)
 move.l %a5,-(%sp)
 move.l %a0,-(%sp)
 jsr {int(doc['slice']['wrapper'],16):#x}
 lea 16(%sp),%sp
frame_done:
 movem.l (%sp),%d0-%d7/%a0-%a6
 lea 60(%sp),%sp
 lea 202(%a5),%a5
 lea 146(%a4),%a4
 jmp 0x40027570
.balign 4
'''
    payload.extend(B.R.assemble(asm,entry,out,'slice-live'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'slice-live.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    for at,hx,label in [(0x400254d4,'218a0c00203c000000ca','slice_capture_hook'),
                        (0x40027568,'4bed00ca49ec0092','slice_frame_hook')]:
        old=bytes.fromhex(hx);assert image[at-B.BASE:at-B.BASE+len(old)]==old
        new=b'\x4e\xf9'+B.BE(symbols[label])+b'\x4e\x71'*((len(old)-6)//2)
        image[at-B.BASE:at-B.BASE+len(old)]=new
        patches.append(dict(address=hex(at),before=hx,after=new.hex(),entry=hex(symbols[label])))
    boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),runtime_copy={**c,'bytes':len(payload)},
        runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),bytes=len(image),flash_ready=False)
    doc['slice_live']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('slice_')},patches=patches,
        snapshots=hex(snapshot),snapshot_stride=S.SIZE,snapshot_count=16,
        original_marker_wrapper=doc['slice']['wrapper'],native_sound_pointer_cache='0x800052a8',
        trigger_mask='0x80005e82',frame_marker_offsets=[238,242,246],
        limits=['Editor integration and hardware playback/persistence remain untested.',
                'Original fresh-note marker updates retained; does not introduce live slice-boundary changes.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),component=doc['slice_live']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
