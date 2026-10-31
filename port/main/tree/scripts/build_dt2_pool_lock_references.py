#!/usr/bin/env python3
"""Port the DT2 incremental pattern-lock reference scan to DN2 storage."""
from pathlib import Path
import argparse,json,struct
import build_dt2_pool_references as K
B=K.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-pool-references-20261009'
SHA='3d4d3ddd2a639bb2612864766532a04b2c3de0312099ecacefbce44068174029'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    # Native pattern-track getter is an exact twin. Lock getter only changes
    # the nested storage-reader target to DN2's 101-parameter layout.
    assert donor[0x4003f304-B.BASE:0x4003f328-B.BASE]==native[0x4003b2ea-B.BASE:0x4003b30e-B.BASE]
    d=bytearray(donor[0x40053c7a-B.BASE:0x40053ca6-B.BASE])
    n=bytearray(native[0x4004eaa4-B.BASE:0x4004ead0-B.BASE])
    assert d[0x1e:0x22]==B.BE(0x400405ce) and n[0x1e:0x22]==B.BE(0x4003cdba)
    d[0x1e:0x22]=n[0x1e:0x22]=bytes(4);assert d==n
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    base=int(copy['destination'],16);src=int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        payload.extend(bytes(-len(payload)%4));at=base+len(payload);payload.extend(blob);return at
    scan=append(donor[0x40045ef0-B.BASE:0x40045fde-B.BASE])
    flags=append(bytes(1024));index=append(bytes(4));empty=append(bytes(84))
    code=base+len(payload)
    source=f'''.text
.global pool_pattern_track,pool_pattern_lock
pool_pattern_track:
 lea -16(%sp),%sp
 movem.l %d2-%d4/%a2,(%sp)
 move.l 20(%sp),%d3
 move.l 24(%sp),%d2
 jsr 0x4018a97a
 move.l %d0,%d4
 move.l %d0,-(%sp)
 jsr 0x4003efa8
 addq.l #4,%sp
 cmp.l %d3,%d0
 bne.s pattern_saved_sound
 move.l %d4,%a0
 lea 244(%a0),%a0
 move.l %d2,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x40030e66
 addq.l #8,%sp
 move.l %d0,%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 move.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 bra.s pattern_sound_ready
pattern_saved_sound:
 move.l %d4,%a0
 lea 244(%a0),%a0
 move.l {index:#x},-(%sp)
 move.l %a0,-(%sp)
 jsr 0x4019172e
 addq.l #8,%sp
 tst.l %d0
 beq.s pattern_track_empty
 move.l %d0,%a0
 move.l %d2,%d0
 move.l #1163,%d1
 mulu.l %d1,%d0
 lea 52(%a0,%d0.l),%a0
 move.l %a0,%d0
pattern_sound_ready:
 tst.l %d0
 beq.s pattern_track_empty
 move.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s pattern_track_empty
 movem.l (%sp),%d2-%d4/%a2
 lea 16(%sp),%sp
 jmp 0x4003b2ea
pattern_track_empty:
 move.l #{empty:#x},%d0
 movem.l (%sp),%d2-%d4/%a2
 lea 16(%sp),%sp
 rts

pool_pattern_lock:
 move.l 12(%sp),%d0
 move.l 8(%sp),%d1
 move.l 4(%sp),%a0
 move.l %d0,-(%sp)
 move.l %d1,-(%sp)
 move.l %a0,-(%sp)
 jsr 0x4004eaa4
 lea 12(%sp),%sp
 cmpi.l #1023,%d0
 bhi.s pattern_lock_absent
 lsl.l #8,%d0
 rts
pattern_lock_absent:
 moveq #-1,%d0
 rts
.balign 4
'''
    payload.extend(B.R.assemble(source,code,out,'pool-lock-references'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'pool-lock-references.elf'])
    symbols={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3}
    edits=[]
    def edit(at,old,new,why):
        pos=scan+at-0x40045ef0-base;assert payload[pos:pos+len(old)]==old
        assert len(old)==len(new);payload[pos:pos+len(old)]=new
        edits.append(dict(donor=hex(at),runtime=hex(base+pos),before=old.hex(),after=new.hex(),reason=why))
    bindings={0x4099c968:index,0x4099c568:flags,0x401988a2:0x4018a97a,
              0x4003f304:symbols['pool_pattern_track'],0x400d9ed8:0x400dbcc4,
              0x40053c7a:symbols['pool_pattern_lock']}
    for at,value,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,0x40045ef0,0x40045fde)):
        assert value in bindings,hex(value)
        edit(at,B.BE(value),B.BE(bindings[value]),'Native service or private scan state')
    edit(0x40045f3e,B.BE(0x43d0),B.BE(0x4414),'DN2 stored-pattern base')
    edit(0x40045fbc,B.BE(0x6d8dd),B.BE(0x6d921),'DN2 pattern reference cache')
    edit(0x40045f5a,bytes.fromhex('00cd'),bytes.fromhex('0004'),'Native ONESHOT alias maps to shared sample slot28')
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),
        pool_lock_references=dict(scan=hex(scan),flags=hex(flags),index=hex(index),
            symbols={k:hex(v) for k,v in symbols.items() if k.startswith('pool_')},edits=edits,
            patterns_per_pass=128,steps_per_track=128,tracks_per_pattern=16,
            connected_to_scheduler=False,remaining=['First reference-cache producer','Project lifecycle and scheduling']))
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),scan=hex(scan)),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
