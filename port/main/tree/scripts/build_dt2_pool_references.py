#!/usr/bin/env python3
"""Port DT2 saved/live-kit sample-reference scanning to DN2 layouts.

The project query is callable but deliberately not bound to the browser yet:
the other two reference caches still need their producers connected.
"""
from pathlib import Path
import argparse,json,struct
import build_dt2_browser_parameters as P
B=P.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-browser-parameters-20261009'
SHA='763553120dd9916024d1054b32abe628512d4bd131cdb7463733de9513f4e210'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    # Saved-kit accessor is identical apart from each device's serialized kit
    # stride. Live-track accessor has an exact complete native twin.
    a=bytearray(donor[0x401a1f2a-B.BASE:0x401a1f4a-B.BASE])
    b=bytearray(native[0x4019172e-B.BASE:0x4019174e-B.BASE])
    assert a[0x12:0x16]==B.BE(0x5574) and b[0x12:0x16]==B.BE(0x5d71)
    a[0x12:0x16]=b[0x12:0x16]=bytes(4);assert a==b
    assert donor[0x40035cca-B.BASE:0x40035cf6-B.BASE]==native[0x40030e66-B.BASE:0x40030e92-B.BASE]
    # Native stored-kit sound address: kit+0x34 + track*0x48b.
    assert native[0x40030da4-B.BASE:0x40030db4-B.BASE]==bytes.fromhex('223c0000048b4c013800204047f03834')
    # The native root allocates/initializes the same three 1024-byte caches,
    # at +0x44 relative to DT2. Do not write donor root offsets on DN2.
    for at,value in [(0x400413f6,0x6d521),(0x40041474,0x6d921),(0x40041486,0x6dd21)]:
        assert native[at+2-B.BASE:at+6-B.BASE]==B.BE(value)
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    base=int(copy['destination'],16);src=int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        payload.extend(bytes(-len(payload)%4));at=base+len(payload);payload.extend(blob);return at
    query=append(donor[0x4004210a-B.BASE:0x40042140-B.BASE])
    scanner=append(donor[0x40045fde-B.BASE:0x400460b2-B.BASE])
    helper=base+len(payload);helper=(helper+3)&~3;payload.extend(bytes(helper-base-len(payload)))
    asm='''.text
.global pool_raw_sample,pool_live_sample
pool_raw_sample:
 move.l %d0,%a0
 adda.l %d1,%a0
 lea 52(%a0),%a0
 bra.s pool_sound_sample
pool_live_sample:
 move.l 4(%sp),%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 move.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.s pool_sample_absent
 move.l %d0,%a0
pool_sound_sample:
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s pool_sample_absent
 mvs.w 76(%a0),%d0
 rts
pool_sample_absent:
 moveq #-1,%d0
 rts
.balign 4
'''
    payload.extend(B.R.assemble(asm,helper,out,'pool-references'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'pool-references.elf'])
    symbols={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3}
    edits=[]
    def edit(code,origin,at,old,new,why):
        pos=code+at-origin-base;assert payload[pos:pos+len(old)]==old
        assert len(old)==len(new);payload[pos:pos+len(old)]=new
        edits.append(dict(donor=hex(at),runtime=hex(base+pos),before=old.hex(),after=new.hex(),reason=why))
    edit(query,0x4004210a,0x4004211e,B.BE(0x6d8dc),B.BE(0x6d920),'DN2 cache member offset')
    for at,old,new,why in [
        (0x40045ff2,0x6dcdd,0x6dd21,'DN2 kit-reference cache'),
        (0x4004600c,0x401a1f2a,0x4019172e,'Native serialized-kit accessor'),
        (0x40046020,0x450,0x48b,'Native stored sound stride'),
        (0x40046042,0x6dcdc,0x6dd20,'DN2 kit-reference cache'),
        (0x40046062,0x401988a2,0x4018a97a,'Native project singleton'),
        (0x40046068,0x40035cca,0x40030e66,'Native live-track accessor'),
        (0x4004606e,0x40050e1e,symbols['pool_live_sample'],'Machine-aware live sample getter'),
        (0x40046096,0x6dcdc,0x6dd20,'DN2 kit-reference cache')]:
        edit(scanner,0x40045fde,at,B.BE(old),B.BE(new),why)
    edit(scanner,0x40045fde,0x40046028,bytes.fromhex('204006810000007c71701804'),
         b'\x4e\xb9'+B.BE(symbols['pool_raw_sample'])+bytes.fromhex('4e714e714e71'),
         'Skip stock/MIDI sounds; read native sample slot in stored sampler sound')
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),
        pool_references=dict(query=hex(query),kit_scan=hex(scanner),edits=edits,
            symbols={k:hex(v) for k,v in symbols.items() if k.startswith('pool_')},
            cache_offsets=['0x6d521','0x6d921','0x6dd21'],kit_stride='0x5d71',sound_stride='0x48b',
            connected_to_browser=False,remaining=['Other reference-cache producers','Refresh scheduling/project lifecycle']))
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),pool_references=doc['pool_references']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
