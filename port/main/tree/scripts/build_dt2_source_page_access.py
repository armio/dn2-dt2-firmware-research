#!/usr/bin/env python3
"""Adapt DT2 Source page control reads to DN2 page context and parameter IDs."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_source_parameters as S
B=S.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-parameters-20261009'
SHA='f4d62e2a73c4ccdb3071df66acb05caa50e4c671fca0b471d5031e2a811eb248'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    native=B.M.RECIPIENT.read_bytes();donor=B.M.S.DONOR.read_bytes();proof=[]
    for name,lo,hi,new in [('page_read',0x4006aa32,0x4006ab50,0x4006538e),('page_sound',0x4006a856,0x4006a944,0x400651b2)]:
        x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo])
        rows=list(B.M.S.disasm(donor,B.BASE,lo,hi));nr=list(B.M.S.disasm(native,B.BASE,new,new+hi-lo));pairs=[]
        assert len(rows)==len(nr)
        # DN2's preset pool follows its larger project header. This is an
        # explicit object-layout difference, not a function address binding.
        offsets=[a[0]-lo+2 for a in rows if a[2]=='move.l' and a[3]=='#$4f314, d1']
        assert len(offsets)==1
        off=offsets[0];assert x[off:off+4]==B.BE(0x4f314) and y[off:off+4]==B.BE(0x4f358)
        x[off:off+4]=y[off:off+4]=bytes(4)
        for operand,target,_,_ in B.M.operands(rows):
            off=operand-lo;value=struct.unpack_from('>I',y,off)[0]
            pairs.append(dict(donor=hex(target),native=hex(value),offset=hex(off)))
            x[off:off+4]=y[off:off+4]=bytes(4)
        for a,b in zip(rows,nr):
            old=re.search(r'\$([0-9a-f]{8})\(pc\)',a[3])
            if old:
                new_pc=re.search(r'\$([0-9a-f]{8})\(pc\)',b[3]);assert new_pc
                off=a[0]-lo+2;x[off:off+2]=y[off:off+2]=bytes(2)
                pairs.append(dict(donor='0x'+old[1],native='0x'+new_pc[1],offset=hex(off),relative=True))
        assert x==y,name
        proof.append(dict(role=name,donor=hex(lo),native=hex(new),bytes=hi-lo,project_pool_offsets=['0x4f314','0x4f358'],operands=pairs))
    imports=doc['source_parameters']['methods']
    source=f'''.text
.global source_page_machine,source_page_parameter_id,source_page_read
source_page_machine:
 move.l 4(%sp),-(%sp)
 jsr 0x4005a42e
 move.l %d0,(%sp)
 jsr {imports['source_donor_machine']}
 addq.l #4,%sp
 rts
source_page_parameter_id:
 move.l 8(%sp),%d0
 subi.l #200,%d0
 cmpi.l #54,%d0
 bhi.s page_id_invalid
 move.l %d2,-(%sp)
 lea {imports['source_parameter_slots']},%a0
 mvz.b (%a0,%d0.l),%d2
 move.l 8(%sp),-(%sp)
 jsr 0x4005a42e
 addq.l #4,%sp
 move.l %d0,%d1
 subi.l #5,%d1
 cmpi.l #5,%d1
 bhi.s page_id_invalid_pop
 clr.l -(%sp)
 move.l %d0,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x400dc02a
 lea 12(%sp),%sp
 move.l (%sp)+,%d2
 rts
page_id_invalid_pop:
 move.l (%sp)+,%d2
page_id_invalid:
 moveq #0,%d0
 rts
source_page_read:
 move.l 8(%sp),-(%sp)
 move.l 8(%sp),-(%sp)
 jsr source_page_parameter_id
 addq.l #8,%sp
 tst.l %d0
 beq.s page_read_invalid
 move.l %d0,8(%sp)
 jmp 0x4006538e
page_read_invalid:
 movea.l 12(%sp),%a0
 clr.b (%a0)
 moveq #-1,%d0
 rts
.balign 4
'''
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    out.mkdir(parents=True,exist_ok=False);payload.extend(B.R.assemble(source,start,out,'source-page-access'))
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'source-page-access.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},
        runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    methods={k:hex(v) for k,v in symbols.items() if k.startswith('source_page_')}
    doc['source_page_access']=dict(methods=methods,bytes=len(payload)-copy['bytes'],spans=[],edits=[],native_body_evidence=proof,
        source_bindings={'0x4005f6bc':methods['source_page_machine'],'0x4006aa32':methods['source_page_read']},
        limits=['Native page context is used; complete SourcePageView lifecycle/call-site integration is pending.',
                'Native sound getter must not be used as a substitute for DT2 slice metadata layout.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=methods),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
