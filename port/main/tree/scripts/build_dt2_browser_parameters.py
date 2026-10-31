#!/usr/bin/env python3
"""Bind donor browser parameter operations to native DN2 Machine controls.

The DT2 list uses ONESHOT's sample-ID alias 205 even for bank operations.
Resolve it through the current DN2 Machine's slot map, preserving native
permissions, parameter locks, notification and assignment implementations.
"""
from pathlib import Path
import argparse,json,struct
import build_dt2_sample_list_model as B

INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-list-view-20261009'
SHA='abbd22b51f74fb5070dd74c0e47fec0654c2ad7ace440ac550455ba7bbe90328'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    evidence=[]
    # Complete native setter: only its parameter-range table accessor moves.
    for old,new,end,extra in [(0x4003b570,0x40037326,0x4003b614,{}),
                             (0x4004297c,0x4003f03a,0x400429f8,
                              {0x26:(bytes.fromhex('0017'),bytes.fromhex('001b')),
                               0x56:(bytes.fromhex('fffffff3'),bytes.fromhex('ffffffef'))})]:
        d=bytearray(donor[old-B.BASE:end-B.BASE]);n=bytearray(native[new-B.BASE:new-B.BASE+len(d)])
        changes=[]
        for off,(before,after) in extra.items():
            assert d[off:off+len(before)]==before and n[off:off+len(after)]==after
            d[off:off+len(before)]=n[off:off+len(after)]=bytes(len(before))
            changes.append(dict(offset=hex(off),donor=before.hex(),dn2=after.hex()))
        for at,value,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,old,end)):
            off=at-old;changes.append(dict(offset=hex(off),donor=hex(value),
                                          dn2=hex(struct.unpack_from('>I',n,off)[0])))
            d[off:off+4]=n[off:off+4]=bytes(4)
        assert d==n,(hex(old),[(i,x,y) for i,(x,y) in enumerate(zip(d,n)) if x!=y])
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=len(d),adaptations=changes))
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    base=int(copy['destination'],16);src=int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    source='''.text
.global browser_resolve,browser_sample_id,browser_sample_set,browser_sample_get,browser_sample_lock_get,browser_sample_lock_set
browser_resolve:
 move.l 12(%sp),%d0
 cmpi.l #1,%d0
 beq.s resolve_preset
 cmpi.l #23,%d0
 beq.s resolve_preset
 subi.l #13,%d0
 cmpi.l #3,%d0
 bls.s resolve_master
 moveq #7,%d0
 bra.s resolve_native
resolve_preset:
 moveq #1,%d0
 bra.s resolve_native
resolve_master:
 moveq #17,%d0
resolve_native:
 move.l %d0,12(%sp)
 jmp 0x4003f03a

browser_sample_id:
 move.l 8(%sp),%d0
 cmpi.l #205,%d0
 bne.s sample_invalid
 move.l %a2,-(%sp)
 move.l 8(%sp),%a2
 move.l 16(%a2),%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 move.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.s sample_invalid_pop
 move.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s sample_invalid_pop
 move.l (%a2),%a0
 pea 28
 move.l %a2,-(%sp)
 move.l 80(%a0),%a0
 jsr (%a0)
 addq.l #8,%sp
 move.l (%sp)+,%a2
 rts
sample_invalid_pop:
 move.l (%sp)+,%a2
sample_invalid:
 moveq #0,%d0
 rts
'''
    for name,offset in [('get',40),('lock_get',64),('lock_set',68),('set',None)]:
        source+=f'''
browser_sample_{name}:
 move.l 8(%sp),%d0
 move.l 4(%sp),%a0
 move.l %d0,-(%sp)
 move.l %a0,-(%sp)
 jsr browser_sample_id
 addq.l #8,%sp
 tst.l %d0
 beq.s {name}_invalid
 move.l %d0,8(%sp)
'''
        if offset is None:source+=' jmp 0x40037326\n'
        else:source+=f''' move.l 4(%sp),%a0
 move.l (%a0),%a0
 move.l {offset}(%a0),%a0
 jmp (%a0)
'''
        source+=f'''{name}_invalid:
 moveq #-1,%d0
 rts
'''
    source+=' .balign 4\n'
    payload.extend(B.R.assemble(source,start,out,'browser-parameters'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'browser-parameters.elf'])
    symbols={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3}
    edits=[]
    imports={0x4004297c:symbols['browser_resolve'],0x4003b570:symbols['browser_sample_set']}
    model=doc['pool_model']
    for edit in model['edits']:
        target=int(edit['before'],16)
        if target not in imports:continue
        component=edit['component'];oldstart=int((INPUT/(component+'.asm')).read_text().split()[0],16)
        at=int(model['methods'][component],16)+int(edit['operand'],16)-oldstart
        old=int(edit['after'],16);new=imports[target]
        assert payload[at-base:at-base+4]==B.BE(old)
        payload[at-base:at-base+4]=B.BE(new)
        edits.append(dict(at=hex(at),before=hex(old),after=hex(new),meaning=hex(target)))
    # Bank-change lambda performs three virtual calls with the fixed donor
    # alias. Replace each six-byte load+call pair with a mapped call, leaving
    # surrounding original instructions and every relative offset unchanged.
    front=int(model['methods']['view_front'],16)
    for at,old,name in [(0x4001df54,'206900404e90','lock_get'),
                        (0x4001df6e,'206900284e90','get'),
                        (0x4001dfac,'206900444e90','lock_set')]:
        dest=front+at-0x4001dd9c;off=dest-base
        assert payload[off:off+6]==bytes.fromhex(old)
        new=b'\x4e\xb9'+B.BE(symbols['browser_sample_'+name]);payload[off:off+6]=new
        edits.append(dict(at=hex(dest),before=old,after=new.hex(),meaning='Machine-specific sample '+name))
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    unresolved=[x for x in model['unresolved'] if int(x['donor'],16) not in imports]
    model['unresolved']=unresolved;doc['sample_list_view']['unresolved']=unresolved
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
               runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
               bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),
               browser_parameters=dict(symbols={k:hex(v) for k,v in symbols.items() if k.startswith('browser_')},
                  evidence=evidence,edits=edits,sample_alias=205,sample_slot=28,
                  bank_lambda=hex(front+0x4001df34-0x4001dd9c),
                  remaining=['Pool load/restore','Project in-use query','+Drive picker','Audition/owner callbacks','SYN routing']))
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),unresolved=unresolved),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
