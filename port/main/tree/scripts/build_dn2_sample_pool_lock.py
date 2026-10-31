#!/usr/bin/env python3
"""Serialize original DT2 pool mutations with DN2 project restoration."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-host-epoch-20261010'
SHA='a0ceca15b0abff8906f61265045b56abcbd52649ec8e54bf4a035a6efab97a8a'
# Only complete, position-independent entry instructions are replayed.
ENTRIES=[('sample_loader','load',2,'4e56ff2848d73cfc'),
         ('sample_loader','unload',1,'4fefffe048d71c7c'),
         ('sample_loader','clear_slot',1,'2f02223c40218572'),
         ('sample_loader','reindex',0,'4fefffe848d71c1c'),
         ('sample_reset','reset',0,'2f0a2f024282'),
         ('project_sample_load','project_load',3,'4e56ffe448d7041c'),
         ('project_sample_load','project_unload',2,'4e56fff82f0a')]

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    lock=int(doc['sample_restore_lifecycle']['methods']['sample_restore_lock'],16)
    source=f'.text\n.equ POOL_LOCK,{lock:#x}\n';entries=[]
    for component,name,argc,expected in ENTRIES:
        entry=int(doc[component]['methods'][name],16);before=bytes.fromhex(expected)
        assert payload[entry-base:entry-base+len(before)]==before,(name,hex(entry))
        rows=list(B.M.S.disasm(before,entry,entry,entry+len(before)))
        assert all('(pc)' not in row[3] and row[2] not in ('bra','bsr','jmp','jsr') for row in rows)
        wrapper=f'sample_pool_{name}';delegate=wrapper+'_original'
        source+=f'.global {wrapper},{delegate}\n{wrapper}:\n move.l %d2,-(%sp)\n pea POOL_LOCK\n jsr 0x40001608\n addq.l #4,%sp\n'
        source+=''.join(f' move.l {argc*4+4}(%sp),-(%sp)\n' for _ in range(argc))
        source+=f' jsr {delegate}\n'
        if argc:source+=f' lea {argc*4}(%sp),%sp\n'
        source+=' move.l %d0,%d2\n pea POOL_LOCK\n jsr 0x4000172a\n addq.l #4,%sp\n move.l %d2,%d0\n move.l (%sp)+,%d2\n rts\n'
        source+=f'{delegate}:\n .byte '+','.join(hex(b) for b in before)+f'\n jmp {entry+len(before):#x}\n'
        entries.append(dict(component=component,method=name,address=hex(entry),before=before.hex(),arguments=argc,wrapper=wrapper,delegate=delegate))
    source+='.balign 4\n';out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'sample-pool-lock'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-pool-lock.elf']))}
    for e in entries:
        address=int(e['address'],16);size=len(bytes.fromhex(e['before']))
        e['wrapper']=hex(symbols[e['wrapper']]);e['delegate']=hex(symbols[e['delegate']])
        patch=b'\x4e\xf9'+B.BE(int(e['wrapper'],16))+b'\x4e\x71'*((size-6)//2)
        payload[address-base:address-base+size]=patch;e['after']=patch.hex()
    assert base+len(payload)<=0x47ab0000 and len(payload)%4==0
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_pool_lock']=dict(lock=hex(lock),entries=entries,
        coverage='Original load/unload/clear/reindex/reset and whole project identity load/unload share the recursive restoration mutex. Existing callers retain their entry addresses.',
        limits=['Queued browser requests are not yet individually stamped with project generation.',
                'Physical task contention and native caller lock order remain unproven.'])
    doc['sample_host_epoch']['limits']=[
        'Uses existing project generation boundaries; other live project copy paths need review.',
        'Pool mutation entry points are serialized; queued browser requests still need their own generation association.',
        'Native project caller lock ordering and physical scheduler contention remain unproven.']
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),pool_lock=doc['sample_pool_lock']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
