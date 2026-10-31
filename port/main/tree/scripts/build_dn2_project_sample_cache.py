#!/usr/bin/env python3
"""Pair native project cache entries with persistent DT2 identity records."""
from pathlib import Path
import argparse,json,struct
import build_dn2_project_sample_record as R
B=R.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-record-20261009'
SHA='29c23874be6302bb9043362cf3ae1ca6db247ce5d70859ae4cff74a73f61d263'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        at=base+len(payload);payload.extend(blob);payload.extend(bytes(-len(payload)%4));return at
    state=append(bytes(4));trampolines={}
    prologues={0x400f6618:bytes.fromhex('4feffff02f0a'),0x4003ea0e:bytes.fromhex('4fefffe848d71c1c'),0x400f672c:bytes.fromhex('4feffff048d70c0c')}
    for entry,original in prologues.items():
        assert raw[entry-B.BASE:entry-B.BASE+len(original)]==original,(hex(entry),raw[entry-B.BASE:entry-B.BASE+8].hex())
        trampolines[entry]=append(original+b'\x4e\xf9'+B.BE(entry+len(original)))
    methods=doc['project_sample_record']['methods']
    symbols={'CACHE_STATE':state,'NATIVE_ACQUIRE':trampolines[0x400f6618],
        'NATIVE_BLANK':trampolines[0x4003ea0e],'NATIVE_LOAD':trampolines[0x400f672c],
        'RECORD_PREPARE':int(methods['sample_record_prepare'],16),
        'RECORD_READ':int(methods['sample_record_read'],16),
        'RECORD_WRITE':int(methods['sample_record_write'],16)}
    defines='\n'.join(f'.equ {k},{v:#x}' for k,v in symbols.items())+'\n'
    at=base+len(payload)
    append(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_project_sample_cache.S').read_text(),at,out,'project-sample-cache'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'project-sample-cache.elf'])
    functions={s[2]:int(s[0],16) for l in nm.splitlines() if len(s:=l.split())==3 and s[2].startswith('sample_cache_')}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    for entry,key in [(0x400f6618,'sample_cache_acquire'),(0x4003ea0e,'sample_cache_blank'),(0x400f672c,'sample_cache_load')]:
        before=prologues[entry];after=b'\x4e\xf9'+B.BE(functions[key])+b'\x4e\x71'*((len(before)-6)//2)
        image[entry-B.BASE:entry-B.BASE+len(before)]=after
        patches.append(dict(address=hex(entry),before=before.hex(),after=after.hex(),method=key))
    for at,old,key in [(0x400f67a4,0x4012daa8,'sample_cache_read'),(0x400f65e2,0x4012ee34,'sample_cache_write')]:
        assert image[at-B.BASE:at-B.BASE+4]==B.BE(old)
        image[at-B.BASE:at-B.BASE+4]=B.BE(functions[key])
        patches.append(dict(address=hex(at),before=hex(old),after=hex(functions[key]),method=key))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_cache']=dict(methods={k:hex(v) for k,v in functions.items()},state_pointer=hex(state),
        heap_bytes=0x8420,entry_bytes=0x4210,record_offset=16,identities_offset=528,
        patches=patches,trampolines={hex(k):hex(v) for k,v in trampolines.items()},
        connected=['Native cache read and commit','Native reuse/eviction with failed-commit retention','Native blank-project initializer'],
        limits=['Current Project live pool and cache/raw copy association still unbound',
                'Cache commit reports extension errors, but no cross-payload transaction yet',
                'No Transfer/SysEx extension, hardware validation or flash-ready claim'])
    for n,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/n).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for n in ('fn_new_map.txt','ram_map.txt'):(out/n).write_bytes((INPUT/n).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['project_sample_cache']['methods']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
