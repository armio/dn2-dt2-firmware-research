#!/usr/bin/env python3
"""Attach sample identities to native alternating working-project backups."""
from pathlib import Path
import argparse,json
import build_dn2_project_sample_active as A
B=A.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-lifecycle-20261009'
SHA='2b986eaf2a37dbf5e96b5fdab2354fe6cd541d4be066105a117655e094379d2f'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        at=base+len(payload);payload.extend(blob);payload.extend(bytes(-len(payload)%4));return at
    state=append(bytes(4));trampolines={}
    prologues={0x400f2004:bytes.fromhex('4feffff048d71c04'),
               0x400f16bc:bytes.fromhex('4fefffec48d7043c'),
               0x400f172e:bytes.fromhex('2f0a206f000c')}
    for entry,original in prologues.items():
        assert raw[entry-B.BASE:entry-B.BASE+len(original)]==original
        trampolines[entry]=append(original+b'\x4e\xf9'+B.BE(entry+len(original)))
    active=doc['project_sample_active'];methods=active['methods']
    symbols={'BACKUP_CHUNK':state,'NATIVE_RESTORE':trampolines[0x400f2004],
             'NATIVE_WRITE':trampolines[0x400f16bc],'NATIVE_CHUNK':trampolines[0x400f172e],
             'ACTIVE_STATE_PTR':int(active['state_pointer'],16),
             'PROJECT_STATE':int(methods['sample_project_state'],16),
             'PROJECT_PUBLISH':int(methods['sample_project_publish'],16),
             'RECORD_VALIDATE':int(doc['project_sample_record']['methods']['sample_record_validate'],16),
             'NATIVE_DESERIALIZE':int(active['trampolines']['0x400e1782'],16),
             'NATIVE_SERIALIZE':int(active['trampolines']['0x400e1494'],16),
             'ACTIVE_DESERIALIZE':int(methods['sample_project_deserialize'],16),
             'ACTIVE_SERIALIZE':int(methods['sample_project_serialize'],16)}
    at=base+len(payload);defines='\n'.join(f'.equ {k},{v:#x}' for k,v in symbols.items())+'\n'
    append(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_project_sample_backup.S').read_text(),at,out,'project-sample-backup'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'project-sample-backup.elf'])
    methods={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3 and s[2].startswith('sample_backup_')}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    hooks={0x400f2004:'sample_backup_restore',0x400f16bc:'sample_backup_write',
           0x400f172e:'sample_backup_chunk',0x400e1782:'sample_backup_deserialize',0x400e1494:'sample_backup_serialize'}
    for entry,key in hooks.items():
        size=len(prologues.get(entry,b'00000000'));before=raw[entry-B.BASE:entry-B.BASE+size]
        after=b'\x4e\xf9'+B.BE(methods[key])+b'\x4e\x71'*((size-6)//2)
        image[entry-B.BASE:entry-B.BASE+size]=after
        patches.append(dict(address=hex(entry),before=before.hex(),after=after.hex(),method=key))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_backup']=dict(methods={k:hex(v) for k,v in methods.items()},chunk_pointer=hex(state),
        chunk_bytes=32768,backup_sectors=['0x40000','0x48000'],record_offset='0xc4b200',
        legacy_length='0xc4b114',physical_poweroff_length='0xc50000',
        final_block_source='0x4121585c',final_block_record_offset='0x3200',
        patches=patches,trampolines={hex(k):hex(v) for k,v in trampolines.items()},
        limits=['Power-off hardware timing and DMA/PIO edges still require device validation',
                'Native backup writers return void and ignore low-level failures; recovery UX unfinished',
                'NOR fallback migration does not yet carry the extension',
                'PCM restoration and donor load/unload remain unconnected'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['project_sample_backup']['methods']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);build(p.parse_args().output)
