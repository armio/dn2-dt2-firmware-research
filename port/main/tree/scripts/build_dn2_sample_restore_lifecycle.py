#!/usr/bin/env python3
"""Connect original DT2 restoration to DN2 boot and active project replacement."""
from pathlib import Path
import argparse,json,re
import build_dn2_sample_fs_startup as P
B=P.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-restore-worker-20261009'
SHA='31e9644b457eb5a38c149b1c52acfeff0ee8712676be9bf3bee148fbf0aef3cf'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray((INPUT/'runtime.bin').read_bytes());out.mkdir(parents=True,exist_ok=False)
    worker=doc['sample_restore_worker'];methods=worker['methods'];fs=doc['sample_fs_startup']
    job=int(methods['job'],16);before=bytes(payload[job-base:job-base+8])
    assert before==bytes.fromhex('48780001206f0008')
    trampoline=base+len(payload);payload.extend(before+b'\x4e\xf9'+B.BE(job+8));payload.extend(bytes(-len(payload)%4))
    delegates={}
    for name,address in (('ORIGINAL_DESERIALIZE',0x400e1782),('ORIGINAL_CLEAR',0x400e7940)):
        assert raw[address-B.BASE:address-B.BASE+2]==b'\x4e\xf9'
        delegates[name]=int.from_bytes(raw[address-B.BASE+2:address-B.BASE+6],'big')
    symbols={**delegates,'ORIGINAL_JOB':trampoline,'PROXY':int(worker['proxy'],16),
        'FS_STARTUP':int(fs['methods']['sample_fs_startup'],16),'FS_STATUS':int(fs['methods']['sample_fs_status'],16),
        'SETTINGS_RAW':int(doc['project_sample_active']['methods']['sample_project_settings_raw'],16),
        'RESTORE':int(methods['restore'],16),'PROXY_INIT':int(methods['proxy_init'],16),
        'PROXY_RAW':int(methods['proxy_raw'],16)}
    defines=''.join(f'.equ {k},{v:#x}\n' for k,v in symbols.items())
    at=base+len(payload)
    payload.extend(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_sample_restore_lifecycle.S').read_text(),at,out,'sample-restore-lifecycle'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-restore-lifecycle.elf'])
    emitted={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (sample_restore_\w+)$',nm)}
    patches=[]
    newjob=b'\x4e\xf9'+B.BE(emitted['sample_restore_job'])+b'\x4e\x71'
    payload[job-base:job-base+8]=newjob
    patches.append(dict(runtime=hex(job),before=before.hex(),after=newjob.hex()))
    assert base+len(payload)<=int(doc['runtime_limit'],16) and len(payload)%4==0
    image=bytearray(raw[:src-B.BASE])+payload
    def patch(address,old,new,offset=None):
        off=address-B.BASE if offset is None else offset
        assert image[off:off+len(old)]==old and len(new)==len(old),(hex(address),image[off:off+len(old)].hex())
        image[off:off+len(old)]=new
        patches.append(dict(address=hex(address),before=old.hex(),after=new.hex()))
    for address,name,delegate in ((0x400e1782,'sample_restore_deserialize','ORIGINAL_DESERIALIZE'),
                                 (0x400e7940,'sample_restore_clear','ORIGINAL_CLEAR')):
        patch(address,b'\x4e\xf9'+B.BE(delegates[delegate]),b'\x4e\xf9'+B.BE(emitted[name]))
    entry=int(fs['entry'],16)
    c=next(c for c in doc['copies'] if int(c['destination'],16)<=entry<int(c['destination'],16)+c['bytes'])
    offset=int(c['source'],16)-B.BASE+entry-int(c['destination'],16)
    patch(entry,b'\x4e\xf9'+B.BE(symbols['FS_STARTUP']),b'\x4e\xf9'+B.BE(emitted['sample_restore_poll']),offset)
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_restore_lifecycle']=dict(methods={k:hex(v) for k,v in emitted.items()},
        delegates={k:hex(v) for k,v in delegates.items()},job_trampoline=hex(trampoline),patches=patches,
        automatic_restore=True,queued_epoch_guard=True,mutex='Native recursive 40001608/4000172A; UI try-lock4000169E',
        limits=['Native project callers may hold locks before these boundaries; cross-task lock ordering still needs validation.',
                'RTOS contention and physical startup are not proven by single-thread offline checks.'])
    doc['sample_restore_worker']['connected_to_lifecycle']=True
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),lifecycle=doc['sample_restore_lifecycle']),indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);build(parser.parse_args().out)
