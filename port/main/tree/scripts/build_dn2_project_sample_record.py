#!/usr/bin/env python3
"""Add native MmcFs persistence for a DT2-format project identity table.

This component is callable but not yet installed into project lifecycle hooks.
It must not be described as completed automatic project persistence.
"""
from pathlib import Path
import argparse,json
import build_dt2_used_samples as U
B=U.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-used-samples-20261009'
SHA='ab41c77df7178741d32e1f9889f5533ea905ea93879af20cdb701c65d7484233'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    native=B.M.RECIPIENT.read_bytes()
    # Pin the exact slot locator, native project payload size and write bound.
    evidence={}
    for name,start,end in [('slot_lba',0x4012d7c2,0x4012d82e),
        ('read_bytes',0x4012d0b4,0x4012d13e),('write_bytes',0x4012e586,0x4012e662)]:
        stop,rows=B.M.function(native,start);assert stop==end
        evidence[name]=dict(address=hex(start),bytes=end-start,
            sha256=B.T.SHA(native[start-B.BASE:end-B.BASE]))
    assert native[0x4012db28-B.BASE:0x4012db2e-B.BASE]==bytes.fromhex('2f3c00c4b004')
    assert native[0x4012e5da-B.BASE:0x4012e5e0-B.BASE]==bytes.fromhex('223c8b000000')
    assert native[0x4012d80a-B.BASE:0x4012d810-B.BASE]==bytes.fromhex('06820000000b')
    assert 0xc4b004<0xc4b200 and 0xc4b200+0x4200<0x1000000
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    base,src=int(copy['destination'],16),int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);at=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    code=B.R.assemble((B.T.ROOT/'scripts/asm/dn2_project_sample_record.S').read_text(),at,out,'project-sample-record')
    payload.extend(code);assert len(payload)%4==0 and base+len(payload)<=int(doc['runtime_limit'],16)
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'project-sample-record.elf'])
    methods={s[2]:hex(int(s[0],16)) for l in nm.splitlines() if len(s:=l.split())==3 and s[2].startswith('sample_record_')}
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_record']=dict(methods=methods,native_services=evidence,
        slot_bytes=0x1000000,legacy_payload_bytes=0xc4b004,record_offset=0xc4b200,
        record_bytes=0x4200,header_bytes=512,identity_bytes=16384,slot_count=129,
        slot_numbering='Saved slots0..127; working/active slot128 at native LBA0x50000',
        record_format={'magic':'DT2P','version':1,'project_uid_offset':8,
            'identity_bytes_offset':12,'crc32_offset':16,'identities_offset':512},
        status_codes={'0':'success','1':'missing/stale/corrupt record','2':'invalid argument','3':'I/O error'},
        connected_to_lifecycle=False,
        limits=['Caller owns work buffer and only publishes a successful load',
                'Project load/save/copy/clear/import hooks still required',
                'Native Transfer/SysEx payload does not yet carry this extension'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for n in ['fn_new_map.txt','ram_map.txt']:(out/n).write_bytes((INPUT/n).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=methods),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
