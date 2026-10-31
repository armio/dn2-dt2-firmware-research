#!/usr/bin/env python3
"""Persist native DT2 recorder preferences in existing DN2 companion headers."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B


def build(parent,out):
    raw=(parent/'main-os.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
    assert B.T.SHA(raw)==doc['main_sha256'] and 'recorder_persistence' not in doc
    copy=doc['runtime_copy'];base,src=int(copy['destination'],16),int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    def append(data):
        at=base+len(payload);payload.extend(data);payload.extend(bytes(-len(payload)%4));return at
    methods={k:int(v,16) for k,v in doc['project_sample_record']['methods'].items()}
    cache={k:int(v,16) for k,v in doc['project_sample_cache']['methods'].items()}
    active={k:int(v,16) for k,v in doc['project_sample_active']['methods'].items()}
    tramp={};sites=[]
    for name,at in [('prepare',methods['sample_record_prepare']),('reset',cache['sample_cache_reset'])]:
        before=bytes(payload[at-base:at-base+8]);assert before==bytes.fromhex('4feffff448d70c04'),(name,before.hex())
        tramp[name]=append(before+b'\x4e\xf9'+B.BE(at+8));sites.append((name,at,before))
    pub=active['sample_project_publish'];span=bytes(payload[pub-base:active['sample_project_deserialize']-base])
    ready=bytes.fromhex('700125400004');assert span.count(ready)==1
    sites.append(('publish',pub+span.index(ready),ready))
    constants=dict(LIVE_STATE=int(doc['recording_settings']['settings_address'],16),
        ACTIVE_STATE_PTR=int(doc['project_sample_active']['state_pointer'],16),
        ORIGINAL_PREPARE=tramp['prepare'],ORIGINAL_RESET=tramp['reset'])
    donor=B.M.S.DONOR.read_bytes()
    blocks={'native_pack':(0x400dd7ae,0x400dd7e4),'native_unpack':(0x400dd3b0,0x400dd47e)}
    asm=''.join(f'.equ {k},{v:#x}\n' for k,v in constants.items())+(B.T.ROOT/'scripts/asm/dn2_recorder_persistence.S').read_text()
    for name,(lo,hi) in blocks.items():
        code=donor[lo-B.BASE:hi-B.BASE]
        assert all(not(m.startswith(('jsr','jmp'))) for _,_,m,_ in B.M.S.disasm(donor,B.BASE,lo,hi))
        asm+=f'\n.global recorder_persist_{name}\nrecorder_persist_{name}:\n.byte '+','.join(hex(x) for x in code)+'\nrts\n.balign 4\n'
    defaults=[doc['recording_settings']['fields'][k]['default'] for k in ('source','threshold','monitor','length','channels','trigger','trim_start','trim_end','audition_mode')]
    asm+='\n.global recorder_persist_defaults\nrecorder_persist_defaults:\n.long '+','.join(map(str,defaults))+'\n'
    code_at=base+len(payload);append(B.R.assemble(asm,code_at,out,'recorder-persistence'))
    sy={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (recorder_persist_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'recorder-persistence.elf']))}
    patches=[]
    for name,at,before in sites:
        after=(b'\x4e\xb9' if name=='publish' else b'\x4e\xf9')+B.BE(sy['recorder_persist_'+name])
        if len(before)==8:after+=bytes.fromhex('4e71')
        assert payload[at-base:at-base+len(before)]==before
        payload[at-base:at-base+len(before)]=after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    assert base+len(payload)<=min(0x47ad0000,int(doc['runtime_limit'],16))
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    bootstrap=(parent/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(parent/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['recorder_persistence']=dict(parent=str(parent),parent_main_sha256=B.T.SHA(raw),methods={k:hex(v) for k,v in sy.items()},constants={k:hex(v) for k,v in constants.items()},patches=patches,added_span=dict(start=hex(start),end=hex(base+len(payload)),bytes=base+len(payload)-start),
        format=dict(container='existing DT2P version1 header',offset=32,bytes=24,magic='RCR1',packed_offset=4,packed_bytes=15,pad_offset=19,crc32_offset=20,crc_bytes=16),
        donor_blocks={k:dict(start=hex(lo),end=hex(hi),sha256=B.T.SHA(donor[lo-B.BASE:hi-B.BASE])) for k,(lo,hi) in blocks.items()},
        semantics='Exact DT2 project field packing/restoration, including native clamps. Fixed live36-byte settings location remains unchanged.',
        compatibility='Legacy/corrupt optional recorder metadata uses existing defaults. Identity version/layout/CRC and native project payload remain unchanged.',
        lifecycle='Existing active/mirror/cache publish, in-place record prepare, cache reset, snapshot copies and power-off backup carry metadata; no additional storage I/O.')
    doc['recording_settings']['persistence']='Per-project through optional RCR1 metadata in existing DT2P companion header; legacy metadata defaults.'
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((parent/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],recorder_persistence=doc['recorder_persistence']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.parent,a.out)
