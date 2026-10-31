#!/usr/bin/env python3
"""Connect the active Project and original DT2 identity getter to companions."""
from pathlib import Path
import argparse,json,struct
import build_dn2_project_sample_cache as C
B=C.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-cache-20261009'
SHA='452f95c607be6e2805b878b76c15257d44ccb3f818752808cfa975a59635066e'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        at=base+len(payload);payload.extend(blob);payload.extend(bytes(-len(payload)%4));return at
    state=append(bytes(4));empty=append(b'\xff'*16);trampolines={}
    prologues={0x400e1494:bytes.fromhex('4fefffd448d77cfc'),0x400e1782:bytes.fromhex('4fefffdc48d77c3c')}
    for entry,original in prologues.items():
        assert raw[entry-B.BASE:entry-B.BASE+len(original)]==original
        trampolines[entry]=append(original+b'\x4e\xf9'+B.BE(entry+len(original)))
    cm=doc['project_sample_cache']['methods'];rm=doc['project_sample_record']['methods']
    symbols={'PROJECT_STATE':state,'NATIVE_SERIALIZE':trampolines[0x400e1494],
        'NATIVE_DESERIALIZE':trampolines[0x400e1782],
        'CACHE_ENTRY':int(cm['sample_cache_entry'],16),'CACHE_BLANK':int(cm['sample_cache_blank'],16),
        'RECORD_PREPARE':int(rm['sample_record_prepare'],16)}
    at=base+len(payload)
    defines='\n'.join(f'.equ {k},{v:#x}' for k,v in symbols.items())+'\n'
    append(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_project_sample_active.S').read_text(),at,out,'project-sample-active'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'project-sample-active.elf'])
    methods={s[2]:int(s[0],16) for l in nm.splitlines() if len(s:=l.split())==3 and s[2].startswith('sample_project_')}
    donor=B.M.S.DONOR.read_bytes();entry=0x4004b710;end,rows=B.M.function(donor,entry)
    assert end==0x4004b794
    getter=bytearray(donor[entry-B.BASE:end-B.BASE]);getter_at=base+len(payload)
    bindings={0x401360ac:0x40134490,0x402aafc8:empty}
    for operand,target,_,_ in B.M.operands(rows):struct.pack_into('>I',getter,operand-entry,bindings[target])
    original=bytes.fromhex('20522f0a206800284e90')
    replacement=bytes.fromhex('2f0a4eb9')+B.BE(methods['sample_project_settings_raw'])+bytes.fromhex('4e71')
    assert getter.count(original)==3
    getter=getter.replace(original,replacement);append(getter)
    methods['sample_project_identity_get']=getter_at
    sites=[]
    for edit in doc['sample_manager']['edits']:
        if edit.get('target')!=hex(entry):continue
        assert edit['kind']=='absolute operand'
        address=int(edit['runtime'],16);old=int(edit['binding'],16)
        assert payload[address-base:address-base+4]==B.BE(old)
        struct.pack_into('>I',payload,address-base,getter_at);edit['binding']=hex(getter_at);sites.append(hex(address))
    assert len(sites)==4
    del doc['sample_manager']['unresolved_services'][hex(entry)]
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    hooks={0x400e1494:'sample_project_serialize',0x400e1782:'sample_project_deserialize',0x4003ea0e:'sample_project_blank'}
    for entry,key in hooks.items():
        size=8;before=raw[entry-B.BASE:entry-B.BASE+size]
        if entry==0x4003ea0e:assert before==b'\x4e\xf9'+B.BE(int(cm['sample_cache_blank'],16))+b'\x4e\x71'
        after=b'\x4e\xf9'+B.BE(methods[key])+b'\x4e\x71'
        image[entry-B.BASE:entry-B.BASE+size]=after
        patches.append(dict(address=hex(entry),before=before.hex(),after=after.hex(),method=key))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_active']=dict(methods={k:hex(v) for k,v in methods.items()},state_pointer=hex(state),
        heap_bytes=0x8420,entry_bytes=0x4210,active_offset=0,mirror_offset=0x4210,
        patches=patches,trampolines={hex(k):hex(v) for k,v in trampolines.items()},getter_sites=sites,
        donor_getter=['0x4004b710','0x4004b794'],
        connected=['Active raw Project deserialize from known native cache or active mirror',
                   'Active raw serialize to native cache or separate active mirror',
                   'Original DT2 identity getter, current ProjectSettings only'],
        limits=['Temporary serialized/raw copies and Transfer do not carry companion associations yet',
                'Unknown legacy deserialize sources initialize an empty identity table',
                'Raw clear, constructor and all startup routes still require lifecycle audit',
                'No cross-payload transaction, PCM restoration or hardware validation'])
    for n,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/n).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for n in ('fn_new_map.txt','ram_map.txt'):(out/n).write_bytes((INPUT/n).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['project_sample_active']['methods']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
