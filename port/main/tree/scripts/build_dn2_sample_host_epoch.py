#!/usr/bin/env python3
"""Bind queued DT2 host jobs to the project generation that requested them."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-host-assignment-20261010'
SHA='d393e23938588057714d19160de2a9be3f7fec290489ffc18010da777b11f336'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());life=doc['sample_host_lifecycle']
    copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    restore=doc['sample_restore_lifecycle']['methods']
    clear=next(s for s in doc['sample_host']['spans'] if int(s['donor'],16)<=0x40127886<int(s['end'],16))
    constants={**life['constants'],'HOST_EPOCH':restore['sample_restore_epoch'],
        'RESTORE_LOCK':restore['sample_restore_lock'],
        'CLEAR_INVOKE':hex(int(clear['runtime'],16)+0x40127886-int(clear['donor'],16))}
    source=''.join(f'.equ {k},{v}\n' for k,v in constants.items())
    for name in ('dn2_sample_host_lifecycle.S','dn2_sample_host_epoch.S'):
        source+=(B.T.ROOT/'scripts/asm'/name).read_text()+'\n'
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'sample-host-epoch'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-host-epoch.elf']))}
    assert base+len(payload)<=0x47ab0000
    patches=[]
    for edit in doc['sample_host']['edits']:
        if edit.get('target')!='0x400f0ab8':continue
        site=int(edit['runtime'],16);old=int(edit['binding'],16);new=symbols['sample_host_enqueue']
        assert payload[site-base:site-base+4]==B.BE(old)
        payload[site-base:site-base+4]=B.BE(new)
        edit['runtime_override']=hex(new)  # Do not rebind the shared donor ABI.
        patches.append(dict(runtime=hex(site),old=hex(old),new=hex(new)))
    assert len(patches)==2
    image=bytearray(raw[:src-B.BASE])+payload
    for site,opcode,name in [(0x4012693e,b'\x4e\xb9','sample_host_route'),(0x4012549a,b'\x4e\xf9','sample_host_native_destroy')]:
        old=int(life['methods'][name],16);new=symbols[name]
        assert image[site-B.BASE:site-B.BASE+6]==opcode+B.BE(old)
        image[site-B.BASE:site-B.BASE+6]=opcode+B.BE(new)
        patches.append(dict(address=hex(site),old=hex(old),new=hex(new)))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    methods={k:hex(v) for k,v in symbols.items() if k.startswith('sample_host_')}
    life.update(methods=methods,constants=constants,state_bytes=0x1a0,entry_bytes=0x1a8,
        request_epoch_offset='0x19c',original_state_bytes=0x19c)
    life['limits'][-1]='Project generation guard is connected; other project-copy paths and physical scheduler contention remain unproven.'
    doc['sample_host_epoch']=dict(methods=methods,patches=patches,constants=constants,
        capture_bytes=32,capture_layout='epoch, project, kind, original state, original std::function<bool()>',
        native_enqueue='0x400f2494',native_job_copy='0x401b40a2',native_job_destroy='0x40188086',
        stale_assignment='Return false; original UI completion reports status3.',
        stale_compaction='Skip mutation; original completed flag reports zero processed.',
        limits=['Uses existing project generation boundaries; other live project copy paths need review.',
                'Other browser/pool mutation entry points still need serialization.',
                'Native project caller lock ordering and physical scheduler contention remain unproven.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=methods),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
