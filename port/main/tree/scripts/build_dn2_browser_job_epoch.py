#!/usr/bin/env python3
"""Bind original queued browser load/unload jobs to their requesting project."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-pool-lock-20261010'
SHA='7939fca90a8ddfba03f2fef68c811d3252a2aa5118f0844b76ae093603e77692'
SITES={0x40028aae:'Load Samples',0x40028d8c:'Unload Samples',0x40028530:'Load continuation barrier (Defragment memory)'}

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    restore=doc['sample_restore_lifecycle']['methods']
    constants={'PROJECT_EPOCH':restore['sample_restore_epoch'],'PROJECT_LOCK':restore['sample_restore_lock']}
    source=''.join(f'.equ {k},{v}\n' for k,v in constants.items())+(B.T.ROOT/'scripts/asm/dn2_browser_job_epoch.S').read_text()
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'browser-job-epoch'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'browser-job-epoch.elf']))}
    patches=[]
    for edit in doc['sample_manager']['edits']:
        donor=int(edit['donor'],16)
        if donor not in SITES:continue
        assert edit['target']=='0x400f0ab8' and edit['kind']=='absolute operand'
        site=int(edit['runtime'],16);old=int(edit['binding'],16)
        new=symbols['browser_barrier_enqueue' if donor==0x40028530 else 'browser_job_enqueue']
        assert payload[site-base:site-base+4]==B.BE(old)
        payload[site-base:site-base+4]=B.BE(new);edit['runtime_override']=hex(new)
        patches.append(dict(donor=hex(donor),runtime=hex(site),old=hex(old),new=hex(new),job=SITES[donor]))
    assert len(patches)==len(SITES)
    assert base+len(payload)<=0x47ab0000 and len(payload)%4==0
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['browser_job_epoch']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith(('browser_job_','browser_barrier_'))},constants=constants,patches=patches,
        capture_bytes=24,capture_layout='request epoch, Project pointer, original16B function (int() worker or void(int) continuation)',
        stale_result='Load/unload: zero processed through unchanged UI completion. Earlier load barrier: skip stale UI continuation, release captures normally.',
        original_jobs={'load':'0x40028f9c','unload':'0x400290ea'},
        original_completions={'load':'0x40029466','unload':'0x4002936c'},
        load_barrier='Original constant-true worker40023EE0, UI completion40027198 invokes captured40028AEC then queues load through400288B0. Guard the completion, not the trivial worker.',
        limits=['Other project-copy paths remain separate integration work.',
                'Physical scheduling and UI lifetimes are not proven by queue fixtures.'])
    doc['sample_pool_lock']['limits'][0]='Queued browser load/unload and preceding load continuation are generation guarded; other project-copy paths remain to review.'
    doc['sample_host_epoch']['limits'][1]='Shared pool mutation boundaries and queued browser load/unload/continuation now share restoration lock/generation.'
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),browser_jobs=doc['browser_job_epoch']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
