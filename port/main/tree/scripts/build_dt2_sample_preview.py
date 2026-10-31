#!/usr/bin/env python3
"""Port DT2 preview preparation and its original background page worker."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-load-20261009'
SHA='a4cddf0cd2baf845220b3722291472fa1b6e33dd39da43a2af58e5cda0f8c646'
ENTRIES={'init':0x4015394a,'worker':0x40153c58,'prepare':0x40153e36,'metadata_flag':0x40153b1e}


def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_preview';L.LIMIT=0x47a90000
    L.CODE=[('init',0x4015394a,0x40153994),('worker',0x40153c58,0x40153e36),
            ('prepare',0x40153e36,0x40154084),('metadata_flag',0x40153b1e,0x40153b26)]
    L.DATA=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False
    L.EXTRA_DATA={0x402b6618:donor[0x402b6618-B.BASE:0x402b6628-B.BASE]}
    L.EXTRA_STATE=[('task_and_queue',0x405a0ef0,0x405a0f64),
                   ('pending_job',0x405a0f70,0x405a0f9c),
                   ('worker_ring_and_stack',0x405ad0b0,0x405b135c)]
    L.EXTRA_SPANS=[];bindings={}
    for key in ('sample_allocator','sample_loader','pcm_pages','project_sample_load'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    for a in (0x40001314,0x40001834,0x40001928,0x40001896):
        end,_=B.M.function(donor,a)
        assert donor[a-B.BASE:end-B.BASE]==native[a-B.BASE:end-B.BASE]
        bindings[a]=a
    # Native task initialization uses its own ready-priority table; all other
    # instructions, stack frame fields and register offsets are identical.
    task=bytearray(donor[0x400012c8-B.BASE:0x40001314-B.BASE])
    assert task[0x1c:0x20]==B.BE(0x47db3f24)
    task[0x1c:0x20]=B.BE(0x4664ac9c)
    assert task==native[0x400012c8-B.BASE:0x40001314-B.BASE]
    bindings[0x400012c8]=0x400012c8
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.RESERVE_VENEERS=True;L.METHODS=ENTRIES;L.build(out)
    result=json.loads((out/'build-receipt.json').read_text());cfg=result['sample_preview']
    copy=result['runtime_copy'];base,src=int(copy['destination'],16),int(copy['source'],16)
    payload=bytearray((out/'runtime.bin').read_bytes())
    worker=int(cfg['methods']['worker'],16)
    # Slot defaults are already copied at boot. A lazily started preview task
    # must not clear samples loaded earlier into the shared1024-slot tables.
    skip=worker+0x40153c62-0x40153c58;target=worker+0x40153cb6-0x40153c58
    assert payload[skip-base:skip-base+2]==b'\x43\xf9'
    payload[skip-base:skip-base+6]=b'\x4e\xf9'+B.BE(target)
    guard=base+len(payload);payload.extend(bytes(4));at=base+len(payload)
    asm=f'''.text
.global sample_preview_prepare
sample_preview_prepare:
 tst.l {guard:#x}
 bne.s preview_ready
 moveq #1,%d0
 move.l %d0,{guard:#x}
 jsr {int(cfg['methods']['init'],16):#x}
preview_ready:
 jmp {int(cfg['methods']['prepare'],16):#x}
.balign 4
'''
    payload.extend(B.R.assemble(asm,at,out,'preview-entry'));payload.extend(bytes(-len(payload)%4))
    cfg['methods']['prepare_body']=cfg['methods']['prepare'];cfg['methods']['prepare']=hex(at)
    # Future linked callers must enter through lazy task initialization too.
    # Only the exact exported entry is aliased; internal body offsets stay put.
    cfg['spans'].insert(0,dict(name='prepare_entry',donor=hex(ENTRIES['prepare']),
        end=hex(ENTRIES['prepare']+1),runtime=hex(at),kind='entry_alias'))
    sites=[]
    for name in ('prepare','metadata_flag'):
        old=ENTRIES[name];new=int(cfg['methods'][name],16)
        for e in result['sample_manager']['edits']:
            if int(e['target'],16)!=old:continue
            assert e['kind']=='absolute operand'
            offset=int(e['runtime'],16)-base
            assert payload[offset:offset+4]==B.BE(int(e['binding'],16))
            struct.pack_into('>I',payload,offset,new);e['binding']=hex(new)
            sites.append(dict(method=name,site=e['runtime']))
        del result['sample_manager']['unresolved_services'][hex(old)]
    assert base+len(payload)<=L.LIMIT
    image=bytearray((out/'main-os.bin').read_bytes()[:src-B.BASE])+payload;boot=B.BASE+len(image)
    source=(out/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(source,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    result.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    cfg.update(connected_to_picker=True,manager_call_sites=sites,init_guard=hex(guard),
        worker_skips_redundant_slot_reset=dict(site=hex(skip),target=hex(target)),
        limits=['Original2MiB preview area follows400MiB donor pool; physical DN2 ownership remains unproven',
                'Browser audition note routing, waveform services and hardware integration remain pending'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(final_sha256=result['main_sha256'],runtime_bytes=len(payload),remaining_services=result['sample_manager']['unresolved_services']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
