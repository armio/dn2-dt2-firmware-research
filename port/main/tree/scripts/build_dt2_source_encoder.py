#!/usr/bin/env python3
"""Port original Source encoder/browser routing with native parameter IDs."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-browser-20261009'
SHA='441a5a63dc9b53ba177f53c3d4435edd83c544beade4f8a9b149a66fb21c6960'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_encoder';L.LIMIT=0x47aa0000
    L.CODE=[('source_encoder',0x400184ea,0x400187c4),('source_sample_title',0x40017b50,0x40017c18)]
    L.DATA=[('source_machine_labels',0x4020eb6c,0x4020ebc0)];L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds[0x4006cb14]=0x40067470
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    assert donor[0x40000e82-B.BASE:0x40000e9e-B.BASE]==native[0x40000e82-B.BASE:0x40000e9e-B.BASE]
    binds[0x40000e82]=0x40000e82
    lo,entry,size=0x4006cb14,0x40067470,1028
    _,rows=B.M.function(donor,lo)
    x=bytearray(donor[lo-B.BASE:lo-B.BASE+size]);y=bytearray(native[entry-B.BASE:entry-B.BASE+size]);pairs=[]
    for at,target,_,_ in B.M.operands(rows):
        off=at-lo;pairs.append(dict(donor=hex(target),native=hex(struct.unpack_from('>I',y,off)[0])))
        x[off:off+4]=y[off:off+4]=bytes(4)
    current=(INPUT/'main-os.bin').read_bytes()
    for at in (0x4006cb7a,0x4006cd72):
        off=at-lo;assert x[off:off+4]==B.BE(274) and y[off:off+4]==B.BE(320)
        x[off:off+4]=y[off:off+4]=bytes(4)
        assert current[entry+off-B.BASE:entry+off-B.BASE+4]==B.BE(367)
    assert x==y
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'encoder':0x400184ea,'sample_title':0x40017b50};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy'];base=int(c['destination'],16);src=int(c['source'],16)
    raw=bytearray((out/'main-os.bin').read_bytes()[:src-B.BASE]);payload=bytearray((out/'runtime.bin').read_bytes())
    # The legacy one-slot ONESHOT formatter takes its output pointer from
    # SP+28 after four pushes (arg3), instead of SP+24 (arg2). Native value
    # display then writes into the caller's code. Restore the original DT2
    # raw-slot formatter's verified native twin, also used by other samplers.
    from build_dt2_sampler_controls import cfplan,oneshot_cf
    check=cfplan.CfPlan(oneshot_cf.SPEC,donor,native)
    twin=next(t for t in oneshot_cf.TWINS if t.donor==0x400e1728)
    cfplan._check_twin(check,twin);assert check.ok,check.refusals
    assert base==0x47a58000
    fmt_off=4*60+52
    assert payload[fmt_off:fmt_off+4]==B.BE(0x47a52968)
    assert raw[0x401f80b8-B.BASE:0x401f80bc-B.BASE]==B.BE(0x47a52968)
    payload[fmt_off:fmt_off+4]=B.BE(0x400e31d0)
    raw[0x401f80b8-B.BASE:0x401f80bc-B.BASE]=B.BE(0x400e31d0)
    # DT2 constructor40111644 seeds two {-1,-1,-1} step triples, then
    # callback400C1618 configures SAMP: raw integers, normal1/4/1,
    # pressed1/4/4. All six SAMP IDs use the native ID4 companion row.
    assert donor[0x4021c92c-B.BASE:0x4021c938-B.BASE]==b'\xff'*12
    config_callback=donor[0x400c1618-B.BASE:0x400c1648-B.BASE]
    assert config_callback==bytes.fromhex('4200206f000842101140000111400002700121400004103c000421400008103c00012140000c103c0004214000184e75')
    def at(old):
        for s in doc['source_encoder']['spans']:
            lo,hi=int(s['donor'],16),int(s['end'],16)
            if lo<=old<hi:return int(s['runtime'],16)+old-lo
        raise ValueError(hex(old))
    patches=[]
    for site,old in zip((0x40018548,0x40018552,0x4001855c,0x40018566,0x40018570,0x4001857a),(205,241,214,232,223,251)):
        new=doc['source_parameters']['records'][str(old)]['native'];off=at(site)-base
        assert payload[off:off+4]==B.BE(old);payload[off:off+4]=B.BE(new)
        patches.append(dict(donor=hex(site),runtime=hex(at(site)),old=old,new=new))
    off=at(0x40017b8a)-base;target=int(doc['source_parameters']['methods']['source_parameter_get'],16)
    assert payload[off:off+4]==bytes.fromhex('20680028')
    payload[off:off+4]=struct.pack('>Hh',0x41fa,target-(base+off+2))
    # Preserve DT2's exact START/LEN/LOOP refresh predicate after converting
    # the descriptor's native ID back to its donor ID. This tail is out of
    # line because ONESHOT's native IDs are not contiguous.
    tail=base+len(payload)
    asm=f'''.text
.global source_encoder_refresh
source_encoder_refresh:
 move.l %d2,-(%sp)
 jsr {doc['source_parameters']['methods']['source_donor_parameter_id']}
 addq.l #4,%sp
 move.l %d0,%d1
 subi.l #206,%d0
 cmpi.l #2,%d0
 bls.s refresh
 move.l %d1,%d0
 subi.l #235,%d0
 cmpi.l #1,%d0
 bls.s refresh
 subi.l #224,%d1
 cmpi.l #1,%d1
 bls.s refresh
 jmp {hex(at(0x40018710))}
refresh:
 jmp {hex(at(0x40018708))}
.balign 4
'''
    payload.extend(B.R.assemble(asm,tail,out,'source-encoder-refresh'))
    start,end=at(0x400186e2),at(0x40018708)
    assert end-start==38
    payload[start-base:end-base]=b'\x4e\xf9'+B.BE(tail)+b'\x4e\x71'*16
    getter_off=0x400c2418-B.BASE
    assert raw[getter_off:getter_off+2]==b'\x4e\xf9'
    old_getter=struct.unpack_from('>I',raw,getter_off+2)[0]
    companion=base+len(payload)
    asm=f'''.text
.global source_sampler_companion
source_sampler_companion:
 move.l 4(%sp),-(%sp)
 jsr {hex(old_getter)}
 addq.l #4,%sp
 cmpi.l #0x4243336c,%d0
 bne.s done
 movea.l %d0,%a0
 lea sample_encoder_config,%a1
 move.l %a1,16(%a0)
done:
 rts
.balign 4
sample_encoder_config:
 .long 0,1,4,1,1,4,4
'''
    payload.extend(B.R.assemble(asm,companion,out,'source-sample-companion'))
    raw[getter_off:getter_off+6]=b'\x4e\xf9'+B.BE(companion)
    assert base+len(payload)<=L.LIMIT
    raw.extend(payload);boot=B.BASE+len(raw)
    bootstrap=(out/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    raw.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));raw[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False,
        runtime_copy={**c,'bytes':len(payload)},bytes=len(raw),bootstrap=hex(boot),bootstrap_bytes=len(raw)-(boot-B.BASE))
    doc['source_encoder'].update(sample_id_patches=patches,title_get_adapter=hex(target),refresh_tail=hex(tail),
        oneshot_formatter=dict(old='0x47a52968',native='0x400e31d0',donor='0x400e1728',
                               table_sites=['0x47a58124','0x401f80b8'],reason='Legacy formatter reads output pointer from wrong argument'),
        sample_encoder_config=dict(companion_hook=hex(companion),previous_getter=hex(old_getter),
            native_companion='0x4243336c',donor_callback='0x400c1618',config=[0,1,4,1,1,4,4]),
        native_parent=dict(donor='0x4006cb14',native='0x40067470',bytes=size,operands=pairs,parameter_max=[274,320,367]),
        limits=['Callable Source encoder; actual Source constructor/vtable/controller integration pending.',
                'Physical knob input and hardware audio untested.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],methods=doc['source_encoder']['methods'])))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
