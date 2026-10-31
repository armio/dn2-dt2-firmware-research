#!/usr/bin/env python3
"""Relocate the original DT2 SamplerView recording, trim and save workflow."""
from pathlib import Path
import argparse
import json
import struct
import re
import tempfile
import build_dt2_directory_model as L
import build_dt2_recorder_fonts as F
import build_dt2_recorder_tempo as T
B = L.B

# These imports are supplied by the native DN2 control/transport adapter.
CONTROL_IMPORTS = (0x4002f47a,0x4004cc42,0x4004cc72,0x4004cca2,0x4004ccd2,
    0x4004cd02,0x4004cd80,0x4004cdd6,0x4004ce36,0x4004ceae,
    0x4004cf26,0x4004cf7c,0x4004cfd6,0x4004d030,0x4004d08a,
    0x4004d0d2,0x4004d9d6,0x4004d9e0,0x400cd6ce,0x400cd6e2,
    0x400cd6ea,0x400cd6f2,0x400cd6fa,0x400cd702,0x400cd70a)

def build(folder, out, imports=None, allow_unbound=False):
    doc=json.loads((folder/'build-receipt.json').read_text())
    donor=B.M.S.DONOR.read_bytes()
    binds={};spans=[]
    # Later adaptations override earlier donor imports. Relocated spans retain
    # their final addresses and any in-place fixes already in the baseline.
    for component in doc.values():
        if not isinstance(component,dict):continue
        spans[0:0]=component.get('spans',[])
        for edit in component.get('edits',[]):
            if 'target' in edit and 'binding' in edit:
                binds[int(edit['target'],16)]=int(edit['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds.update({0x40050daa:int(doc['sample_services']['methods']['sound_assign_sample'],16),
        0x4004b502:int(doc['project_sample_load']['methods']['project_load'],16),
        0x4004b794:int(doc['project_sample_load']['methods']['project_unload'],16)})
    binds.update({0x46030000:int(doc['oneshot_shared_defaults']['methods']['oneshot_ui_assign'],16),
                  0x46030004:0x4004b7f2})
    native=B.M.RECIPIENT.read_bytes()
    # These are raw font descriptors, not strings; the generic data linker
    # would otherwise truncate their leading zero to an empty string.
    font_binds,font_proof=F.font_bindings(donor,native)
    binds.update(font_binds)
    tempo_binds,tempo_proof=T.tempo_binding(donor,native)
    binds.update(tempo_binds)
    # Complete shared font initialization fragment; resolve actual native
    # number-font object rather than substituting another font.
    lo,hi=0x401d0c50,0x401d0c80
    rows=list(B.M.S.disasm(donor,B.BASE,lo,hi));refs=list(B.M.operands(rows))
    mask=bytearray(b'\1'*(hi-lo))
    for at,_,_,_ in refs:mask[at-lo:at-lo+4]=bytes(4)
    pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(donor[lo-B.BASE:hi-B.BASE],mask))
    hits=[m.start()+B.BASE for m in re.finditer(pattern,native,re.S) if not m.start()%2]
    callback_end,_=B.M.function(donor,0x401112f4)
    size=callback_end-0x401112f4
    hits=[h for h in hits if donor[0x401112f4-B.BASE:callback_end-B.BASE]==native[struct.unpack_from('>I',native,h-B.BASE+16)[0]-B.BASE:struct.unpack_from('>I',native,h-B.BASE+16)[0]-B.BASE+size]]
    assert len(hits)==1,hits
    for at,target,_,_ in refs:
        binds[target]=struct.unpack_from('>I',native,hits[0]-B.BASE+at-lo)[0]
    binds.update(dict(zip((0x400cd6ce,0x400cd6e2,0x400cd6ea,0x400cd6f2,
        0x400cd6fa,0x400cd702,0x400cd70a),
        (0x400cfa40,0x400cfa54,0x400cfa5c,0x400cfa64,0x400cfa6c,0x400cfa74,0x400cfa7c))))
    binds.update({0x4004d9d6:0x40049164,0x4004d9e0:0x4004916e})
    assert donor[0x401f0a70-B.BASE:0x401f0a7c-B.BASE]==native[0x401d9610-B.BASE:0x401d961c-B.BASE]
    old=bytearray(donor[0x4019eb14-B.BASE:0x4019eb2a-B.BASE])
    new=bytearray(native[0x4018ef48-B.BASE:0x4018ef5e-B.BASE])
    for offset in (6,16):old[offset:offset+4]=new[offset:offset+4]=bytes(4)
    assert old==new
    binds.update({0x40966a9c:0x4059cd74,0x40966aa0:0x4059cd78,0x40966aa4:0x4059cd7c})
    supplied={} if imports is None else json.loads(imports.read_text())
    binds.update({int(k,16):int(v,16) for k,v in supplied.items()})
    unbound=[x for x in CONTROL_IMPORTS if x not in binds and not any(int(s['donor'],16)<=x<int(s['end'],16) for s in spans)]
    if unbound and not allow_unbound:raise ValueError(f'Recorder control imports absent: {[hex(x) for x in unbound]}')
    binds.update({x:x for x in unbound})
    L.INPUT=folder;L.SHA=doc['main_sha256'];L.COMPONENT='recorder_ui';L.LIMIT=0x47ad0000
    L.DIRECTORY_AUX=False;L.INFER_NATIVE_LIBRARY_OPERANDS=True;L.RESERVE_VENEERS=True
    L.EXTRA_BINDINGS=binds;L.EXTRA_SPANS=spans;L.EXTRA_DATA={};L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[]
    assets=((0x44f35090,11,2,0x402d20ac,0x402d2080,1),
        (0x44f35ec4,17,9,0x402e3224,0x402e31e0,1),
        (0x44f36d08,4,5,0x403075c8,0x403075b8,1),
        (0x44f36c14,4,5,0x403052dc,0x403052cc,1),
        (0x44f36bf8,7,5,0x403052b0,0x40305294,1),
        (0x44f367f4,12,9,0x402f7a40,0x402f7a10,1),
        (0x44f36bb4,12,9,0x4030022c,0x403001fc,1),
        (0x44f34010,17,9,0x402b6bf4,0x402b6bb0,2))
    for global_at,height,width,pixels,mask,count in assets:
        size=height*((width+31)//32)*4
        L.EXTRA_DATA[mask]=donor[mask-B.BASE:mask-B.BASE+size]
        objects=[]
        for i in range(count):
            plane=pixels+i*size
            L.EXTRA_DATA[plane]=donor[plane-B.BASE:plane-B.BASE+size]
            objects.append(struct.pack('>7I',0x4021cb40,height,width,(width+31)//32,plane,mask,0))
        if count==1:
            L.EXTRA_TYPED_DATA.append((f'recorder_bitmap_{global_at:x}',global_at,b''.join(objects)))
        else:
            label=0x46010000
            L.EXTRA_TYPED_DATA.append(('recorder_audition_frames',label,b''.join(objects)+bytes(4)))
            L.EXTRA_TYPED_DATA.append(('recorder_audition_vector',global_at,struct.pack('>3I',label,label+28*count,label+28*count)))
    with tempfile.TemporaryDirectory(prefix='recorder-name-scan-') as temp:
        code=B.R.assemble((B.T.ROOT/'scripts/asm/dt2_recorder_filename_scan.S').read_text(),0x40189c20,Path(temp),'filename-scan')
        assign=B.R.assemble((B.T.ROOT/'scripts/asm/dt2_recorder_assign_complete.S').read_text(),0x46020000,Path(temp),'assign-complete')
    L.EXTRA_CODE.append(('recorder_filename_scan',0x40189c20,code))
    L.EXTRA_CODE.append(('recorder_assign_complete',0x46020000,assign))
    L.EXTRA_STATE=[('recording_shared_singleton',0x44f370e0,0x44f370e8),
                   ('sampler_view_worker_state',0x40965ef0,0x40965ef4)]
    L.CODE=[('recording_assign_prompt_a',0x40018bdc,0x40018dd2),
            ('recording_assign_prompt_b',0x40018ea0,0x400194d6),
            ('sampler_view',0x4001f3f2,0x400232e0),
            ('recorder_controller_a',0x40015dec,0x4001606c),
            ('recorder_controller_b',0x4001613a,0x400163b0),
            ('recorder_singleton',0x4019988a,0x40199926),
            ('sampler_view_lifetime',0x4019bc7a,0x4019bdbe),
            ('sampler_view_factory',0x401afdd4,0x401afe1e),
            ('sampler_view_lookup',0x4019be72,0x4019bf38)]
    L.DATA=[('recording_assign_prompt_types',0x401eda7c,0x401edabc),
            ('recording_assign_prompt_vtables',0x401edac8,0x401edb80),
            ('recorder_confirm_owner_type',0x401ed864,0x401ed870),
            ('recorder_confirm_owner_vtable',0x401ed9f4,0x401eda10),
            ('recorder_info_owner_type',0x401edabc,0x401edac8),
            ('recorder_info_owner_vtable',0x401edb80,0x401edb9c),
            ('sampler_option_tables',0x401ee758,0x401ee9a8),
            ('sampler_callback_types',0x401eeb84,0x401eec34),
            ('sampler_vtables',0x401eec4c,0x401eed5c),
            ('sampler_shared_type',0x401f7638,0x401f7644),
            ('sampler_shared_vtable',0x401f7aa0,0x401f7abc),
            ('recorder_base_type',0x401ed35c,0x401ed364),
            ('recorder_types',0x401ed3bc,0x401ed404),
            ('recorder_vtables',0x401ed41c,0x401ed44c),
            ('recorder_shared_type',0x401ed508,0x401ed514),
            ('recorder_shared_vtable',0x401ed5e8,0x401ed604)]
    L.METHODS={'constructor':0x40020fd6,'factory':0x401afdd4,
       'destroy':0x4019bc7a,'draw':0x40021de0,'event':0x40022c6e,
       'encoder_event':0x40020960,'recorder':0x4019988a,'recording_state':0x40015f6c,
       'recorder_tick':0x40016338,'normalize':0x400161fe,'assign_complete':0x46020000}
    L.build(out)
    path=out/'build-receipt.json';doc=json.loads(path.read_text())
    # Bind only AssignPrompt's registered UI completion, retaining its body as
    # the wrapper's tail call. Native ONESHOT init runs on success, never on an
    # unsuccessful file/pool load and never for an already-sampling track.
    edit=next(e for e in doc['recorder_ui']['edits'] if e.get('donor')=='0x40019182')
    before=int(edit['binding'],16);after=int(doc['recorder_ui']['methods']['assign_complete'],16)
    image=bytearray((out/'main-os.bin').read_bytes());c=doc['runtime_copy']
    offset=int(c['source'],16)-B.BASE+int(edit['runtime'],16)-int(c['destination'],16)
    assert image[offset:offset+4]==struct.pack('>I',before)
    image[offset:offset+4]=struct.pack('>I',after);edit['binding']=hex(after)
    runtime=bytes(image[int(c['source'],16)-B.BASE:int(c['source'],16)-B.BASE+c['bytes']])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(runtime)
    doc['main_sha256']=B.T.SHA(image);doc['runtime_sha256']=B.T.SHA(runtime)
    doc['recorder_ui'].update(unbound_control_imports=[hex(x) for x in unbound],
        native_font_assets=font_proof, native_tempo_binding=tempo_proof,
        donor_main_view_subobject=0, factory_abi='void factory(shared_owner** output)',
        view_bytes=0x11a8, shared_owner_bytes=0x11b8,
        connected_to_navigation=False, donor_workflow=True,
        assignment='Successful loads initialize stock synth target as ONESHOT through existing UI init; existing sampler Machine preserved.')
    doc['flash_ready']=False
    path.write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(final_main_sha256=doc['main_sha256'],runtime_bytes=c['bytes'],
                         methods=doc['recorder_ui']['methods']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--bindings',type=Path)
    p.add_argument('--allow-unbound-controls',action='store_true')
    a=p.parse_args();build(a.input,a.out,a.bindings,a.allow_unbound_controls)
