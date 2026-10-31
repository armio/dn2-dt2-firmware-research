#!/usr/bin/env python3
"""Port the original DT2 ManualSliceEditorView; full firmware integration pending."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-slice-create-dialog-20261009'
SHA='47938fcd9a5bdbbb8d2fc58533505900853ce418980ce77744447378cf3dd81b'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='manual_slice_editor';L.LIMIT=0x47aa0000
    L.CODE=[('manual_slice_editor',0x4001a05c,0x4001d1b0)]
    L.DATA=[('manual_slice_callback_types',0x401edeac,0x401ededc),
            ('manual_slice_keys',0x401ededc,0x401edeec),
            ('manual_slice_types_vtables',0x401edeec,0x401ee034)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[('manual_waveform_scratch',0x40965bf4,0x40965df4)]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder','source_dialogs','grid_actions','slice_create_dialog'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds[0x4005063e]=int(doc['source_browser']['methods']['source_browser_machine'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    evidence=[]
    # The soft-float multiply/divide helpers share backward exception and
    # rounding tails. A single-function scan cannot delimit them. Match the
    # complete cluster, including its native floating-point status object.
    lo,hi,new=0x40182a4c,0x40183286,0x401782f4
    delta=new-lo
    x=bytearray(donor[lo-B.BASE:hi-B.BASE])
    y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo])
    rows=list(B.M.S.disasm(donor,B.BASE,lo,0x40183216))
    rows+=list(B.M.S.disasm(donor,B.BASE,0x40183218,hi))
    refs=list(B.M.operands(rows));pairs=[]
    for at,target,_,_ in refs:
        dest=struct.unpack_from('>I',y,at-lo)[0]
        expected=target+delta if lo<=target<hi else {0x4030c418:0x402f6f20}[target]
        assert dest==expected,(hex(at),hex(target),hex(dest))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
        binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
    assert x==y,'soft-float cluster changed beyond bound address operands'
    for pc,hx,mn,ops in rows:
        match=re.search(r'\$([0-9a-f]{8})',ops)
        if match and (mn.split('.')[0] in B.M.BRANCHES or '(pc)' in ops):
            assert lo<=int(match[1],16)<hi,(hex(pc),ops)
    L.EXTRA_SPANS.insert(0,dict(name='native_soft_float_cluster',donor=hex(lo),end=hex(hi),runtime=hex(new),kind='native'))
    evidence.append(dict(donor=hex(lo),end=hex(hi),native=hex(new),bytes=hi-lo,operands=pairs))
    # Audition snapshots use the native full Sound record, not DT2's shorter
    # record. The corresponding double-buffer allocator differs only in its
    # addresses and the 1104 -> 1163 byte stride.
    lo,hi,new=0x400d95f0,0x400d9620,0x400db44c
    x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo])
    pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,lo,hi))):
        dest=struct.unpack_from('>I',y,at-lo)[0]
        binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    assert x[30:34]==B.BE(1104) and y[30:34]==B.BE(1163)
    x[30:34]=y[30:34]=bytes(4)
    assert x==y
    binds[lo]=new
    evidence.append(dict(donor=hex(lo),end=hex(hi),native=hex(new),bytes=hi-lo,operands=pairs,sound_bytes=1163))
    # Use DN2's note dispatcher so its polyphonic allocator retains ownership.
    # Both ABIs are (track,note,velocity,source,only_midi,preset,override,
    #              trig_note_length,extra). Native source64 honors the override
    # Sound pointer written by the setter above. DN2 intentionally differs in
    # retrigger/voice handling; copying DT2's monophonic dispatcher is invalid.
    assert native[0x40121adc-B.BASE:0x40121aec-B.BASE]==bytes.fromhex('242e0008262e000c2a2e00142c2e001c')
    assert native[0x40121c1c-B.BASE:0x40121c26-B.BASE]==bytes.fromhex('2039445e215c2d40fff0')
    binds[0x4011fe12]=0x40121ad2
    binds[0x4012020c]=0x4012182a
    evidence.append(dict(donor='0x4011fe12',native='0x40121ad2',kind='Native nine-argument note-on ABI; override Sound at native frame+48',
                         note_off=dict(donor='0x4012020c',native='0x4012182a',args=['track','note','source'])))
    lo,hi,new=0x400c14a6,0x400c14dc,0x400bbad6
    x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo]);pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,lo,hi))):
        dest=struct.unpack_from('>I',y,at-lo)[0]
        binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    assert x==y
    binds[lo]=new
    evidence.append(dict(donor=hex(lo),end=hex(hi),native=hex(new),bytes=hi-lo,operands=pairs))
    lo,hi,new=0x401207c4,0x40120800,0x4012216c
    x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo]);pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,lo,hi))):
        dest=struct.unpack_from('>I',y,at-lo)[0]
        binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    for at,old_size,new_size in [(0x401207e6,1104,1163),(0x401207ec,17664,18608)]:
        assert struct.unpack_from('>I',x,at-lo)[0]==old_size
        assert struct.unpack_from('>I',y,at-lo)[0]==new_size
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    assert x==y
    binds[lo]=new
    evidence.append(dict(donor=hex(lo),end=hex(hi),native=hex(new),bytes=hi-lo,operands=pairs,sound_bytes=1163))
    # Play/stop indicator: the two 15x5 bitmap constructors and their vector
    # initialization are identical, including both pixel and mask payloads.
    lo,hi,new=0x40160ef6,0x40160f5c,0x4015679e
    x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo])
    pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,lo,hi))):
        dest=struct.unpack_from('>I',y,at-lo)[0]
        if target in (0x402f0328,0x402f0364,0x402f03a0):
            assert donor[target-B.BASE:target-B.BASE+60]==native[dest-B.BASE:dest-B.BASE+60]
        binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    assert x==y
    evidence.append(dict(donor=hex(lo),end=hex(hi),native=hex(new),bytes=hi-lo,operands=pairs))
    # Shared OverlayWindow constructor establishes native base vtables and
    # owner fields; its complete instruction body identifies the native ABI.
    for old in (0x4011894e,0x40062486,0x4005acf2,0x4005b116,0x4005ac9c,0x4005ad9c,0x40199680,0x400c0ec8,0x40079674,0x40113aa4):
        end,rows=B.M.function(donor,old);blob=donor[old-B.BASE:end-B.BASE]
        refs=list(B.M.operands(rows));mask=bytearray(b'\1'*len(blob))
        for at,_,_,_ in refs:mask[at-old:at-old+4]=bytes(4)
        pattern=b''.join(re.escape(bytes([v])) if keep else b'.' for v,keep in zip(blob,mask))
        hits=[B.BASE+m.start() for m in re.finditer(pattern,native,re.S) if m.start()%2==0]
        assert len(hits)==1,(hex(old),hits)
        new=hits[0];pairs=[];binds[old]=new
        for at,target,_,_ in refs:
            dest=struct.unpack_from('>I',native,new-B.BASE+at-old)[0]
            binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,operands=pairs))
    # MainScreenView singleton factory has the same hidden-A0 shared-owner
    # return, but DN2 inlines its weak-pointer checks and allocates 0x228 bytes.
    # Keep the native factory and the native close-overlays method above.
    assert native[0x4018e750-B.BASE:0x4018e760-B.BASE]==bytes.fromhex('4e56ffec48d70c042448207944647984')
    assert native[0x4018e7a2-B.BASE:0x4018e7b8-B.BASE]==bytes.fromhex('4878022847f9401202644e9324002f004eb940060e72')
    lo,hi,new=0x4019abbc,0x4019ac3a,0x4018e7b8
    x=bytearray(donor[lo-B.BASE:hi-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+hi-lo]);pairs=[]
    for at,target,_,_ in B.M.operands(list(B.M.S.disasm(donor,B.BASE,lo,hi))):
        dest=struct.unpack_from('>I',y,at-lo)[0]
        pairs.append(dict(donor=hex(target),native=hex(dest)))
        x[at-lo:at-lo+4]=y[at-lo:at-lo+4]=bytes(4)
    assert x==y
    binds[0x4019ab40]=0x4018e750
    evidence.append(dict(donor='0x4019ab40',native='0x4018e750',kind='Native MainScreenView singleton; matched shared-owner return suffix',operands=pairs))
    # OverlayWindow RTTI has the same class name and native base type.
    for old,new in [(0x4021d2f8,0x40206cc4)]:
        def name(raw,at):
            p=struct.unpack_from('>I',raw,at+4-B.BASE)[0]-B.BASE
            return raw[p:raw.index(0,p)]
        assert name(donor,old)==name(native,new)==b'13OverlayWindow'
        assert struct.unpack_from('>I',native,new+8-B.BASE)[0]==0x402074ac
        binds[old]=new
    for old,new in [(0x401ed35c,0x401d4f94),(0x401ed4e0,0x401d4c00),(0x40216784,0x40200158)]:
        def type_name(raw,at):
            off=struct.unpack_from('>I',raw,at+4-B.BASE)[0]-B.BASE
            return raw[off:raw.index(0,off)]
        assert type_name(donor,old)==type_name(native,new)
        binds[old]=new
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'init':0x4001bcbe,'event':0x4001cbba,'draw':0x4001c53a,'encoder':0x4001b5d0,
               'commit':0x4001a712,'waveform':0x4001a752,'audition':0x4001a7d8,
               'audition_stop':0x4001a8a8,'audition_update':0x4001a8d8}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    cfg=doc['manual_slice_editor'];copy=doc['runtime_copy']
    base,src=int(copy['destination'],16),int(copy['source'],16)
    payload=bytearray((out/'runtime.bin').read_bytes());raw=bytearray((out/'main-os.bin').read_bytes())
    block=next(s for s in cfg['spans'] if s['name']=='manual_slice_editor')
    delta=int(block['runtime'],16)-int(block['donor'],16);patches=[]
    # Preserve the historical T1E2 editor; later editor fixes are outside this release.
    changes={0x4001a808:(1104,1163),0x4001a908:(1104,1163)}
    for at,old in [(0x4001a83a,0x134),(0x4001a840,0x138),(0x4001a846,0x13c),(0x4001a850,0x13c),
                   (0x4001a93a,0x134),(0x4001a940,0x138),(0x4001a946,0x13c),(0x4001a950,0x13c)]:
        changes[at]=(old,old+59)
    for pc,(old,new) in changes.items():
        off=pc+delta-base;assert struct.unpack_from('>H',payload,off)[0]==old
        struct.pack_into('>H',payload,off,new)
        patches.append(dict(donor=hex(pc),runtime=hex(pc+delta),before=old,after=new))
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    cfg.update(native_body_evidence=evidence,sound_layout_patches=patches,
        limits=['Source actions and editor ownership integration remain pending.',
                'Waveform/analysis RPC commands and audition telemetry require remaining DSP integration.',
                'No hardware editor or audition result yet.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(final_sha256=doc['main_sha256'],runtime_bytes=len(payload),flash_ready=False),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
