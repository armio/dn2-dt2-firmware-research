#!/usr/bin/env python3
"""Port original Source buttons, GRID/SLICE menus and slice creation actions.

See DN2-AGENT-HANDOFF-20261009.md for unresolved parameter/action boundaries.
"""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-manual-slice-editor-20261009'
SHA='b3755e59b01a899465ec060187613043df28a4580502e25861c0885f0d0619fd'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_events';L.LIMIT=0x47aa0000
    L.CODE=[('source_buttons',0x400181fe,0x400184ea),
            ('source_parent_buttons',0x4005fb0c,0x4005fe3e)]
    L.DATA=[('parent_callback_types',0x401f6a28,0x401f6a50),
            ('parent_dialog_owner_types',0x401f6a5c,0x401f6a8c),
            ('parent_dialog_owner_vtables',0x401f6be4,0x401f6c54)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[('source_browser_latch',0x40965bf0,0x40965bf4)]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder','source_dialogs','grid_actions','slice_create_dialog','manual_slice_editor'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds[0x4005063e]=int(doc['source_browser']['methods']['source_browser_machine'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    evidence=[]
    # Source's INFO path asks the Sound object for its owned display name.
    # DN2 has identical Kit/Sound name readers; choose the Sound reader and
    # its wrapper explicitly, preserving native string allocation/lifetime.
    for old,new,end in [(0x400e6074,0x400e7ac8,0x400e608a),
                        (0x400e608a,0x400e7ade,0x400e6154),
                        (0x4005003c,0x4004b1f4,0x40050060)]:
        rows=list(B.M.S.disasm(donor,B.BASE,old,end))
        x=bytearray(donor[old-B.BASE:end-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+len(x)]);pairs=[]
        for at,target,_,_ in B.M.operands(rows):
            off=at-old;dest=struct.unpack_from('>I',y,off)[0]
            binds[target]=dest;pairs.append(dict(donor=hex(target),native=hex(dest)))
            x[off:off+4]=y[off:off+4]=bytes(4)
        assert x==y,hex(old)
        binds[old]=new
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,operands=pairs))
    for old,new,end,adjust in [
        (0x4011de70,0x4011f7e4,0x4011dea2,{}),
        (0x4006cf20,0x4006787c,0x4006da74,
         {0x4006d06e:(274,320,4),0x4006d936:(274,320,4),
          0x4006d96b:(17,21,1),0x4006d97d:(18,22,1),0x4006d9c4:(275,321,4)})]:
        rows=list(B.M.S.disasm(donor,B.BASE,old,end))
        x=bytearray(donor[old-B.BASE:end-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+len(x)]);pairs=[]
        for at,target,_,_ in B.M.operands(rows):
            off=at-old;dest=struct.unpack_from('>I',y,off)[0]
            pairs.append(dict(donor=hex(target),native=hex(dest)))
            x[off:off+4]=y[off:off+4]=bytes(4)
        for at,(a,b,width) in adjust.items():
            off=at-old
            assert int.from_bytes(x[off:off+width],'big')==a
            assert int.from_bytes(y[off:off+width],'big')==b
            x[off:off+width]=y[off:off+width]=bytes(width)
        assert x==y,hex(old)
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=end-old,operands=pairs,
                             adaptations={hex(k):v for k,v in adjust.items()}))
        binds[old]=new
    for pair in next(e for e in evidence if e['donor']=='0x4011de70')['operands']:
        binds[int(pair['donor'],16)]=int(pair['native'],16)
    # Shared OverlayWindow constructor establishes native base vtables and
    # owner fields; its complete instruction body identifies the native ABI.
    for old in (0x4011894e,0x4005aabc,0x4005b926,0x4011dfc4,0x4005b23a):
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
    # OverlayWindow RTTI has the same class name and native base type.
    for old,new in [(0x4021d2f8,0x40206cc4)]:
        def name(raw,at):
            p=struct.unpack_from('>I',raw,at+4-B.BASE)[0]-B.BASE
            return raw[p:raw.index(0,p)]
        assert name(donor,old)==name(native,new)==b'13OverlayWindow'
        assert struct.unpack_from('>I',native,new+8-B.BASE)[0]==0x402074ac
        binds[old]=new
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'event':0x400181fe,'parent_event':0x4005fb0c,
               'slice_action':0x4005f92e,'slice_create':0x4005fe3e,'slice_assign':0x4005f822}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    cfg=doc['source_events'];c=doc['runtime_copy'];base,src=int(c['destination'],16),int(c['source'],16)
    raw=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes());patches=[]
    def runtime(pc):
        for s in cfg['spans']:
            lo,hi=int(s['donor'],16),int(s['end'],16)
            if lo<=pc<hi:return int(s['runtime'],16)+pc-lo
        raise AssertionError(hex(pc))
    def replace(pc,before,after,reason):
        at=runtime(pc);off=at-base
        assert len(before)==len(after) and payload[off:off+len(before)]==before,(hex(pc),payload[off:off+len(before)].hex())
        payload[off:off+len(before)]=after
        patches.append(dict(donor=hex(pc),runtime=hex(at),before=before.hex(),after=after.hex(),reason=reason))
    for pc,old,new in [(0x4001829a,205,4),(0x400182a4,241,325),(0x400182ac,214,352),
                       (0x400182b4,232,334),(0x400182bc,223,361),(0x400182c4,251,344)]:
        replace(pc,B.BE(old),B.BE(new),'Native SAMP parameter returned by Source knob resolver')
    replace(0x400183ec,bytes.fromhex('2052700620680090b084'),
            b'\x41\xf9'+B.BE(int(doc['source_browser']['methods']['source_browser_lock_read'],16))+bytes.fromhex('7006b084'),
            'Translate donor sample ID before native selected-trigger lock read')
    replace(0x40018444,bytes.fromhex('2040225022690028'),
            b'\x20\x40\x43\xf9'+B.BE(int(doc['source_parameters']['methods']['source_parameter_get'],16)),
            'Translate donor sample ID before native Sound parameter read')
    replace(0x4005f85e,B.BE(0x4f314),B.BE(0x4f358),'Native Project Sound pool offset')
    replace(0x4005f89a,struct.pack('>H',252),struct.pack('>H',345),'Native SLICE selection descriptor')
    # The inherited native parent already accepts every added sampler ID.
    for pc,want in [(0x400679ca,367),(0x40068292,367),(0x40068320,368)]:
        assert struct.unpack_from('>I',raw,pc-B.BASE)[0]==want
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    cfg.update(native_body_evidence=evidence,adaptations=patches,
        limits=['Complete Source view lifecycle is not yet installed in native page factories.',
                'Automatic and transient analysis RPC clients are linked; DSP commands3..10 remain pending.',
                'No hardware result.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(final_sha256=doc['main_sha256'],runtime_bytes=len(payload)),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
