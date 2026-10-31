#!/usr/bin/env python3
"""Port the original DT2 Create Slice Grid dialog and confirmation flow."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-grid-actions-20261009'
SHA='ee04c9777a885aa02ca409cc3e8301ed87d3fd4fb5d419f8f6e4eeecae268b86'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='slice_create_dialog';L.LIMIT=0x47aa0000
    L.CODE=[('slice_create_draw',0x400196b6,0x40019864),
            ('slice_create_dialog',0x400199d8,0x4001a05a)]
    L.DATA=[('slice_create_callback_type',0x401edc00,0x401edc08),('slice_grid_counts',0x401edc08,0x401edc20),
            ('slice_create_type',0x401edc2c,0x401edc38),
            ('slice_create_vtables',0x401edcd8,0x401edd78)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder','source_dialogs','grid_actions'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    binds[0x4005063e]=int(doc['source_browser']['methods']['source_browser_machine'],16)
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    evidence=[]
    # Shared OverlayWindow constructor establishes native base vtables and
    # owner fields; its complete instruction body identifies the native ABI.
    for old in (0x4011894e,):
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
    # Corresponding font constructors identify every native font object,
    # including the numeric font used only by this dialog.
    for old,new in zip(range(0x401d0e86,0x401d0fee,24),range(0x401b9d1c,0x401b9e84,24)):
        x=donor[old-B.BASE:old-B.BASE+24];y=native[new-B.BASE:new-B.BASE+24]
        assert x[:6]==bytes.fromhex('203c4021cb58') and y[:6]==bytes.fromhex('203c40206524')
        assert x[6:8]==y[6:8]==b'\x23\xc0' and x[12:14]==y[12:14]==b'\x20\x3c' and x[18:20]==y[18:20]==b'\x23\xc0'
        for offset in (8,20):binds[struct.unpack_from('>I',x,offset)[0]]=struct.unpack_from('>I',y,offset)[0]
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'init':0x40019c02,'event':0x40019d06,'draw':0x400196b6,'encoder':0x40019abc}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    c=doc['runtime_copy'];base=int(c['destination'],16);src=int(c['source'],16)
    raw=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes())
    spans=doc['slice_create_dialog']['spans']
    block=next(x for x in spans if x['name']=='slice_create_dialog')
    table=next(x for x in spans if x['name']=='slice_grid_counts')
    site=int(block['runtime'],16)+0x40019c84-int(block['donor'],16)
    # This immediate is an end iterator, not the adjacent class RTTI pointer.
    # Independently relocated spans no longer preserve original adjacency.
    end=int(table['runtime'],16)+24
    before=struct.unpack_from('>I',payload,site-base)[0]
    payload[site-base:site-base+4]=B.BE(end)
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    doc['slice_create_dialog'].update(native_body_evidence=evidence,
        count_list_end=dict(site=hex(site),previous=hex(before),end=hex(end)),
        limits=['Original creation UI/callback ABI is callable; sample-creation callback and Source ownership integration remain pending.',
                'Hardware display and input are untested.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
