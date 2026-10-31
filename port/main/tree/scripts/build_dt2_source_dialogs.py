#!/usr/bin/env python3
"""Port original DT2 GRID assignment and SLICE action menu dialogs."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-encoder-20261009'
SHA='e2784efb9101a9fb2db1ed627444e83addee4b57c490a6249386bc71803c3ba3'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_dialogs';L.LIMIT=0x47aa0000
    L.CODE=[('grid_dialog',0x4007c1bc,0x4007c49c),
            ('slice_dialog_base',0x400194d8,0x400196b6),
            ('slice_dialog_event',0x40019864,0x400199d8)]
    L.DATA=[('slice_dialog_rows',0x401edb9c,0x401edbac),('slice_dialog_labels',0x401edbac,0x401edbbc),
            ('grid_dialog_type',0x401fa56c,0x401fa618),
            ('slice_dialog_type',0x401edc20,0x401edc2c),
            ('slice_dialog_vt',0x401edc38,0x401edcd8)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[('grid_dialog_choice',0x4099d1e0,0x4099d1e4)]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('sample_manager','pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw','source_browser','source_encoder'):
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
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'grid_init':0x4007c410,'grid_event':0x4007c268,'grid_draw':0x4007c1bc,'grid_encoder':0x4007c3aa,
               'slice_init':0x4001957e,'slice_event':0x40019864,'slice_draw':0x400194d8,'slice_encoder':0x4001960e}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['source_dialogs'].update(native_body_evidence=evidence,
        limits=['Original menu dialogs are callable; Source parent callbacks and controller adoption remain pending.',
                'Hardware buttons, display and sample operations are untested.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
