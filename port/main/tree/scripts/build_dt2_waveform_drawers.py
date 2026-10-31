#!/usr/bin/env python3
"""Port the three original DT2 Source waveform drawers onto native graphics."""
from pathlib import Path
import argparse,json
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-waveform-events-20261009'
SHA='994510a22417c00b79ec756c3d08997f99c874c474c8434ae21e34aeb19fe0ba'
TWINS={0x4005aa8e:(0x40055b3a,4),0x40187db0:(0x4017cea4,12),
       0x4011221c:(0x40113b90,102),0x40112380:(0x40113cf4,184),
       0x40112568:(0x40113edc,208),0x401126f2:(0x40114066,226),
       0x401131e0:(0x40114b54,302)}

def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    doc=json.loads((INPUT/'build-receipt.json').read_text());evidence=[]
    for old,(new,size) in TWINS.items():
        assert donor[old-B.BASE:old-B.BASE+size]==native[new-B.BASE:new-B.BASE+size]
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=size,kind='exact complete native body'))
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='waveform_drawers';L.LIMIT=0x47a90000
    # Exclude unrelated translation-unit static destructors. These live
    # objects use the already ported shared waveform factory.
    L.CODE=[('markers_controls',0x4010e9f0,0x4010eb4c),('markers_draw',0x4010eb84,0x4010eef0),
            ('grid_controls',0x4010eef0,0x4010f02a),('grid_draw',0x4010f062,0x4010f32e),
            ('range_controls',0x4010f330,0x4010f46a),('range_draw',0x4010f4a2,0x4010f70e)]
    L.DATA=[];L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[]
    L.EXTRA_SPANS=[];bindings={}
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update({old:new for old,(new,size) in TWINS.items()})
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'markers_init':0x4010e9f0,'markers_slot':0x4010ea42,'markers_dirty':0x4010ea66,
        'markers_bounds':0x4010ea70,'markers_playhead':0x4010eaf8,'markers_arrows':0x4010eb40,'markers_draw':0x4010eb84,
        'grid_init':0x4010eef0,'grid_slot':0x4010ef50,'grid_dirty':0x4010ef74,'grid_blink':0x4010ef7e,
        'grid_count':0x4010ef90,'grid_selected':0x4010efaa,'grid_length':0x4010efc8,'grid_playhead':0x4010efe2,'grid_draw':0x4010f062,
        'range_init':0x4010f330,'range_slot':0x4010f38c,'range_dirty':0x4010f3b0,'range_blink':0x4010f3ba,
        'range_start':0x4010f3cc,'range_end':0x4010f3ea,'range_total':0x4010f408,'range_playhead':0x4010f422,'range_draw':0x4010f4a2}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['waveform_drawers'].update(native_twins=evidence,
        limits=['Callable original drawing components; SourcePageView lifecycle and hardware display are not yet connected.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
