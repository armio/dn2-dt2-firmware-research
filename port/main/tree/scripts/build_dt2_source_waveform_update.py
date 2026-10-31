#!/usr/bin/env python3
"""Connect original Source waveform updates to DN2 controls and slice fields."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-slice-live-20261009'
SHA='6e5d3a38b0450fbe163ac271268843d9f2bd2e12792fc80eced69e8322d1d13f'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_waveform_update';L.LIMIT=0x47aa0000
    L.CODE=[('source_update',0x40017728,0x40017a40)]
    L.DATA=[]
    donor=B.M.S.DONOR.read_bytes()
    L.EXTRA_DATA={0x401ed620:donor[0x401ed620-B.BASE:0x401ed627-B.BASE]};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    bindings={}
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    bindings.update({0x4006a856:0x400651b2,0x400da204:0x400dbff0})
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'update':0x40017728};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy']
    src,base=int(c['source'],16),int(c['destination'],16)
    raw=bytearray((out/'main-os.bin').read_bytes());payload=bytearray((out/'runtime.bin').read_bytes())
    entry=int(doc['source_waveform_update']['methods']['update'],16);patches=[]
    # Native Sound::data() returns the native record. Only these three
    # decoded slice offsets differ; ordinary source controls use adapters.
    for oldat,old,new in [(0x400179a6,316,375),(0x400179ec,320,379),(0x40017a08,324,383),
                         (0x40017838,243,doc['source_parameters']['records']['243']['native'])]:
        # GRID record243 is its LEN slot32, eighth entry of slots25..33.
        at=entry+oldat-0x40017728
        assert payload[at-base:at-base+2]==struct.pack('>H',old),(hex(oldat),payload[at-base:at-base+2].hex())
        payload[at-base:at-base+2]=struct.pack('>H',new)
        patches.append(dict(donor=hex(oldat),runtime=hex(at),old=old,new=new))
    raw[src-B.BASE:src-B.BASE+len(payload)]=payload
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False)
    doc['source_waveform_update'].update(layout_patches=patches,
        limits=['Original Source updater and drawer setters connected; Source view construction/events are still pending.',
                'Native controls and stored slice metadata; no hardware display claim.'])
    for name,data in [('main-os.bin',raw),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),update=hex(entry))))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
