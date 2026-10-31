#!/usr/bin/env python3
"""Port original DT2 Source drawing onto DN2 page and graphics methods."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-controls-20261009'
SHA='c9936bb3fecf607bce71b6d4dbbb8d983a0dfacbffbe44ef8c2f84097feca9d6'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_draw';L.LIMIT=0x47aa0000
    L.CODE=[('source_draw',0x40016eac,0x400170c0)];L.DATA=[]
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({int(k,16):int(v,16) for k,v in doc['source_page_access']['source_bindings'].items()})
    twins={0x4006b01e:0x4006597a,0x4006b02e:0x4006598a,0x4006b0b0:0x40065a0c,
           0x4005b076:0x40056122,0x40113cf4:0x40115668}
    evidence=[];donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    for old,new in twins.items():
        end,rows=B.M.function(donor,old);size=end-old
        x=bytearray(donor[old-B.BASE:end-B.BASE]);y=bytearray(native[new-B.BASE:new-B.BASE+size]);pairs=[]
        nr=list(B.M.S.disasm(native,B.BASE,new,new+size));assert len(rows)==len(nr),(hex(old),len(rows),len(nr))
        for at,target,_,_ in B.M.operands(rows):
            off=at-old;dest=struct.unpack_from('>I',y,off)[0]
            pairs.append(dict(donor=hex(target),native=hex(dest)))
            x[off:off+4]=y[off:off+4]=bytes(4)
        for a,b in zip(rows,nr):
            pc=re.search(r'\$([0-9a-f]{8})\(pc\)',a[3])
            if pc:
                npc=re.search(r'\$([0-9a-f]{8})\(pc\)',b[3]);assert npc
                off=a[0]-old+2;x[off:off+2]=y[off:off+2]=bytes(2)
                pairs.append(dict(donor='0x'+pc[1],native='0x'+npc[1]))
        adaptations=[]
        if old==0x4006b0b0:
            # Parent draw indexes native parameter records. The only non-address
            # difference is the two OSes' original record-count ceiling.
            off=0x4006b15e-old
            assert x[off:off+4]==struct.pack('>I',275)
            assert y[off:off+4]==struct.pack('>I',321)
            x[off:off+4]=y[off:off+4]=bytes(4)
            current=(INPUT/'main-os.bin').read_bytes()
            assert current[0x40065ab8-B.BASE:0x40065abe-B.BASE]==bytes.fromhex('0c8200000170')
            adaptations.append(dict(kind='native_parameter_record_limit',donor=275,stock_native=321,expanded_native=368))
        assert x==y,(hex(old),[(i,a,b) for i,(a,b) in enumerate(zip(x,y)) if a!=b][:10])
        evidence.append(dict(donor=hex(old),native=hex(new),bytes=size,operands=pairs,adaptations=adaptations))
    binds.update(twins)
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'draw':0x40016eac};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['source_draw'].update(native_body_evidence=evidence,
        required_vtable={'0xb4':'0x4006448a','0xb8':'0x40063cfc',
                         '0xbc':doc['source_controls']['methods']['knob_parameter'],
                         '0xec':'0x4018a28e'},
        limits=['Original Source draw is callable with the native parameter widgets and original waveform drawers.',
                'Full Source constructor, vtable/event adoption and hardware display remain pending.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
