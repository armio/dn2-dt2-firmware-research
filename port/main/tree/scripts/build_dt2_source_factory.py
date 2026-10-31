#!/usr/bin/env python3
"""Link the original DT2 Source view shared-owner factory."""
from pathlib import Path
import argparse,json
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-view-20261009'
SHA='07ca03dd8ee6a3891c96ab71a33e8d643a4d487fac8c4ab3338be7f513fca753'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_factory';L.LIMIT=0x47aa0000
    L.CODE=[('source_factory',0x401b0640,0x401b06b8)]
    L.DATA=[('source_owner_type',0x401f7560,0x401f756c),('source_owner_vtable',0x401f78a8,0x401f78c4)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[]
    L.EXTRA_SPANS=[];binds={}
    for part in doc.values():
        if not isinstance(part,dict) or 'spans' not in part:continue
        L.EXTRA_SPANS[0:0]=part['spans']
        for e in part.get('edits',[]):
            if 'target' in e and 'binding' in e:binds[int(e['target'],16)]=int(e['binding'],16)
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True
    L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.METHODS={'factory':0x401b0640}
    L.build(out)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
