#!/usr/bin/env python3
"""Link the original DT2 project sample-pool reset to existing DN2 ports."""
from pathlib import Path
import argparse,json
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-fs-startup-20261009'
SHA='1498a585c2123967f30ae821c2a75650121850e96700b4d5c52c60de32d7cd04'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_reset';L.LIMIT=0x47aa0000
    L.CODE=[('reset',0x40154358,0x401543a6)]
    L.DATA=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_SPANS=[];bindings={}
    for key in ('sample_loader','sample_allocator','pcm_pages'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update({0x401360ac:0x40134490,0x401360f4:0x401344d8,
                     0x4011e8f0:0x40120264,0x4011e8fc:0x40120270})
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.RESERVE_VENEERS=True;L.METHODS={'reset':0x40154358};L.build(out)
    p=out/'build-receipt.json';result=json.loads(p.read_text())
    result['sample_reset']['behavior']='Original DT2 loop clears 1024 slot descriptors, destroys allocation records, reindexes and emits event32/-1.'
    result['sample_reset']['connected_to_project_lifecycle']=False
    result['sample_reset']['limits']=['Reset routine linked; original restore scheduling and DN2 project access still need integration.']
    p.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
