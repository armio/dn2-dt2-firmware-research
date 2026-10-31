#!/usr/bin/env python3
"""Port original DT2 waveform factory/cache and its slot metadata provider."""
from pathlib import Path
import argparse,json
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-waveform-rpc-v2-20261009'
SHA='a03da7e1637a328fb5b7bebb2da7c608f6dd1bc76aa73e893901ab5495bd1414'


def build(out):
    donor=B.M.S.DONOR.read_bytes();doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='waveform_cache';L.LIMIT=0x47a90000
    L.CODE=[('cache_getters',0x4019f8a8,0x4019fac8),('cache_constructors',0x4019fe22,0x401a02c0),('convert',0x4003314e,0x4003321a),
            ('metadata',0x40153844,0x401538ce)]
    L.DATA=[('factory_rtti',0x401f10b4,0x401f10c8),('owner_rtti',0x401f111c,0x401f1128),
            ('factory_vtables',0x401f1198,0x401f11b8),('owner_vtable',0x401f127c,0x401f1298)]
    L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False
    L.EXTRA_DATA={0x402aafc8:donor[0x402aafc8-B.BASE:0x402aafd8-B.BASE]}
    L.EXTRA_STATE=[('factory_owner',0x44f371b8,0x44f371c0)];L.STATE_ALIGNMENT=4
    L.EXTRA_SPANS=[];bindings={0x45672351:0x45672351}
    for key in ('waveform_rpc','sample_allocator','sample_loader','pcm_pages','project_sample_load','sample_preview'):
        L.EXTRA_SPANS.extend(doc[key]['spans'])
        for edit in doc[key]['edits']:bindings[int(edit['target'],16)]=int(edit['binding'],16)
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.RESERVE_VENEERS=True
    L.METHODS={'factory':0x401a0208,'small':0x4019f8a8,'large':0x4019f9b8,
        'convert_small':0x4003314e,'convert_large':0x400331b4,'metadata':0x40153844}
    L.build(out)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
