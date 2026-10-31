#!/usr/bin/env python3
"""Port original ColdFire waveform requests, handshake and DMA transfer code."""
from pathlib import Path
import argparse,json
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-preview-20261009'
SHA='bafee19b2037e98942c255c09add6b2731897bbc2a9bb87657168fa54ba12f54'


def build(out):
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='waveform_rpc';L.LIMIT=0x47a90000
    L.CODE=[('requests',0x400124a0,0x40012632),('dma_irq',0x400ccd74,0x400ccda0),
            ('response_getter',0x400cd482,0x400cd48a),('transfer',0x400cd48a,0x400cd638)]
    L.DATA=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.DIRECTORY_AUX=False;L.EXTRA_DATA={};L.EXTRA_SPANS=[]
    L.EXTRA_STATE=[('request_state',0x40965b70,0x40965b8c),('dma_callback',0x42948b04,0x42948b08),
                   ('dma_buffers',0x4fe79340,0x4fe7c340)]
    L.STATE_ALIGNMENT=64
    bindings={0x400ccf28:0x400cf300,0x400ccf40:0x400cf318,0x401360ac:0x40134490,0x40000158:0x40000158}
    evidence=[]
    for a in (0x40001398,0x4000141a,0x4000155c,0x40001608,0x4000172a):
        end,_=B.M.function(donor,a);body=donor[a-B.BASE:end-B.BASE]
        fixed=body.replace(B.BE(0x47db3f64),B.BE(0x4664acdc)).replace(B.BE(0x47db3f24),B.BE(0x4664ac9c)).replace(B.BE(0x40964914),B.BE(0x4058d15c))
        assert fixed==native[a-B.BASE:a-B.BASE+len(body)],hex(a)
        bindings[a]=a;evidence.append(dict(donor=hex(a),native=hex(a),bytes=len(body)))
    for a,to in ((0x400ccf28,0x400cf300),(0x400ccf40,0x400cf318)):
        end,_=B.M.function(donor,a);body=donor[a-B.BASE:end-B.BASE]
        assert body.replace(B.BE(0x42948b10),B.BE(0x42440960))==native[to-B.BASE:to-B.BASE+len(body)]
        evidence.append(dict(donor=hex(a),native=hex(to),bytes=len(body)))
    # Native synth/control callers use A80-byte packets. Only packets >AF0
    # enter the existing first-port overflow transmitter400CF694.
    current=(INPUT/'main-os.bin').read_bytes()
    for pc in (0x40025e9a,0x400d0fe2):
        assert current[pc-B.BASE:pc-B.BASE+4]==native[pc-B.BASE:pc-B.BASE+4]==bytes.fromhex('48780a80')
    L.EXTRA_BINDINGS=bindings;L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.RESERVE_VENEERS=True
    L.METHODS={'request':0x400124a0,'request_sent':0x400124fa,'response_ready':0x40012500,
               'response_received':0x40012532,'small':0x40012562,'large':0x400125ca,
               'transfer':0x400cd48a,'response_buffer':0x400cd482,'dma_irq':0x400ccd74}
    L.build(out)
    p=out/'build-receipt.json';doc=json.loads(p.read_text());cfg=doc['waveform_rpc']
    cfg.update(native_twins=evidence,completion_callback_global='0x42440960',
        request_layout='Two packed big-endian u16 words: kind,slot; four bytes total.',
        buffers_alignment=64,
        limits=['ColdFire request transport not yet called by waveform cache.',
                'DMA buffers are in private MAIN RAM; cache/coherency and peripheral coexistence need hardware validation.',
                'Native callers currently use A80 bytes below AF0 overflow threshold; future larger packets require arbitration.',
                'DSP research worker currently supports commands0..2 only; remaining commands pending.'])
    p.write_text(json.dumps(doc,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
