#!/usr/bin/env python3
"""Relocate original DT2 RPC arm/open/send routines; startup remains separate."""
from pathlib import Path
import argparse,json,struct
import build_dt2_waveforms as W
C,R=W.C,W.R
BASE=C.ROOT/'output/dn2-research/dt2-waveforms-20261009/section_7.bin'
SHA='501b802632bb599f1391423a59638c841e0c02bf5a13c8577612688df5ca9f11'
LO,HI,CODE=0x1c7d09,0x1c7e1f,0x18c000
OLD_STATE,STATE,SIZE=0x25f7d8,0x319000,0x2070
CONFIG=0x31b080
# Same peripheral driver API used by the native dormant channel-1 initializer
# 1CA63E. Channel 0 audio initialization remains untouched.
BINDINGS={0x1c070a:0x1c0756,0x1c989b:0x1cc019,0x1c9fd5:0x1cc753,
    0x1c8ef4:0x1cb672,0x1c8edf:0x1cb65d,0x1c9195:0x1cb913,
    0x1c8e21:0x1cb59f,0x1c8e9f:0x1cb61d,0x1c8e8c:0x1cb60a,
    0x261848:0x2c0078,0x261b18:0x2c0348,0x261cb8:CONFIG}
TWINS=((0x1c989b,0x1c99e9,0x1cc019),(0x1c9fd5,0x1ca034,0x1cc753),
    (0x1c8ef4,0x1c8f17,0x1cb672),(0x1c8edf,0x1c8ef4,0x1cb65d),
    (0x1c9195,0x1c91c2,0x1cb913),(0x1c8e21,0x1c8e46,0x1cb59f),
    (0x1c8e9f,0x1c8eb2,0x1cb61d),(0x1c8e8c,0x1c8e9f,0x1cb60a))


def mapped(v,*,required=False):
    if LO<=v<HI:return CODE+v-LO
    if OLD_STATE<=v<OLD_STATE+SIZE:return STATE+v-OLD_STATE
    if v in BINDINGS:return BINDINGS[v]
    if required:raise ValueError(f'Unbound RPC target {v:#x}')
    return v


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    native=k.ldr.LoadedMemory.from_stream(raw)
    def twin_map(v,*,required=False):
        for a,z,to in TWINS:
            if a<=v<z:return to+v-a
        leaf={0x1c8b0d:0x1cb28b,0x1c8aaa:0x1cb228,0x2694a0:0x268ce0,
              0x1c0cd0:0x1c0bde,0x1c9f9c:0x1cc71a,0x1c9a52:0x1cc1d0,
              0x1c9a4c:0x1cc1ca,0x1c99e9:0x1cc167,0x1ca034:0x1cc7b2,0x1c8e46:0x1cb5c4}
        if v in leaf:return leaf[v]
        return R.mapped(v,required=required)
    twins=[]
    for a,z,to in TWINS:
        body,changes,_=R.relocate(k,donor,a,z,to,mapper=twin_map)
        assert body==native.read_sw(to,len(body)),hex(a)
        twins.append(dict(donor=hex(a),native=hex(to),bytes=len(body),sha256=C.SHA(body),bindings=changes))
    # Two 40-byte channel descriptors: physical register blocks and IRQ IDs.
    physical=donor.read(C.S.data_address(0x2694a0),80)
    assert physical==native.read(C.S.data_address(0x268ce0),80)
    memcpy,_,_=R.relocate(k,donor,0x1c070a,0x1c072a,0x1c0756,
        mapper=lambda v,required=False:0x1c0756+v-0x1c070a if 0x1c070a<=v<0x1c072a else mapped(v,required=required))
    assert memcpy==native.read_sw(0x1c0756,len(memcpy))
    code,bindings,listing=R.relocate(k,donor,LO,HI,CODE,mapper=mapped)
    state=donor.read(C.S.data_address(OLD_STATE),SIZE);assert state==bytes(SIZE)
    cfg=list(struct.unpack('<4I',donor.read(C.S.data_address(0x261cb8),16)))
    assert cfg==[0x25f810,0x25f7d8,0x202,0x4000]
    cfg[:2]=[mapped(a) for a in cfg[:2]]
    blocks=[(C.S.code_address(CODE),code),(C.S.data_address(STATE),state),
            (C.S.data_address(CONFIG),struct.pack('<4I',*cfg))]
    regions=C.B.load_regions(raw)
    for a,b in blocks:
        assert not any(x<a+len(b) and a<x+len(y) for x,y in regions),hex(a)
        regions.append((a,b))
    image=C.B.insert_before_final(raw,b''.join(C.B.block(a,b) for a,b in blocks))
    out.mkdir(parents=True,exist_ok=False)
    (out/'section_7.bin').write_bytes(image);(out/'rpc-transport.asm').write_text('\n'.join(listing)+'\n')
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),code=hex(CODE),code_bytes=len(code),
        state=hex(STATE),state_bytes=SIZE,config=hex(CONFIG),bindings=bindings,native_twins=twins,
        physical_channel_table_sha256=C.SHA(physical),
        entries={n:hex(mapped(a)) for n,a in [('arm',LO),('initialize',0x1c7d9f),('send',0x1c7e02)]},
        native_handle='0x2c0078',native_driver_context='0x2c0348',startup_hook=False,flash_ready=False,
        remaining=['Task/command dispatch and completion interrupt wakeup',
                   'ColdFire request transport/cache and audition',
                   'Hardware RAM/peripheral ownership and final firmware integration'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps({n:doc[n] for n in ('section7_sha256','entries','startup_hook')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
