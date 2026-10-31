#!/usr/bin/env python3
"""Transplant the original DT2 small/large PCM waveform producers."""
from pathlib import Path
import argparse, json
import build_dt2_pcm_receiver as R
C=R.C
BASE=C.ROOT/'output/dn2-research/dt2-output-hook-20261009/section_7.bin'
SHA='82b28205ec4766bd351b5433e2c07c63831aac7b3f4b85b6636e9da4b7029b59'
START,END,CODE=0x1c42b8,0x1c443f,0x17ed00
OLD_STATE,STATE,SIZE=0x25c92c,0x805dc000,0xe40
DIV_OLD,DIV_NATIVE,DIV_BYTES=0xb88e04,0xb8b4dc,148


def mapped(value, *, required=False):
    if START<=value<END:return CODE+value-START
    if OLD_STATE<=value<OLD_STATE+SIZE:return STATE+value-OLD_STATE
    if value==DIV_OLD:return DIV_NATIVE
    return R.mapped(value,required=required)


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit')
    donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    native=k.ldr.LoadedMemory.from_stream(raw)
    division=donor.read_sw(DIV_OLD,DIV_BYTES)
    assert division==native.read_sw(DIV_NATIVE,DIV_BYTES)
    code,bindings,listing=R.relocate(k,donor,START,END,CODE,mapper=mapped)
    state=donor.read(C.S.data_address(OLD_STATE),SIZE)
    assert state is not None and len(state)==SIZE
    blocks=[(C.S.code_address(CODE),code),(STATE,state)]
    regions=C.B.load_regions(raw)
    for addr,payload in blocks:
        assert not any(a<addr+len(payload) and addr<a+len(b) for a,b in regions),hex(addr)
        regions.append((addr,payload))
    image=C.B.insert_before_final(raw,b''.join(C.B.block(a,b) for a,b in blocks))
    out.mkdir(parents=True,exist_ok=False)
    (out/'section_7.bin').write_bytes(image)
    (out/'waveforms.asm').write_text('\n'.join(listing)+'\n')
    receipt=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),donor_sha256=C.SHA(C.DONOR.read_bytes()),
        code=hex(CODE),code_bytes=len(code),state=hex(STATE),state_bytes=SIZE,bindings=bindings,
        entries={n:hex(mapped(a)) for n,a in [('reduce',START),('small',0x1c4353),('large',0x1c43c9)]},
        native_division=dict(donor=hex(DIV_OLD),native=hex(DIV_NATIVE),bytes=DIV_BYTES,sha256=C.SHA(division)),
        rpc_connected=False,flash_ready=False,
        remaining=['Connect native DSP RPC dispatch and ColdFire waveform cache',
                   'Audition and remaining browser/UI integration',
                   'Hardware validation of private RAM placement and final firmware'])
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ('section7_sha256','entries','rpc_connected')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
