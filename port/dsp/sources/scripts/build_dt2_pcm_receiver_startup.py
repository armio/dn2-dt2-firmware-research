#!/usr/bin/env python3
"""Add DT2's LP0 sample initialization at the corresponding DN2 startup point.

Research DSP only. Host allocator/loading, voice lookup and DDR ownership are
still unfinished; no SysEx is emitted.
"""
from pathlib import Path
import argparse, json, struct
import build_dt2_pcm_receiver as B
C=B.C
BASE=C.ROOT/'output/dn2-research/dt2-pcm-receiver-20261009/section_7.bin'
BASE_SHA='c4bb3a1149eab357e0f29e1d5b7ec8d570345b4485d2e139746791f64517ee31'
SITE,CODE,NEXT = 0x1ca822,0x172c00,0x1ca167


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit')
    mem=k.ldr.LoadedMemory.from_stream(raw)
    donor_raw=C.DONOR.read_bytes()
    donor=k.ldr.LoadedMemory.from_stream(donor_raw)
    # Includes the bootstrap's code, initialized DDR parameter tables, and
    # fill records, up to (not including) the second application header.
    native_end=C.B.walk(raw).blocks[7].offset
    donor_end=C.B.walk(donor_raw).blocks[7].offset
    assert native_end==donor_end==10612 and raw[:native_end]==donor_raw[:donor_end]
    # DT2: common init1C7F67, sample init1C7EC5, common init1C78D1.
    # DN2: common init1CA6D9,                  common init1CA167.
    for pc,target in ((0x1ca81b,0x1ca6d9),(SITE,NEXT)):
        assert C.S.get_field(k.st.decode_at(mem,None,pc).raw,'addr24')==target
    for pc,target in ((0x1c80b0,0x1c7f67),(0x1c80b7,0x1c7ec5),(0x1c80be,0x1c78d1)):
        assert C.S.get_field(k.st.decode_at(donor,None,pc).raw,'addr24')==target
    # Copy the original linked call and its compiler-managed frame stores.
    call=bytearray(donor.read_sw(0x1c80b7,14))
    call[:6]=C.S.to_bytes(C.S.retarget(C.S.to_value(call[:6]),'addr24',CODE,B.mapped(0x1c7ec5)))
    call[8:14]=C.S.to_bytes(C.S.retarget(C.S.to_value(call[8:14]),'data32',CODE+4,CODE+6))
    # After init returns, tail-call the original next native function. Its
    # return uses the original startup caller's linked frame and resumes1CA829.
    code=bytes(call)+C.S.to_bytes(0x063e00000000|NEXT)
    address=C.S.code_address(CODE)
    assert not any(a<address+len(code) and address<a+len(b) for a,b in C.B.load_regions(raw))
    old=k.st.decode_at(mem,None,SITE)
    assert old.type_name=='25a_direct' and old.length_bytes==6
    replacement=C.S.retarget(old.raw,'addr24',SITE,CODE)
    linked=bytearray(raw)
    C.B.write_span(linked,C.S.code_address(SITE),C.S.to_bytes(replacement))
    linked=C.B.insert_before_final(bytes(linked),C.B.block(address,code))
    # No found static callers or address constants reference the generic native
    # LP open. This is evidence of an unused port, not a dynamic ownership test.
    generic=struct.pack('<I',0x1caffb)
    address_refs=[]
    for a,b in C.B.load_regions(raw):
        pos=0
        while (hit:=b.find(generic,pos))>=0:
            address_refs.append(hex(a+hit));pos=hit+1
    receipt=dict(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(linked),
                 site=hex(SITE),wrapper=hex(CODE),bytes=len(code),
                 before=hex(old.raw),after=hex(replacement),
                 initialize=hex(B.mapped(0x1c7ec5)),next_native=hex(NEXT),resume='0x1ca829',
                 generic_native_open_address_refs=address_refs,
                 shared_ddr_bootstrap={'bytes':native_end,'sha256':C.SHA(raw[:native_end]),
                                       'scope':'Entire first loader application byte-exact in DT2 1.16 and DN2 1.11; no physical RAM test.'},
                 startup_hook=True,flash_ready=False,
                 remaining=['LP0 and DDR validation on device',
                            'Original host allocator/loader and voice descriptor binding',
                            'Full firmware integration and playback validation'])
    (out/'section_7.bin').write_bytes(linked)
    (out/'startup.bin').write_bytes(code)
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
