#!/usr/bin/env python3
"""Add DT2's original slot-length RPC (command6) to the DSP worker."""
from pathlib import Path
import argparse,json,struct
import build_dt2_waveform_worker as W
C,R=W.C,W.R
BASE=C.ROOT/'output/dn2-research/dt2-waveform-worker-20261009/section_7.bin'
SHA='7a105d5caee0a41cbd916181b61964fda9a1731b7b30ae14b303055d24def6b2'
LO,HI,CODE=0x1c3d75,0x1c3db0,0x18c400
TABLE=0x31b400

def mapped(v,*,required=False):
    if LO<=v<HI:return CODE+v-LO
    return W.mapped(v,required=required)

def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');d=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());n=k.ldr.LoadedMemory.from_stream(raw)
    body,bindings,listing=R.relocate(k,d,LO,HI,CODE,mapper=mapped)
    wait=W.mapped(0x1c3c1d)
    table=[W.mapped(v) for v in (0x1c3c3e,0x1c3c4f,0x1c3c72)]+[wait]*3+[CODE]
    blocks=[(C.S.code_address(CODE),body),(C.S.data_address(TABLE),struct.pack('<7I',*table))]
    regions=C.B.load_regions(raw)
    for addr,data in blocks:assert not any(a<addr+len(data) and addr<a+len(b) for a,b in regions),hex(addr)
    image=bytearray(raw);patches=[]
    for pc,old,new in [(W.mapped(0x1c3c0f),3,7),(W.mapped(0x1c3c11),W.TABLE,TABLE)]:
        ins=k.st.decode_at(n,None,pc)
        if pc==W.mapped(0x1c3c0f):
            before=n.read_sw(pc,4);assert before==bytes.fromhex('8f0f0300')
            after=struct.pack('<HH',0x0f8f,new)
        else:
            assert C.S.get_field(ins.raw,'data32')==old
            after=C.S.to_bytes(C.S.retarget(ins.raw,'data32',pc,new))
        C.B.write_span(image,C.S.code_address(pc),after)
        patches.append(dict(pc=hex(pc),before=hex(old),after=hex(new)))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    out.mkdir(parents=True,exist_ok=False)
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),code=hex(CODE),bytes=len(body),
             enabled_commands=[0,1,2,6],table=hex(TABLE),bindings=bindings,patches=patches,flash_ready=False,
             response='Four bytes containing 16-bit PCM frame count; original slot getter shifts byte length right by one at1C3FC1, then worker swaps16-bit words for the link.',
             remaining=['RPC commands3..5 and7..10, full firmware integration and hardware validation'])
    (out/'section_7.bin').write_bytes(image);(out/'length.asm').write_text('\n'.join(listing)+'\n')
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(doc,indent=2))

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--out',type=Path,required=True);build(a.parse_args().out)
