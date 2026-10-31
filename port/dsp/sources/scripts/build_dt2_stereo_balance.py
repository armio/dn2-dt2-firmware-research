#!/usr/bin/env python3
"""Link DT2's channel-preserving balance/output branch behind the pan ABI."""
from pathlib import Path
import argparse,json
import build_dt2_stereo_pan as P
C,A,O,B=P.C,P.A,P.O,P.B
BASE=C.ROOT/'output/dn2-research/dt2-stereo-pan-20261009/section_7.bin'
SHA='5ce1363d511ef85690131ebd80e37c68a0d0329219662ab0ca37899f250218aa'
CODE,PAN,LO,HI=0x178000,0x178400,0x1c705f,0x1c7158
STATE,FRAME,PARAM,GATE,AMP,PAIRS,REGS=P.STATE,P.FRAME,P.PARAM,P.GATE,P.AMP,P.PAIRS,P.REGS


def mapped(v,*,required=False):
    if LO<=v<HI:return PAN+v-LO
    if v==HI:return P.EXIT
    if v in P.TABLES:return P.TABLES[v]
    if required:raise ValueError(hex(v))
    return v


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    s=P.source().replace('native_stereo_pan','native_stereo_balance')
    s=s.replace(f'CALL {P.PAN:#x};',f'I5 = I13;\n      CALL {PAN:#x};')
    asm=out/'stereo-balance.asm';asm.write_text(s);be,offsets=A._selas(asm,out)
    labels=O.symbols((out/'stereo-balance.doj').read_bytes());restore=CODE+labels['native_stereo_balance_restore.']
    asm.write_text(s.replace('JUMP 0x0;',f'JUMP {restore:#x};'));be,again=A._selas(asm,out);assert again==offsets
    wrapper=O.load_bytes(be);assert CODE+len(wrapper)//2<PAN
    balance,changes,listing=B.relocate(k,donor,LO,HI,PAN,mapper=mapped)
    balance+=C.S.to_bytes(0x063e00000000|P.EXIT)
    blocks=[(C.S.code_address(CODE),wrapper),(C.S.code_address(PAN),balance)]
    for at,data in blocks:assert not any(a<at+len(data) and at<a+len(b) for a,b in C.B.load_regions(base))
    image=C.B.insert_before_final(base,b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image);(out/'native-balance.asm').write_text('\n'.join(listing)+'\n')
    doc=dict(section7_sha256=C.SHA(image),baseline_sha256=SHA,donor_sha256=C.DONOR_SHA,entry=hex(CODE),wrapper_bytes=len(wrapper),pan_bytes=len(balance),relocations=changes,
             contract='Same 13-word ordinary CALL ABI as177000, sharing serialized scratch and per-voice histories. Balance uses original DT2 constant0x3EB5A858; the scale ABI word is ignored by this branch. Both pan inputs may receive the same normalized track pan. Distinct channels stay distinct at center.',
             preserved_registers=REGS,hook_installed=False,flash_ready=False,
             remaining=['Bind native DN2 output and controls','Resolve original DT2 branch selector','Host load/preview, Source/SLICE UI and firmware'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n');print(json.dumps({key:doc[key] for key in ('section7_sha256','wrapper_bytes','pan_bytes')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
