#!/usr/bin/env python3
"""Original DT2 stereo coefficient, smoothing and mixing code behind an ABI."""
from pathlib import Path
import argparse,json,struct
import build_dn2_right_hooks as H
C,A,O,B=H.C,H.A,H.O,H.P.B
BASE=C.ROOT/'output/dn2-research/dn2-right-hooks-20261009/section_7.bin'
SHA='be81d711d80c497b6adde91b8aa37c0712dd3011edb6928088b72d0bb8c23544'
CODE,PAN,EXIT=0x177000,0x177400,0x173480
LO,HI=0x1c71ec,0x1c72fa
SCRATCH,STATE=0x805d9a00,0x805da000
CONTEXT=SCRATCH+0x100
PARAM,GATE,AMP,PAIRS,FRAME=SCRATCH+0x180,SCRATCH+0x200,SCRATCH+0x204,SCRATCH+0x250,SCRATCH+0x380
REGS=[*(f'{bank}{i}' for bank in ('R','S','I','M') for i in range(16))]
TABLES={0x8055c440:0x8052d790,0x8055c640:0x8052d990}


def mapped(v,*,required=False):
    if LO<=v<HI:return PAN+v-LO
    if v==0x1c7158:return EXIT
    if v in TABLES:return TABLES[v]
    if required:raise ValueError(hex(v))
    return v


def source():
    s='.SECTION/PM seg_pmco;\n.GLOBAL native_stereo_pan.;\nnative_stereo_pan.:\n'
    for i,reg in enumerate(REGS):s+=f'      DM({SCRATCH+4*i:#x}) = {reg};\n'
    s+=f'''      DM({CONTEXT:#x}) = R4;
      I4 = R4;
      R15 = DM(4, I4);
      R15 = PASS R15;
      IF EQ JUMP 0x0; // restore
      F8 = FLOAT R15;
      R4 = 0x3f800000;
      CALL 0x1c06ba;
      DM({FRAME-12:#x}) = R0;
      DM({FRAME-40:#x}) = R0;
      R0 = 0;
      DM({FRAME-8:#x}) = R0;
      I4 = DM({CONTEXT:#x});
'''
    for idx,addr in [(0,PAIRS),(1,PAIRS+4),(2,PAIRS+8),(3,PAIRS+12),
                     (5,PARAM-26*4),(6,PARAM+29*4),(7,PARAM-27*4),(8,PARAM+28*4),
                     (11,GATE),(12,AMP+20)]:
        s+=f'      R0 = DM({idx}, I4);\n      DM({addr:#x}) = R0;\n'
    s+=f'''      R15 = DM(4, I4);
      R4 = DM(9, I4);
      R0 = DM(10, I4);
      I4 = R0;
      R1 = 0x380;
      R0 = R0 + R1;
      I10 = R0;
      I6 = {FRAME:#x};
      I13 = {PARAM:#x};
      I11 = {GATE:#x};
      I9 = {AMP:#x};
      I8 = 0;
      I15 = {PAIRS+0x240:#x};
      I14 = 0;
      M0 = {PAIRS+8:#x};
      R8 = 0x43000000;
      R0 = 0x43000000;
      R11 = 0x42fe0000;
      R12 = 0;
      R14 = 0;
      CALL {PAN:#x};
.GLOBAL native_stereo_pan_restore.;
native_stereo_pan_restore.:
'''
    for i,reg in enumerate(REGS):s+=f'      {reg} = DM({SCRATCH+4*i:#x});\n'
    s+='      RTS;\n';return s


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());native=k.ldr.LoadedMemory.from_stream(base)
    assert C.SHA(C.DONOR.read_bytes())==C.DONOR_SHA
    for da,na in TABLES.items():assert donor.read(da,512)==native.read(na,512)
    asm=out/'stereo-pan.asm';asm.write_text(source());be,offsets=A._selas(asm,out)
    labels=O.symbols((out/'stereo-pan.doj').read_bytes());restore=CODE+labels['native_stereo_pan_restore.']
    asm.write_text(asm.read_text().replace('JUMP 0x0;',f'JUMP {restore:#x};'));be,again=A._selas(asm,out);assert offsets==again
    wrapper=O.load_bytes(be);assert CODE+len(wrapper)//2<PAN
    pan,changes,listing=B.relocate(k,donor,LO,HI,PAN,mapper=mapped)
    # After coefficient production continue through the already-linked original
    # DT2 matrix loop, whose ordinary RTS returns to this wrapper.
    pan+=C.S.to_bytes(0x063e00000000|0x173400)
    blocks=[(C.S.code_address(CODE),wrapper),(C.S.code_address(PAN),pan),(SCRATCH,bytes(0x400)),(STATE,bytes(0x700))]
    placed=[]
    for at,data in blocks:
        assert not any(a<at+len(data) and at<a+len(b) for a,b in (*C.B.load_regions(base),*placed));placed.append((at,data))
    image=C.B.insert_before_final(base,b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image);(out/'native-pan.asm').write_text('\n'.join(listing)+'\n')
    doc=dict(section7_sha256=C.SHA(image),baseline_sha256=SHA,donor_sha256=C.DONOR_SHA,entry=hex(CODE),wrapper_bytes=len(wrapper),pan_bytes=len(pan),relocations=changes,
             table_bindings={hex(a):hex(b) for a,b in TABLES.items()},
             state=hex(STATE),state_bytes=0x700,voice_state='STATE+4+56*voice; paired native state is+0x380',
             contract='Ordinary CALL R4->13 words: left,right,outL,outR,count,panL,panR,levelL,levelR,scale,state-pointer,gate,previous-AMP-flag. Pan/levels/scale are floats, pan inputs are native normalized channel positions. Per-voice state persists between blocks. Scalar serial execution; normal M5/M6/M7/M13/M14 conventions.',
             preserved_registers=REGS,hook_installed=False,flash_ready=False,
             remaining=['Bind DN2 controls to original DT2 channel pan positions','Replace final native sampler mono mix','Host load/preview and Source/SLICE UI','Final firmware and device playback'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n');print(json.dumps({key:doc[key] for key in ('section7_sha256','wrapper_bytes','pan_bytes')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
