#!/usr/bin/env python3
"""Preserve DT2's four-gain stereo output loop behind a small DSP ABI.

Development component, not yet connected to the DN2 mono effects/pan chain.
The original mixer is copied; this adapter only supplies its registers.
"""
from pathlib import Path
import argparse,json
import build_dt2_voice_samples as V
C,B,A,O=V.C,V.B,V.A,V.O
BASE=C.ROOT/'output/dn2-research/dt2-voice-samples-20261009/section_7.bin'
SHA='49559f462c5bd37a836e94d9b4b5ccd98db4baf9c66ae546099d1d9e36ca14f7'
CODE,MIX,EXIT=0x173100,0x173400,0x173480
STATE=0x2fa400
POINTERS=STATE+0x100
# Ordinary CALL ABI: R4 points to thirteen words:
# left,right,out-left,out-right,count,LL,RL,LR,RR,dLL,dRL,dLR,dRR.
REGS=[*(f'R{i}' for i in range(16)),*(f'I{i}' for i in (0,1,2,3,4,5,14,15)), 'M0','M4']


def source():
    s='.SECTION/PM seg_pmco;\n.GLOBAL native_stereo_mix.;\nnative_stereo_mix.:\n'
    for i,reg in enumerate(REGS):s+=f'      DM({STATE+4*i:#x}) = {reg};\n'
    s+='      I4 = R4;\n      R15 = DM(4, I4);\n      R15 = PASS R15;\n'
    s+='      IF EQ JUMP 0x0; // -> native_stereo_restore.\n'
    for i in range(4):
        s+=f'      R0 = DM({i}, I4);\n'
        s+=f'      DM({POINTERS+4*i:#x}) = R0;\n'
    for index,reg in enumerate(('R11','R10','R9','R1','R13','R0','R14','R2'),5):
        s+=f'      {reg} = DM({index}, I4);\n'
    s+=f'''      I15 = {POINTERS+0x240:#x};
      I14 = 0;
      M0 = {POINTERS+8:#x};
      CALL {MIX:#x};
.GLOBAL native_stereo_restore.;
native_stereo_restore.:
'''
    for i,reg in enumerate(REGS):s+=f'      {reg} = DM({STATE+4*i:#x});\n'
    s+='''.GLOBAL native_stereo_return.;
native_stereo_return.:
      RTS;
'''
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    base=BASE.read_bytes();assert C.SHA(base)==SHA
    asm=out/'stereo-mixer.asm';asm.write_text(source());be,offsets=A._selas(asm,out)
    symbols=O.symbols((out/'stereo-mixer.doj').read_bytes())
    target=CODE+symbols['native_stereo_restore.']
    asm.write_text(asm.read_text().replace('JUMP 0x0;',f'JUMP {target:#x};'))
    be,again=A._selas(asm,out);assert again==offsets
    code=O.load_bytes(be);assert CODE+len(code)//2<=MIX
    k=C.M.Digikit(C.SRC/'toolchains/digikit');donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    def mapper(v,*,required=False):
        if 0x1c72fa<=v<0x1c7356:return MIX+v-0x1c72fa
        if v==0x1c7158:return EXIT
        if required:raise ValueError(hex(v))
        return v
    mix,changes,listing=B.relocate(k,donor,0x1c72fa,0x1c7356,MIX,mapper=mapper)
    (out/'original-stereo-mixer.asm').write_text('\n'.join(listing)+'\n')
    assert MIX+len(mix)//2<EXIT
    blocks=[(C.S.code_address(CODE),code),(C.S.code_address(MIX),mix),
            (C.S.code_address(EXIT),bytes.fromhex('3e0a00000000')),
            (C.S.data_address(STATE),bytes(0x110))]
    for at,blob in blocks:
        assert not any(a<at+len(blob) and at<a+len(b) for a,b in C.B.load_regions(base))
    image=C.B.insert_before_final(base,b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image)
    doc=dict(baseline_sha256=SHA,donor_sha256=C.DONOR_SHA,section7_sha256=C.SHA(image),
             entry=hex(CODE),code_bytes=len(code),mixer=hex(MIX),mixer_bytes=len(mix),
             exit=hex(EXIT),state=hex(STATE),labels={n:hex(CODE+v) for n,v in symbols.items() if n.startswith('native_')},
             relocations=changes,hook_installed=False,flash_ready=False,
             contract='Ordinary CALL; R4 -> 13 words: L,R,outL,outR,count,LL,RL,LR,RR,dLL,dRL,dLR,dRR. Positive count runs original DT2 loop; zero count is a no-op. Serialized audio-thread scratch; normal ABI M5=0/M6=1/M7=-1. Scalar execution mode.',
             remaining=['Paired render and effects state','Original stereo pan/gain producer','Install in DN2 output chain','Host allocator/loader/preview','Source/SLICE UI and final firmware'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(doc,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
