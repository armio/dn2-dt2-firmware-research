#!/usr/bin/env python3
"""Relocate DN2 voice-engine initialization with independent right-side buffers.

Development component; no startup or dispatch hook is installed yet.
"""
from pathlib import Path
import argparse,json
import build_dt2_stereo_voices as P
C,B=P.C,P.B
BASE=C.ROOT/'output/dn2-research/dt2-stereo-voices-v2-20261009/section_7.bin'
SHA='796cadbb66f4907ec7d93872a3e8b92cacfbb9c6e4d1c00487ddeed7b215ef32'
INIT,RESET=0x174000,0x174100
NOOP=0x174480
# The right lane processes already-rendered sampler audio, not native
# oscillators. Native global tables have already been initialized at startup.
UNUSED_SYNTH_INIT={0x1c463b,0x1c4e78,0x1c6909,0x1c7069,0x1c8246}
DELAY,SCRATCH,ENGINE,PARAMS,CONFIG=0x80540000,0x805c0000,0x805c1000,0x805d6000,0x805d9000
SPANS=[('init',0x1c8e1c,0x1c8ef1,INIT),('reset_voice',0x1c8b6d,0x1c8e1c,RESET)]
BINDINGS={0x804acf90:P.BUFFERS,0x804ace90:SCRATCH,0x804ad790:DELAY}


def mapped(v,*,required=False):
    for _,lo,hi,at in SPANS:
        if lo<=v<hi:return at+v-lo
    if required and v in UNUSED_SYNTH_INIT:return NOOP
    return BINDINGS.get(v,v)


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    base=BASE.read_bytes();assert C.SHA(base)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');memory=k.ldr.LoadedMemory.from_stream(base)
    blocks=[];spans=[];relocations=[]
    for name,lo,hi,at in SPANS:
        code,changes,listing=B.relocate(k,memory,lo,hi,at,mapper=mapped)
        blocks.append((C.S.code_address(at),code))
        (out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
        spans.append(dict(name=name,native=hex(lo),end=hex(hi),target=hex(at),bytes=len(code)))
        relocations.extend(changes)
    asm=out/'unused-synth-init.asm'
    asm.write_text('''.SECTION/PM seg_pmco;
      I12 = DM(M7, I6);
      NOP;
      JUMP (M14, I12) (DB);
      NOP;
      RFRAME;
''')
    be,_=P.A._selas(asm,out);blocks.append((C.S.code_address(NOOP),P.O.load_bytes(be)))
    regions=[('delay',DELAY,0x80000),('shared_scratch',SCRATCH,0x100),
             ('engine',ENGINE,0x14220),('parameters',PARAMS,0x2340),('configuration',CONFIG,0x100)]
    for name,at,size in regions:blocks.append((at,bytes(size)))
    placed=[]
    for at,blob in blocks:
        assert not any(a<at+len(blob) and at<a+len(b) for a,b in (*C.B.load_regions(base),*placed))
        placed.append((at,blob))
    image=C.B.insert_before_final(base,b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image)
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),spans=spans,relocations=relocations,
             regions=[dict(name=n,address=hex(a),bytes=b) for n,a,b in regions],
             buffer_bindings={hex(a):hex(b) for a,b in BINDINGS.items()},
             entry=hex(INIT),reset=hex(RESET),hook_installed=False,flash_ready=False,
             contract='Effects-only engine. Original linked ABI: R4=engine, R8=parameters, R12=config, stack arg1=48000.0f. Run after native global initialization. Native synth initialization calls return through a leaf stub; their caller delay slots and frames are preserved. Right processing must bypass native oscillators and use sampler-kind parameter records.',
             unused_synth_initializers=[hex(x) for x in sorted(UNUSED_SYNTH_INIT)],
             remaining=['Connect right processing without duplicate oscillator generation','Reset/voice-steal routing','DT2 stereo pan and output hook','Host loader and final firmware'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=doc['section7_sha256'],spans=spans,regions=doc['regions']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
