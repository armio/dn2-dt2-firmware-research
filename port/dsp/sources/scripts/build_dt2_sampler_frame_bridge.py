#!/usr/bin/env python3
"""DN2 frame adapter feeding the original DT2 sampler setup entry points.

Caller supplies per-voice record, raw frame, note and WERP position. No Machine
selection hook is installed by this offline component builder.
"""
from pathlib import Path
import argparse,json,re,sys
import build_dt2_sampler_dsp as C
import sharc_waverider_m3 as A
from dnfw.image import sharc_object as O
A.m1.SELAS=str(C.ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release/selas')
CODE=0x171000
CTX=0x2e4000
TABLE=CTX+0x40
FIELDS={'record':0,'frame':4,'note_float':8,'selector':12,'engine_rate_float':16,
        'warp_position':20,'trigger':40,'status':44}
SAVE_I6,SAVE_I7=CTX+0x1f0,CTX+0x1f4
BASE=C.ROOT/'output/dn2-research/dt2-sampler-dsp-20261009/section_7.bin'
BASE_SHA='a6ed5a90c3e63a619824552c4737cb24a9289a1da079b82ee1a2aee64513d759'


def read_word(off):
    return f'''      R13 = DM({CTX+4:#x});
      R0 = {off};
      R0 = R13 + R0;
      R1 = 0xfffffffc;
      R1 = R0 AND R1;
      I4 = R1;
      R8 = DM(0, I4);
      R1 = 2;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 3;
      R1 = 0;
      R0 = R1 - R0;
      R8 = LSHIFT R8 BY R0;
      R1 = 0xffff;
      R8 = R8 AND R1;
'''


def flags():
    # Original PLAY conversion: reverse in bit 0 and loop in bit 8.
    return '''      R8 = LSHIFT R8 BY -8;
      R0 = 1;
      R1 = LSHIFT R8 BY -1;
      R1 = R1 AND R0;
      R2 = R8 AND R0;
      R2 = R2 XOR R1;
      R1 = R0 - R1;
      R0 = 3;
      COMPU(R8, R0);
      IF GT R1 = M5;
      IF GT R2 = M5;
'''


def source():
    s=f'''// Register/frame adaptation; original donor code makes all bounds,
// pitch, grid, segment and stretch decisions. Called inside a saved scope.
.SECTION/PM seg_pmco;
.GLOBAL native_frame_entry.;
native_frame_entry.:
      DM({SAVE_I6:#x}) = I6;
      DM({SAVE_I7:#x}) = I7;
      I6 = I7;
      R0 = I7;
      R1 = -64;
      R0 = R0 + R1;
      I7 = R0;
      R0 = 0;
      DM(I6, -2) = R0;
      DM({CTX+44:#x}) = R0;
      R0 = DM({CTX+12:#x});
      R1 = 1;
      COMPU(R0, R1);
      IF LT JUMP 0x0; // -> native_frame_exit.
      R1 = 5;
      COMPU(R0, R1);
      IF GT JUMP 0x0; // -> native_frame_exit.
'''
    s+='      R0 = 0;\n'
    for off in range(0,80,4):s+=f'      DM({TABLE+off:#x}) = R0;\n'
    s+=read_word(0)+f'''      R0 = -15;
      F8 = FLOAT R8 BY R0;
      DM({TABLE:#x}) = R8;
'''
    for word,normal,coarse in [(12,4,(24,36)),(14,8,(28,)),(16,12,(20,32))]:
        s+=read_word(word)+f'''      R0 = LSHIFT R8 BY -8;
'''
        for at in coarse:s+=f'      DM({TABLE+at:#x}) = R0;\n'
        s+=f'''      F8 = FLOAT R8;
      R0 = 0x38088889;
      F8 = F8 * F0;
      DM({TABLE+normal:#x}) = R8;
'''
    s+=read_word(2)+flags()+f'''      R0 = LSHIFT R2 BY 8;
      R0 = R0 OR R1;
      DM({TABLE+68:#x}) = R0;
'''
    s+=read_word(14)+flags()+f'''      DM({TABLE+40:#x}) = R2;
      DM({TABLE+44:#x}) = R1;
'''
    s+=read_word(18)+f'''      R0 = -15;
      F8 = FLOAT R8 BY R0;
      DM({TABLE+72:#x}) = R8;
      R0 = DM({CTX+20:#x});
      DM({TABLE+60:#x}) = R0;
'''
    # DT2 1C2699..1C26AD swaps 16-bit halves of frame words 35..40:
    # start/end/loop are full sample positions carried in ordinary frame slots.
    for off,dest in [(20,48),(24,52),(28,56)]:
        s+=read_word(off)+'''      R12 = LSHIFT R8 BY 16;
'''+read_word(off+2)+f'''      R8 = R12 OR R8;
      DM({TABLE+dest:#x}) = R8;
'''
    s+=f'''      // Same compensated /120 as donor 1C2F75..1C2FC2.
      R8 = DM(0x25c564);
      R0 = 0xffff;
      R8 = R8 AND R0;
      F8 = FLOAT R8;
      R6 = 0x3c088889;
      F6 = F8 * F6;
      R1 = 0x42f00000;
      F2 = MANT F6;
      F1 = F6 * F1;
      IF NOT AV F1 = F1 - F8;
      R10 = 0x3c088889;
      F2 = F1 * F10;
      IF NOT AV F6 = F6 - F2;
      R11 = R6;
      // Original native setup caller contract (1C654C..1C6579).
      R1 = DM({TABLE:#x});
      R0 = 0x43000000;
      F9 = F1 * F0;
      R7 = DM({TABLE+68:#x});
      R10 = LSHIFT R7 BY -8;
      R14 = 0x3f800000;
      R6 = DM({CTX+12:#x});
      I14 = {TABLE+0x4c:#x};
      I9 = {CTX+16:#x};
      M8 = {CTX+8:#x};
      I0 = {TABLE+0x84:#x};
      R0 = DM({CTX:#x});
      R1 = 0x188;
      R0 = R0 + R1;
      I15 = R0;
      // Mark the donor's seed flag only for a fresh note.
      R2 = DM({CTX+40:#x});
      R2 = PASS R2;
      IF EQ JUMP 0x0; // -> native_frame_seed_done.
      R0 = DM({CTX:#x});
      R1 = 0x1b8;
      R0 = R0 + R1;
      I4 = R0;
      R2 = DM(0, I4);
      R1 = 0x10000;
      R2 = R2 OR R1;
      DM(0, I4) = R2;
.GLOBAL native_frame_seed_done.;
native_frame_seed_done.:
      R8 = 0x42700000;
      R0 = DM({CTX+12:#x});
'''
    for selector,name in [(1,'WERP'),(2,'STRETCH'),(3,'REPITCH'),(4,'GRID'),(5,'SLICE')]:
        s+=f'''      R1 = {selector};
      COMP(R0, R1);
      IF EQ JUMP 0x0; // -> native_frame_{name.lower()}.
'''
    for selector,name in [(1,'WERP'),(2,'STRETCH'),(3,'REPITCH'),(4,'GRID'),(5,'SLICE')]:
        s+=f'''.GLOBAL native_frame_{name.lower()}.;
native_frame_{name.lower()}.:
      CALL {C.mapped(C.ENTRIES[name+'-setup']):#x};
      JUMP 0x0; // -> native_frame_success.
'''
    s+=f'''.GLOBAL native_frame_success.;
native_frame_success.:
      R0 = 1;
      DM({CTX+44:#x}) = R0;
.GLOBAL native_frame_exit.;
native_frame_exit.:
      I6 = DM({SAVE_I6:#x});
      I7 = DM({SAVE_I7:#x});
      RETURN;
'''
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==BASE_SHA
    asm=out/'frame.asm';text=source();asm.write_text(text)
    be,offsets=A._selas(asm,out);syms=O.symbols((out/'frame.doj').read_bytes())
    labels={n:CODE+off for n,off in syms.items() if n.startswith('native_')}
    text=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (native_\w+\.))',
                lambda m:m[1]+hex(labels[m[3]])+m[2],text)
    asm.write_text(text);be,new_offsets=A._selas(asm,out);assert new_offsets==offsets
    code=O.load_bytes(be);at=C.S.code_address(CODE)
    assert at+len(code)<=C.S.data_address(CTX)
    regions=C.B.load_regions(base)
    assert not any(a<at+len(code) and at<a+len(b) for a,b in regions)
    assert not any(a<C.S.data_address(CTX)+0x200 and C.S.data_address(CTX)<a+len(b) for a,b in regions)
    linked=C.B.insert_before_final(base,C.B.block(at,code)+C.B.block(C.S.data_address(CTX),flags=C.B.FLAG_FILL,count=0x200))
    (out/'section_7.bin').write_bytes(linked)
    receipt={'baseline_sha256':BASE_SHA,'section7_sha256':C.SHA(linked),'code_bytes':len(code),
             'entry':hex(CODE),'context':hex(CTX),'fields':FIELDS,'normalized_table':hex(TABLE),
             'labels':{n:hex(a) for n,a in labels.items()},'flash_ready':False,
             'contract':['Ordinary CALL inside caller register-save scope; I6/I7 restored',
                         'Caller provides valid sample record, engine sample rate, note, sampler selector and WERP position',
                         'SLICE reads native marker slots 35..40 and derives note mode from slot 31',
                         'Tempo reads the DN2 frame word at 0x25c564 (BPM times 120)',
                         'Shared scratch/context is for the serial audio loop; not reentrant'],
             'remaining':['Live DN2 voice selection/handoff and alternate-render dispatch',
                          'WERP position and SLICE metadata producers',
                          'Machine registration and browser',
                          'Replace offline fatal-assert stop before firmware delivery']}
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'code_bytes':len(code),'section7_sha256':C.SHA(linked),'flash_ready':False}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    build(p.parse_args().output)
