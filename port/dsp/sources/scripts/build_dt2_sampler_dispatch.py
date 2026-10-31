#!/usr/bin/env python3
"""Connect the native sampler component to DN2's existing per-voice adapter.

Development DSP component only: CF Machine registration and metadata producers
are still absent. No SysEx is emitted by this builder.
"""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_sampler_frame_bridge as F
C, A, O = F.C, F.A, F.O
BASE = C.ROOT/'output/dn2-research/dt2-sampler-frame-v4-20261009/section_7.bin'
BASE_SHA = 'f14d12ad8a1495e066ff2871ec827d7b3c674399867acfb594a7ff50227eca4a'
CODE, STATE, MAP = 0x171400, 0x2e4400, 0x2e4820
CACHE, CURRENT, SAVE_R0, SAVE_R1 = STATE, STATE+0x100, STATE+0x104, STATE+0x108
WARP = STATE+0x200  # Explicit per-voice input; CF producer is not yet installed.
MACHINES = {5:'ONESHOT', 6:'WERP', 7:'STRETCH', 8:'REPITCH', 9:'GRID', 10:'SLICE'}


def source():
    s=f'''// Calls the original DT2 setup/render code through DN2's proven adapter.
.SECTION/PM seg_pmco;
.GLOBAL native_lifecycle.;
native_lifecycle.:
      R0 = DM(0x30dc94);
      R1 = 1;
      R1 = R0 AND R1;
      R2 = R0 - R1;
      R2 = LSHIFT R2 BY 1;
      R3 = 0x25c520;
      R2 = R3 + R2;
      I4 = R2;
      R2 = DM(0, I4);
      R1 = LSHIFT R1 BY 4;
      R1 = -R1;
      R2 = LSHIFT R2 BY R1;
      R1 = 0xffff;
      R2 = R2 AND R1;
      DM({CURRENT:#x}) = R2;
      R0 = LSHIFT R0 BY 2;
      R1 = {CACHE:#x};
      R0 = R1 + R0;
      I4 = R0;
      R3 = DM(0, I4);
      DM(0, I4) = R2;
      COMP(R2, R3);
      IF EQ JUMP 0x0; // -> native_lifecycle_done.
      // A new family must never inherit render history or STRETCH state.
      I4 = DM(0x30dc98);
      R0 = 0;
'''
    for word in range(118):
        s+=f'      DM({word}, I4) = R0;\n'
    s+=f'''      R1 = DM(0x30dc94);
      R1 = LSHIFT R1 BY 2;
      R2 = 0x30de60;
      R1 = R2 + R1;
      I4 = R1;
      DM(0, I4) = R0;
.GLOBAL native_lifecycle_done.;
native_lifecycle_done.:
      R2 = DM(0x30dce0);
      JUMP 0x185a26;

.GLOBAL native_setup_gate.;
native_setup_gate.:
      R0 = DM({CURRENT:#x});
      R1 = 6;
      COMPU(R0, R1);
      IF LT JUMP 0x0; // -> native_setup_oneshot.
      R1 = 10;
      COMPU(R0, R1);
      IF GT JUMP 0x0; // -> native_setup_oneshot.
      R1 = 5;
      R0 = R0 - R1;
      DM({F.CTX+12:#x}) = R0;
      R0 = DM(0x30dc98);
      DM({F.CTX:#x}) = R0;
      R1 = 0x188;
      R0 = R0 + R1;
      I4 = R0;
      R1 = DM(1, I4);
      R1 = PASS R1;
      IF NE JUMP 0x0; // -> native_setup_invalid.
      R0 = DM(0, I4);
      R1 = 141;
      COMPU(R0, R1);
      IF LT JUMP 0x0; // -> native_setup_invalid.
      R1 = 32767;
      COMPU(R0, R1);
      IF GT JUMP 0x0; // -> native_setup_invalid.
      R0 = DM(0x30dc9c);
      DM({F.CTX+4:#x}) = R0;
      R0 = DM(0x30dc94);
      R0 = LSHIFT R0 BY 2;
      R1 = 0x254b14;
      R1 = R0 + R1;
      I4 = R1;
      R1 = DM(0, I4);
      DM({F.CTX+8:#x}) = R1;
      R1 = {WARP:#x};
      R0 = R1 + R0;
      I4 = R0;
      R0 = DM(0, I4);
      DM({F.CTX+20:#x}) = R0;
      R0 = 0x473b8000;
      DM({F.CTX+16:#x}) = R0;
      R0 = DM(0x30dce8);
      DM({F.CTX+40:#x}) = R0;
      CALL {F.CODE:#x};
      JUMP 0x185737;
.GLOBAL native_setup_invalid.;
native_setup_invalid.:
      R0 = DM(0x30dc98);
      R1 = 0x1b8;
      R0 = R0 + R1;
      I4 = R0;
      R0 = 0;
      DM(0, I4) = R0;
      DM({F.CTX+44:#x}) = R0;
      JUMP 0x185737;
.GLOBAL native_setup_oneshot.;
native_setup_oneshot.:
      CALL 0x16f380;
      JUMP 0x1856b2;

.GLOBAL native_sample_rate.;
native_sample_rate.:
      // The legacy seed copies pointer/length but omitted the OSB1 rate.
      // I4 still addresses the selected (and bounds-checked) directory entry.
      // Native DT2 pitch setters require this unsigned Hz field at +0x184.
      R0 = DM(2, I4);
      R1 = DM(0x30dc98);
      R2 = 0x184;
      R1 = R1 + R2;
      I4 = R1;
      DM(0, I4) = R0;
      R0 = DM(0x30dcbc);
      JUMP 0x185b82;

.GLOBAL native_render_gate.;
native_render_gate.:
      // Tail dispatch preserves the original linked-call frame and arguments.
      DM({SAVE_R0:#x}) = R0;
      DM({SAVE_R1:#x}) = R1;
      R0 = DM({CURRENT:#x});
      R1 = 7;
      COMP(R0, R1);
      IF EQ JUMP 0x0; // -> native_render_stretch.
      R0 = DM({SAVE_R0:#x});
      R1 = DM({SAVE_R1:#x});
      JUMP 0x185000;
.GLOBAL native_render_stretch.;
native_render_stretch.:
      R0 = DM({SAVE_R0:#x});
      R1 = DM({SAVE_R1:#x});
      JUMP {C.mapped(0x1c5576):#x};

.GLOBAL native_handoff_gate.;
native_handoff_gate.:
      // Existing guard has already tested raw ON and extracted both words.
      R1 = 0xffff;
      R2 = R2 AND R1;
      R3 = R3 AND R1;
      R1 = 10;
      COMPU(R2, R1);
      IF GT JUMP 0x18619f;
      COMPU(R3, R1);
      IF GT JUMP 0x18619f;
      COMP(R2, R3);
      IF EQ JUMP 0x18619f;
      R1 = 5;
      COMPU(R2, R1);
      IF GE JUMP 0x1861ad;
      COMPU(R3, R1);
      IF GE JUMP 0x1861ad;
      JUMP 0x18619f;
'''
    return s


def build(out):
    base=BASE.read_bytes();assert C.SHA(base)==BASE_SHA
    out.mkdir(parents=True,exist_ok=False)
    asm=out/'dispatch.asm';text=source();asm.write_text(text)
    be,offsets=A._selas(asm,out)
    labels={n:CODE+off for n,off in O.symbols((out/'dispatch.doj').read_bytes()).items() if n.startswith('native_')}
    text=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (native_\w+\.))',
                lambda m:m[1]+hex(labels[m[3]])+m[2],text)
    asm.write_text(text);be,again=A._selas(asm,out);assert again==offsets
    code=O.load_bytes(be)
    k=C.M.Digikit(C.SRC/'toolchains/digikit');m=k.ldr.LoadedMemory.from_stream(base)
    oldmap=C.B.read_span(base,C.S.data_address(0x25d748),48)
    assert struct.unpack('<12I',oldmap)==(0,1,2,3,4,5,0,0,0,0,0,0)
    mapping=struct.pack('<12I',0,1,2,3,4,5,5,5,5,5,5,0)
    edits=[];linked=bytearray(base)
    for pc,expected,target,field in [
        (0x1c2958,0x0f150025d748,MAP,'data32'),
        (0x185a23,0x10020030dce0,labels['native_lifecycle.'],None),
        (0x1856af,0x06be0016f380,labels['native_setup_gate.'],None),
        (0x185b7f,0x10000030dcbc,labels['native_sample_rate.'],None),
        (0x185d03,0x180400185000,labels['native_render_gate.'],'addr24'),
        (0x18617b,0x0f010000ffff,labels['native_handoff_gate.'],None),
    ]:
        ins=k.st.decode_at(m,None,pc)
        assert ins.raw==expected and ins.length_bytes==6,(hex(pc),hex(ins.raw))
        raw=C.S.retarget(ins.raw,field,pc,target) if field else 0x063e00000000|target
        C.B.write_span(linked,C.S.code_address(pc),C.S.to_bytes(raw))
        edits.append(dict(pc=hex(pc),before=hex(ins.raw),after=hex(raw),target=hex(target)))
    blocks=[(C.S.code_address(CODE),code),(C.S.data_address(MAP),mapping)]
    regions=C.B.load_regions(base)
    reservations=[(C.S.data_address(STATE),0x300)]+[(at,len(b)) for at,b in blocks]
    for i,(at,n) in enumerate(reservations):
        assert 0x282e0000<=at<at+n<=0x282ec000
        assert not any(a<at+n and at<a+len(b) for a,b in regions)
        assert not any(a<at+n and at<a+s for a,s in reservations[:i])
    linked=C.B.insert_before_final(bytes(linked),b''.join(C.B.block(a,b) for a,b in blocks)+
                                   C.B.block(C.S.data_address(STATE),flags=C.B.FLAG_FILL,count=0x300))
    (out/'section_7.bin').write_bytes(linked)
    receipt=dict(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(linked),code_bytes=len(code),
                 labels={n:hex(a) for n,a in labels.items()},patches=edits,
                 machine_codes=MACHINES,machine_table=hex(MAP),state=hex(STATE),warp_positions=hex(WARP),
                 flash_ready=False,remaining=['ColdFire Machine registration and views',
                 'WERP position and SLICE editor producers','Native browser and sample pool',
                 'Offline SLICE assertion stub remains; live gate guards the short-length condition',
                 'Hardware validation and final image integration'])
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
