#!/usr/bin/env python3
"""Connect paired DT2 sample records/setup/render to DN2's voice adapter.

Right blocks are available before voice effects. The DN2 output still uses
its mono path until paired effects and the original stereo panner are wired.
"""
from pathlib import Path
import argparse,json,re
import build_dt2_stereo_mixer as M
V=M.V;C,B,A,O=M.C,M.B,M.A,M.O
BASE=C.ROOT/'output/dn2-research/dt2-stereo-mixer-v2-20261009/section_7.bin'
SHA='15e6755cc856617bd5029fed190a61bf3a73891a7c9a8f38bcd580daa1a6c0ca'
CODE,STATE,TAGS,VALID=0x173500,0x2fa600,0x2fa700,0x2fa740
RECORDS,BUFFERS=0x2fac00,0x2fd000
RIGHT,LEFT,PHASE,SAVER4,SAVER8,SAVER12=range(STATE,STATE+24,4)
LEVEL_CURSOR=STATE+24
CURRENT=0x2e4500


def label(name):return f'.GLOBAL {name};\n{name}:\n'
def branch(name,cond=''):return f'      {cond}JUMP 0x0; // -> {name}\n'


def source():
    s='.SECTION/PM seg_pmco;\n'+label('native_pair_block.')
    s+='      DM(0x30dc10) = R0;\n      R0 = 0;\n'
    for i in range(16):s+=f'      DM({VALID+4*i:#x}) = R0;\n'
    s+='      R0 = DM(0x30dc10);\n      JUMP 0x185803;\n'
    s+=label('native_pair_bind.')+f'''      R0 = 0;
      DM({PHASE:#x}) = R0;
      R0 = DM(0x30dc94);
      R1 = 472;
      R0 = R0 * R1 (SSI);
      R1 = {RECORDS:#x};
      R0 = R0 + R1;
      DM({RIGHT:#x}) = R0;
      R0 = DM(0x30dc94);
      R0 = LSHIFT R0 BY 2;
      R1 = {TAGS:#x};
      R0 = R0 + R1;
      I4 = R0;
      R1 = DM(0, I4);
      R0 = DM({CURRENT:#x});
      DM(0, I4) = R0;
      COMP(R0, R1);
'''+branch('native_pair_metadata.','IF EQ ')+f'      I4 = DM({RIGHT:#x});\n      R0 = 0;\n'
    for i in range(118):s+=f'      DM({i}, I4) = R0;\n'
    s+=label('native_pair_metadata.')+f'''      I4 = DM({RIGHT:#x});
      R0 = DM({V.DESC+4:#x});
      R1 = DM(0, I4);
      COMP(R0, R1);
'''+branch('native_pair_rebind.','IF NE ')
    for address,offset in [(V.DESC+8,98),(V.DESC+12,97)]:
        s+=f'      R0 = DM({address:#x});\n      R1 = DM({offset}, I4);\n      COMP(R0, R1);\n'+branch('native_pair_rebind.','IF NE ')
    s+='      R1 = DM(99, I4);\n      R1 = PASS R1;\n'+branch('native_pair_arm.','IF EQ ')
    s+=label('native_pair_rebind.')+f'''      R0 = I7;
      R1 = -4;
      R0 = R0 + R1;
      I7 = R0;
      R0 = DM({V.DESC+12:#x});
      DM(I7, M7) = R0;
      DM(I7, M7) = 0;
      R0 = DM({V.DESC+8:#x});
      DM(I7, M7) = R0;
      R4 = DM({RIGHT:#x});
      R8 = DM({V.DESC+4:#x});
'''+V.linked(V.BIND,'native_pair_bound.')+'''      R0 = I7;
      R1 = 16;
      R0 = R0 + R1;
      I7 = R0;
'''+label('native_pair_arm.')+'''      R0 = DM(0x30dce8);
      R0 = PASS R0;
'''+branch('native_pair_bound_return.','IF EQ ')+f'      R4 = DM({RIGHT:#x});\n'+V.linked(V.ARM,'native_pair_bound_return.')+f'''      I6 = DM({V.STATE:#x});
      JUMP 0x172dbf;
'''
    # Run the existing setup route a second time inside its register-save scope.
    s+=label('native_pair_setup_done.')+f'''      R0 = DM({PHASE:#x});
      R0 = PASS R0;
'''+branch('native_pair_setup_return.','IF NE ')+f'''      R0 = 1;
      DM({PHASE:#x}) = R0;
      R0 = DM(0x30dc98);
      DM({LEFT:#x}) = R0;
      R0 = DM({RIGHT:#x});
      DM(0x30dc98) = R0;
      JUMP 0x17159f;
'''+label('native_pair_setup_return.')+f'''      R0 = DM({LEFT:#x});
      DM(0x30dc98) = R0;
      R0 = DM(0x30de50);
      JUMP 0x18573a;
'''
    # Nested linked call renders right, then a tail call renders left and
    # returns through the original caller's linked frame.
    s+=label('native_pair_render.')+f'''      DM({SAVER4:#x}) = R4;
      DM({SAVER8:#x}) = R8;
      DM({SAVER12:#x}) = R12;
      R4 = DM({RIGHT:#x});
      R0 = DM(0x30dc94);
      R0 = LSHIFT R0 BY 7;
      R1 = {BUFFERS:#x};
      R8 = R0 + R1;
      DM({LEVEL_CURSOR:#x}) = R8;
'''+V.linked(0x171671,'native_pair_rendered.')+f'''      R0 = DM(0x30dc94);
      R0 = LSHIFT R0 BY 2;
      R1 = {VALID:#x};
      R0 = R0 + R1;
      I4 = R0;
      R0 = 1;
      DM(0, I4) = R0;
      R4 = DM({SAVER4:#x});
      R8 = DM({SAVER8:#x});
      R12 = DM({SAVER12:#x});
      JUMP 0x171671;
'''
    # Apply the same per-sample gain to both channels before advancing it.
    # Keep the established native-curve level producer and shared ramp state.
    s+=label('native_pair_level.')+f'''      DM(0, I4) = R1;
      I4 = DM({LEVEL_CURSOR:#x});
      R1 = DM(0, I4);
      F1 = F1 * F4;
      DM(0, I4) = R1;
      R0 = DM({LEVEL_CURSOR:#x});
      R1 = 4;
      R0 = R0 + R1;
      DM({LEVEL_CURSOR:#x}) = R0;
      F4 = F4 + F5;
      JUMP 0x16f552;
'''
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==SHA
    asm=out/'stereo-voices.asm';text=source();asm.write_text(text)
    be,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'stereo-voices.doj').read_bytes()).items() if n.startswith('native_')}
    text=re.sub(r'(JUMP\s+)0x0(;\s*// -> (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],text)
    text=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],text)
    asm.write_text(text);be,again=A._selas(asm,out);assert again==offsets
    code=O.load_bytes(be);assert CODE+len(code)//2<0x174000
    k=C.M.Digikit(C.SRC/'toolchains/digikit');memory=k.ldr.LoadedMemory.from_stream(base)
    image=bytearray(base);patches=[]
    for pc,expected,name,field in [(0x185800,0x11000030dc10,'native_pair_block.',None),
                                  (0x172dbc,0x1016002fa200,'native_pair_bind.',None),
                                  (0x185737,0x10000030de50,'native_pair_setup_done.',None),
                                  (0x185d03,0x180400171671,'native_pair_render.','addr24')]:
        ins=k.st.decode_at(memory,None,pc);assert ins.raw==expected
        fixed=C.S.retarget(ins.raw,field,pc,labels[name]) if field else 0x063e00000000|labels[name]
        C.B.write_span(image,C.S.code_address(pc),C.S.to_bytes(fixed))
        patches.append(dict(pc=hex(pc),before=hex(expected),after=hex(fixed),target=name))
    # Two whole instructions: left store (4B), then ramp increment (2B).
    at=0x16f54f;expected=bytes.fromhex('0899800045c8')
    assert memory.read_sw(at,6)==expected
    fixed=C.S.to_bytes(0x063e00000000|labels['native_pair_level.'])
    C.B.write_span(image,C.S.code_address(at),fixed)
    patches.append(dict(pc=hex(at),before_bytes=expected.hex(),after_bytes=fixed.hex(),target='native_pair_level.'))
    blocks=[(C.S.code_address(CODE),code),(C.S.data_address(STATE),bytes(0x180)),
            (C.S.data_address(RECORDS),bytes(16*472)),(C.S.data_address(BUFFERS),bytes(16*128))]
    for at,blob in blocks:
        assert not any(a<at+len(blob) and at<a+len(b) for a,b in C.B.load_regions(base))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image)
    doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),entry=hex(CODE),code_bytes=len(code),
             labels={n:hex(v) for n,v in labels.items()},patches=patches,records=hex(RECORDS),buffers=hex(BUFFERS),valid=hex(VALID),
             flash_ready=False,remaining=['Right effects path','Original stereo gain producer and output hook','Host allocator/loader/preview','Source/SLICE UI and final firmware'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n');print(json.dumps(doc,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
