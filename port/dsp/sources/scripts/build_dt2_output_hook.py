#!/usr/bin/env python3
"""Route sampler voices through original DT2 balance after native mono output."""
from pathlib import Path
import argparse,json,re
import build_dt2_stereo_balance as P
import build_dn2_right_hooks as H
C,A,O=P.C,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dt2-stereo-balance-20261009/section_7.bin'
SHA='884090cfe905bb38fe49a35d640b66c13d54ee95bbd1cb3732da7cf0fc23d23b'
CODE,SAVE,CTX=0x179000,0x805db000,0x805db200
REGS=H.REGS


def source():
    def label(n):return f'.GLOBAL {n};\n{n}:\n'
    def jump(n,cond):return f'      {cond} JUMP 0x0; // -> {n}\n'
    s='.SECTION/PM seg_pmco;\n'+label('dt2_output.')
    for i,reg in enumerate(REGS):s+=f'      DM({SAVE+4*i:#x}) = {reg};\n'
    s+='      R0 = PASS R9;\n'+jump('dt2_output_restore.','IF EQ')
    for v in range(16):
        nxt=f'dt2_output_voice_{v}_done.'
        # Current per-physical-voice Machine ID; unlike render VALID, this
        # keeps the right filter/envelope tail connected after sample end.
        s+=f'''      R0 = DM({0x25c520+4*(v//2):#x});
      R0 = LSHIFT R0 BY {-16*(v%2)};
      R1 = 0xffff;
      R0 = R0 AND R1;
      R1 = 5;
      COMP(R0, R1);
'''+jump(nxt,'IF LT')+'''      R1 = 11;
      COMP(R0, R1);
'''+jump(nxt,'IF GE')+f'''      I4 = DM(-24, I6);
      R0 = DM({v}, I4);
      DM({CTX:#x}) = R0;
      R0 = {H.E.P.BUFFERS+128*v:#x};
      DM({CTX+4:#x}) = R0;
      I4 = DM(-30, I6);
      I4 = DM(3, I4);
      R0 = DM({2*v}, I4);
      DM({CTX+8:#x}) = R0;
      R0 = DM({2*v+1}, I4);
      DM({CTX+12:#x}) = R0;
      DM({CTX+16:#x}) = R9;
      R0 = DM(-29, I6);
      R1 = {0x230-0x1b4+v*0x234:#x};
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      DM({CTX+20:#x}) = R0;
      DM({CTX+24:#x}) = R0;
      R0 = DM(-1, I4);
      DM({CTX+28:#x}) = R0;
      DM({CTX+32:#x}) = R0;
      R0 = 0;
      DM({CTX+36:#x}) = R0;
      R0 = {P.STATE+4+56*v:#x};
      DM({CTX+40:#x}) = R0;
      R0 = I9;
      R1 = {0x1390c+4*(v//4):#x};
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      R0 = LSHIFT R0 BY {-8*(v%4)};
      R1 = 0xff;
      R0 = R0 AND R1;
      DM({CTX+44:#x}) = R0;
      R0 = I9;
      R1 = {0x1351c+44*v+20:#x};
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(0, I4);
      DM({CTX+48:#x}) = R0;
      R4 = {CTX:#x};
      CALL {P.CODE:#x};
'''+label(nxt)
    s+=label('dt2_output_restore.')
    order=[*(f'{bank}{i}' for bank in ('R','S','B','L','I','M') for i in range(16)), 'ASTATX','ASTATY','MODE1']
    for reg in order:s+=f'      {reg} = DM({SAVE+4*REGS.index(reg):#x});\n'
    s+='      M0 = DM(-57, I6);\n      M1 = DM(-56, I6);\n      JUMP 0x1c9b37;\n'
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==SHA
    asm=out/'output-hook.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'output-hook.doj').read_bytes()).items() if n.startswith('dt2_output')}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (dt2_output\w*\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(be));assert CODE+len(code)//2<0x17c000
    fixes=[]
    for offset in offsets:
        if offset+6>len(code):continue
        raw=C.S.to_value(code[offset:offset+6]);reg=(raw>>32)&0x7f
        if raw>>40 not in (0x10,0x11) or reg not in (0x70,0x73,0x74):continue
        new={0x70:0x72,0x73:0x76,0x74:0x77}[reg]
        code[offset:offset+6]=C.S.to_bytes((raw&~(0x7f<<32))|(new<<32));fixes.append(hex(CODE+offset//2))
    assert len(fixes)==6
    k=C.M.Digikit(C.SRC/'toolchains/digikit');m=k.ldr.LoadedMemory.from_stream(base);image=bytearray(base)
    before=m.read_sw(0x1c9b33,8);assert all(k.st.decode_at(m,None,p).length_bytes==4 for p in (0x1c9b33,0x1c9b35))
    after=C.S.to_bytes(0x063e00000000|CODE)+bytes(2);C.B.write_span(image,C.S.code_address(0x1c9b33),after)
    blocks=[(C.S.code_address(CODE),bytes(code)),(SAVE,bytes(0x300))]
    for at,data in blocks:assert not any(a<at+len(data) and at<a+len(b) for a,b in C.B.load_regions(base))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks));(out/'section_7.bin').write_bytes(image)
    doc=dict(section7_sha256=C.SHA(image),baseline_sha256=SHA,entry=hex(CODE),code_bytes=len(code),labels={n:hex(v) for n,v in labels.items()},preserved_registers=REGS,system_register_fixes=fixes,
             patch=dict(pc='0x1c9b33',before=before.hex(),after=after.hex()),
             contract='After original native mono output: overwrite only physical voices with Machine5..10, using independently processed left/right audio and original DT2 balance. Normalized DN2 pan+230 and level+22C; event1390C and AMP state+20; preserve99 registers, replay M0/M1 restores, resume original epilogue.',
             output_hook=True,flash_ready=False,remaining=['Focused mixed-voice output check','Full sample load/preview and Source/SLICE UI','Firmware integration and device playback'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n');print(json.dumps({key:doc[key] for key in ('section7_sha256','code_bytes')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
