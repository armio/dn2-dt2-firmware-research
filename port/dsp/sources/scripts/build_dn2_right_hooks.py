#!/usr/bin/env python3
"""Wire independent right effects into native initialization and block flow."""
from pathlib import Path
import argparse,json,re
import build_dn2_right_process as P
C,E,A,O=P.C,P.E,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dn2-right-process-20261009/section_7.bin'
SHA='b1fada0dc36938f83eede4970e68acbef415eeeda8a5abf8f9d4879d83319dd6'
CODE,STATE,READY=0x176000,0x805d9600,0x805d9800
REGS=[*(f'{bank}{i}' for bank in ('R','S','I','M','B','L') for i in range(16)), 'ASTATX','ASTATY','MODE1']
# Two arrays of16 floats followed by six arrays of16 byte events.
CONTROL_OFFSET,CONTROL_SIZE=0x1387c,0xe0


def source():
    def label(n):return f'.GLOBAL {n};\n{n}:\n'
    def save():return ''.join(f'      DM({STATE+4*i:#x}) = {reg};\n' for i,reg in enumerate(REGS))
    # A B-register load also loads its I register (PRM6-24). Restore bases
    # before indices even though the pinned runner omits that side effect.
    def restore():
        order=[*(f'{bank}{i}' for bank in ('R','S','B','L','I','M') for i in range(16)), 'ASTATX','ASTATY','MODE1']
        return ''.join(f'      {reg} = DM({STATE+4*REGS.index(reg):#x});\n' for reg in order)
    def jump(n,cond=''):return f'      {cond}JUMP 0x0; // -> {n}\n'
    def linked(target,labelname):return E.P.V.linked(target,labelname)
    s='.SECTION/PM seg_pmco;\n'+label('native_right_startup.')+save()
    s+=f'''      R0 = I7;
      R1 = -4;
      R0 = R0 + R1;
      I7 = R0;
      R0 = DM(1, I6);
      DM(I7, M7) = R0;
      R4 = {E.ENGINE:#x};
      R8 = {E.PARAMS:#x};
      R12 = {E.CONFIG:#x};
'''+linked(E.INIT,'native_right_initialized.')
    s+=f'      R0 = 1;\n      DM({READY:#x}) = R0;\n'+restore()+'      JUMP 0x1c8e1c;\n'
    s+=label('native_right_block.')+save()+f'''      R0 = DM({READY:#x});
      R0 = PASS R0;
'''+jump('native_right_restore.','IF EQ ')
    # Copy only pitch/note/event inputs. Filter, AMP, envelope and pan histories
    # remain independent. This happens before the left chain consumes events.
    s+=f'''      R0 = I9;
      R1 = {CONTROL_OFFSET:#x};
      R0 = R0 + R1;
      I4 = R0;
      I5 = {E.ENGINE+CONTROL_OFFSET:#x};
'''
    for i in range(CONTROL_SIZE//4):s+=f'      R0 = DM({i}, I4);\n      DM({i}, I5) = R0;\n'
    # No new sample block on a physical voice must not reuse stale right PCM.
    for v in range(16):
        nxt=f'native_right_voice_{v}_ready.'
        s+=f'      R0 = DM({E.P.VALID+4*v:#x});\n      R0 = PASS R0;\n'+jump(nxt,'IF NE ')
        s+=f'      I4 = {E.P.BUFFERS+v*128:#x};\n      R0 = 0;\n'
        for i in range(32):s+=f'      DM({i}, I4) = R0;\n'
        s+=label(nxt)
    s+=f'''      R4 = {E.ENGINE:#x};
      R8 = DM(-29, I6);
      R0 = -436;
      R8 = R8 + R0;
      R12 = DM(-30, I6);
'''+linked(P.CODE,'native_right_processed.')
    s+=label('native_right_restore.')+restore()+'''      R14 = 20;
      R15 = 16;
      JUMP 0x1c9450;
'''
    return s


def build(out):
    out.mkdir(parents=True,exist_ok=False);base=BASE.read_bytes();assert C.SHA(base)==SHA
    asm=out/'right-hooks.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'right-hooks.doj').read_bytes()).items() if n.startswith('native_')}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    s=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (native_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
    code=bytearray(O.load_bytes(be));assert CODE+len(code)//2<0x177000
    # Selas uses legacy system-register numbers. SHARC+ PRM27-16 specifies
    # MODE1=0x72, ASTATX=0x76, ASTATY=0x77. Correct only these explicit Type14a
    # saves/restores; the ordinary R/S/DAG codes already match SHARC+.
    system_fixes=[]
    for offset in offsets:
        if offset+6>len(code):continue
        value=C.S.to_value(code[offset:offset+6])
        if value>>40 not in (0x10,0x11):continue
        old=(value>>32)&0x7f
        if old not in (0x70,0x73,0x74):continue
        new={0x70:0x72,0x73:0x76,0x74:0x77}[old]
        code[offset:offset+6]=C.S.to_bytes((value&~(0x7f<<32))|(new<<32))
        system_fixes.append(dict(pc=hex(CODE+offset//2),before=old,after=new))
    assert len(system_fixes)==12
    k=C.M.Digikit(C.SRC/'toolchains/digikit');m=k.ldr.LoadedMemory.from_stream(base)
    image=bytearray(base);patches=[]
    old=k.st.decode_at(m,None,0x1c14ab);assert C.S.get_field(old.raw,'addr24')==0x1c8e1c
    replacement=C.S.to_bytes(C.S.retarget(old.raw,'addr24',0x1c14ab,labels['native_right_startup.']))
    C.B.write_span(image,C.S.code_address(0x1c14ab),replacement)
    patches.append(dict(pc='0x1c14ab',before=C.S.to_bytes(old.raw).hex(),after=replacement.hex()))
    old=m.read_sw(0x1c944c,8)
    assert k.st.decode_at(m,None,0x1c944c).length_bytes==4 and k.st.decode_at(m,None,0x1c944e).length_bytes==4
    replacement=C.S.to_bytes(0x063e00000000|labels['native_right_block.'])+bytes(2)
    C.B.write_span(image,C.S.code_address(0x1c944c),replacement)
    patches.append(dict(pc='0x1c944c',before=old.hex(),after=replacement.hex()))
    blocks=[(C.S.code_address(CODE),bytes(code)),(STATE,bytes(0x204))]
    for at,data in blocks:assert not any(a<at+len(data) and at<a+len(b) for a,b in C.B.load_regions(base))
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image)
    doc=dict(section7_sha256=C.SHA(image),baseline_sha256=SHA,entry=hex(CODE),code_bytes=len(code),labels={n:hex(v) for n,v in labels.items()},patches=patches,
             preserved_registers=REGS,sharc_plus_system_register_bindings=system_fixes,control_copy=dict(offset=hex(CONTROL_OFFSET),bytes=CONTROL_SIZE),
             contract='Serialized scalar native audio thread. Initialize right state then tail original native constructor. At post-sampler/pre-effects boundary copy pitch/note/events, clear inactive right buffers, process native right FX once, restore live registers and resume left FX.',
             startup_hook=True,block_hook=True,output_hook=False,flash_ready=False,
             remaining=['Composed playback/event check','DT2 stereo pan/output','Host allocator/load/preview','Source/SLICE UI and firmware'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n');print(json.dumps({k:doc[k] for k in ('section7_sha256','code_bytes','patches')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
