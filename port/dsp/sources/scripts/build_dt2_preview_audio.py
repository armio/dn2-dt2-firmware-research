#!/usr/bin/env python3
"""Connect the original DT2 independent stereo browser audition to DN2 output."""
from pathlib import Path
import argparse,json,re
import build_dt2_cursor_stop_fix as P
import build_dt2_pcm_receiver as N
import build_dt2_voice_samples as V
import build_dn2_right_hooks as H
C,B,A,O=P.C,P.B,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-cursor-idle-stage-fix-20261010/section_7.bin'
SHA='d374e650fd30fa61c5946b78ac52ed6cc532ed58d06dc9f17006e7d63c3f8294'
AUDITION,RENDER,BRIDGE=0xbf6800,0xbf6a00,0xbf6d00
RECORDS,BUFFERS,SAVE,FLAGS=0x200ef000,0x200ef400,0x200ef600,0x200ef800
SITE,RESUME=0x1c309a,0xbe8a00
WIRE=0x25c4b6
REGS=H.REGS
SPANS=(('audition',0x1c29fd,0x1c2b24,AUDITION),('preview-render',0x1c5334,0x1c5576,RENDER))
EXTERNAL={0x1c3f78:0xbca800,0x1c4afe:0xbc80cd,0x1c4e70:0xbcb000,0x1c4eaf:0xbcb03f}


def mapped(v,*,required=False):
    for _,lo,hi,to in SPANS:
        if lo<=v<hi:return to+v-lo
    if 0x252730<=v<0x252ae0:return RECORDS+v-0x252730
    if 0x2560e0<=v<0x2561e0:return BUFFERS+v-0x2560e0
    if v in EXTERNAL:return EXTERNAL[v]
    if required:raise ValueError(f'Unbound preview target {v:#x}')
    return v


def source():
    s='.SECTION/PM seg_pmco;\n.GLOBAL preview_bridge.;\npreview_bridge.:\n'
    for i,reg in enumerate(REGS):s+=f'      DM({SAVE+4*i:#x}) = {reg};\n'
    # Audition owns both scratch channels. Clear every word before the native
    # inactive path; this cannot affect its fully written active output.
    s+=f'      I4 = {BUFFERS:#x};\n      R0 = 0;\n'
    for i in range(64):s+=f'      DM({i}, I4) = R0;\n'
    s+=f'''      // CF event8 packs native start, stop, metadata booleans in free header+2A.
      R0 = DM({WIRE-2:#x});
      R0 = LSHIFT R0 BY -16;
      R1 = 1;
      R2 = R0 AND R1;
      R3 = LSHIFT R0 BY -1;
      R3 = R3 AND R1;
      R3 = LSHIFT R3 BY 16;
      R2 = R2 OR R3;
      DM({FLAGS:#x}) = R2;
      R0 = LSHIFT R0 BY -2;
      R0 = R0 AND R1;
      DM({FLAGS+4:#x}) = R0;
      // Same point as DT2: add audition after main mix/gain, before final output.
      R4 = DM(-25, I6);
      R8 = {FLAGS-0x7f6:#x};
'''+V.linked(AUDITION,'preview_mixed.')
    # Publishing follows the native audition's completed render and retains
    # the stock reply fields around its reserved preview-state word.
    s+=f'''      R0 = DM({RECORDS+0x1b8:#x});
      R1 = DM({RECORDS+472+0x1b8:#x});
      R0 = R0 OR R1;
      R1 = 0xff;
      R0 = R0 AND R1;
      I4 = DM(1, I6);
      R1 = DM(6, I4);
      R2 = 0xffff0000;
      R1 = R1 AND R2;
      R0 = R0 OR R1;
      DM(6, I4) = R0;
'''
    order=[*(f'{bank}{i}' for bank in ('R','S','B','L','I','M') for i in range(16)), 'ASTATX','ASTATY','MODE1']
    for reg in order:s+=f'      {reg} = DM({SAVE+4*REGS.index(reg):#x});\n'
    s+=f'      JUMP {RESUME:#x};\n'
    return s


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    donorraw=C.DONOR.read_bytes();assert C.SHA(donorraw)==C.DONOR_SHA
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    m=B.decode_view(k,raw);donor=k.ldr.LoadedMemory.from_stream(donorraw)
    before=m.read_sw(SITE,6);assert before==C.S.to_bytes(0x063e00000000|RESUME)
    out.mkdir(parents=True,exist_ok=False);blocks=[];spans=[]
    for name,lo,hi,to in SPANS:
        code,changes,listing=N.relocate(k,donor,lo,hi,to,mapper=mapped)
        (out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
        (out/(name+'.bin')).write_bytes(code)
        blocks.append((C.S.code_address(to,window='l2'),code))
        spans.append(dict(name=name,donor=hex(lo),end=hex(hi),target=hex(to),bytes=len(code),bindings=changes))
    asm=out/'preview-bridge.asm';s=source();asm.write_text(s)
    be,offsets=A._selas(asm,out)
    labels={n:BRIDGE+v for n,v in O.symbols((out/'preview-bridge.doj').read_bytes()).items() if n.startswith('preview_')}
    s=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (preview_\w+\.))',lambda x:x[1]+hex(labels[x[3]]-1)+x[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(be));sysfix=[]
    for off in offsets:
        if off+6>len(code):continue
        ins=C.S.to_value(code[off:off+6]);reg=(ins>>32)&0x7f
        if ins>>40 not in (0x10,0x11) or reg not in (0x70,0x73,0x74):continue
        code[off:off+6]=C.S.to_bytes((ins&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));sysfix.append(hex(BRIDGE+off//2))
    assert len(sysfix)==6
    blocks.append((C.S.code_address(BRIDGE,window='l2'),bytes(code)))
    # Dedicated zero-initialized records: the donor bind/arm/setter fills all
    # playback state. None of the16 track sample/AMP/voice records is reused.
    blocks.append((RECORDS,bytes(0x808)))
    placed=[]
    for at,payload in blocks:
        assert 0x20000000<=at<at+len(payload)<=0x20100000
        assert not any(a<at+len(payload) and at<a+len(v) for a,v in (*C.B.load_regions(raw),*placed)),hex(at)
        placed.append((at,payload))
    after=C.S.to_bytes(0x063e00000000|BRIDGE)
    image=bytearray(raw);C.B.write_span(image,C.S.code_address(SITE),after)
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,v) for a,v in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['preview_audio_fix']=dict(base=str(BASE),base_sha256=SHA,donor_sha256=C.DONOR_SHA,spans=spans,
        code=hex(BRIDGE),code_bytes=len(code),instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},system_register_fixes=sysfix,
        hook=dict(site=hex(SITE),resume=hex(RESUME),before=before.hex(),after=after.hex()),
        wire=dict(frame_offset='0x2a',dsp=hex(WIRE),bits=dict(start=0,stop=1,metadata=2)),
        state=dict(records=hex(RECORDS),buffers=hex(BUFFERS),save=hex(SAVE),native_flags=hex(FLAGS),slot=1024,reply_offset='0x18'),
        preserved_registers=REGS,external_bindings={hex(a):hex(b) for a,b in EXTERNAL.items()},
        contract='Original DT2 dedicated stereo preview mixer and fixed32-frame renderer, driven by event8 independently of selected track, Machine, transport, or16voice allocation. Adds to native final stereo mix; retains native fade/start/metadata behavior.',
        remaining=['Focused native audition execution','Hardware FUNC+YES preview confirmation'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),native_code_bytes=sum(x['bytes'] for x in spans),bridge_bytes=len(code))))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
