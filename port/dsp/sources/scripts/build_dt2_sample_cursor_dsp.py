#!/usr/bin/env python3
"""Publish original DT2 sample-position words from DN2's physical voices."""
from pathlib import Path
import argparse, json, re
import build_dt2_recording_rpc as Q
import build_dt2_voice_samples as V
C, R, A, O = Q.C, Q.R, V.A, V.O
BASE = C.ROOT/'output/dn2-research/dt2-recording-rpc-20261009/section_7.bin'
SHA = 'c86540f7dd55518c0684b04edeafc33b3c0f694fd6a58afafb489ef914276268'
GETTER, DIVIDE, CODE = 0x190800, 0x190900, 0x190a00
STATE = 0x805de000
SITE, RESUME = 0x1c309a, 0x1c309e
RECORDS = 0x30e000
REGS = [*(f'R{i}' for i in range(16)), 'I4', 'I5', 'I6', 'I7', 'I12', 'ASTATX', 'ASTATY']
SPANS = (('position', 0x1c149b, 0x1c14e7, GETTER),
         ('division', 0xb88e4e, 0xb88f06, DIVIDE))


def mapped(v, *, required=False):
    for _,lo,hi,to in SPANS:
        if lo<=v<hi:return to+v-lo
    if v==0x2412cc:return RECORDS
    if v==0xb88e04:return 0xb8b4dc  # Verified native 32-bit division twin.
    if required:raise ValueError(hex(v))
    return v


def source():
    s='.SECTION/PM seg_pmco;\n.GLOBAL cursor_publish.;\ncursor_publish.:\n'
    s+=''.join(f'      DM({STATE+4*i:#x}) = {reg};\n' for i,reg in enumerate(REGS))
    # This is the native frame processor's first stack argument: its reply
    # page. Each word is packed16; the DT2 emits these through Type3d SW.
    s+='      I5 = DM(1, I6);\n      R0 = I5;\n      R1 = 0xa9c;\n      R0 = R0 + R1;\n      I5 = R0;\n'
    for voice in range(16):
        label=f'cursor_store_{voice}.'
        s+=f'''      R0 = DM({0x25c520+4*(voice//2):#x});
      R0 = LSHIFT R0 BY {-16*(voice%2)};
      R1 = 0xffff;
      R1 = R0 AND R1;
      R0 = -1;
      R2 = 5;
      COMPU(R1, R2);
      IF LT JUMP 0x0; // -> {label}
      R2 = 10;
      COMPU(R1, R2);
      IF GT JUMP 0x0; // -> {label}
      R4 = {voice};
'''+V.linked(GETTER,f'cursor_got_{voice}.')+f'''.GLOBAL {label};
{label}:
      DM(0x805de100) = R0; // replaced with original Type3d packed16 store
'''
    s+=''.join(f'      {reg} = DM({STATE+4*i:#x});\n' for i,reg in enumerate(REGS))
    return s


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==SHA
    out.mkdir(parents=True,exist_ok=False)
    k=C.M.Digikit(C.SRC/'toolchains/digikit')
    d=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());n=k.ldr.LoadedMemory.from_stream(raw)
    # The only external arithmetic leaf is fully byte-verified after mapping
    # its internal branches. The 64-bit routine itself is imported unchanged.
    leaf=lambda v,required=False: 0xb8b4dc+v-0xb88e04 if 0xb88e04<=v<0xb88e4e else mapped(v,required=required)
    body,_,_=R.relocate(k,d,0xb88e04,0xb88e4e,0xb8b4dc,mapper=leaf)
    assert n.read_sw(0xb8b4dc,len(body))==body
    blocks=[];spans=[]
    for name,lo,hi,to in SPANS:
        body,bindings,listing=R.relocate(k,d,lo,hi,to,mapper=mapped)
        blocks.append((C.S.code_address(to),body))
        spans.append(dict(name=name,donor=hex(lo),end=hex(hi),target=hex(to),bytes=len(body),bindings=bindings))
        (out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
    s=source();asm=out/'cursor-publish.asm';asm.write_text(s)
    be,offsets=A._selas(asm,out)
    labels={name:CODE+v for name,v in O.symbols((out/'cursor-publish.doj').read_bytes()).items() if name.startswith('cursor_')}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (cursor_\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],s)
    s=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (cursor_\w+\.))',lambda m:m[1]+hex(labels[m[3]]-1)+m[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
    code=bytearray(O.load_bytes(be));fixes=[]
    for off in offsets:
        if off+6>len(code):continue
        value=C.S.to_value(code[off:off+6]);reg=(value>>32)&0x7f
        if value>>40 not in (0x10,0x11) or reg not in (0x73,0x74):continue
        new={0x73:0x76,0x74:0x77}[reg]
        code[off:off+6]=C.S.to_bytes((value&~(0x7f<<32))|(new<<32));fixes.append(hex(CODE+off//2))
    assert len(fixes)==4
    # Selas silently narrows DM(...)=R0 (SW) to an ordinary Type3c store.
    # Use the exact original DT2 Type3d instruction, including its short-word
    # postincrement, and replay the displaced native loads byte-for-byte.
    packed=d.read_sw(0x1c313c,6)
    assert packed==C.S.to_bytes(0x5bbec0300000)
    for voice in range(16):
        off=2*(labels[f'cursor_store_{voice}.']-CODE)
        assert C.S.to_value(code[off:off+6])==0x1100805de100
        code[off:off+6]=packed
    old=n.read_sw(SITE,8)
    assert old==bytes.fromhex('089c700abe4b3d43'),old.hex()
    code.extend(old+C.S.to_bytes(0x063e00000000|RESUME))
    assert CODE+len(code)//2<0x191000
    blocks.extend([(C.S.code_address(CODE),bytes(code)),(STATE,bytes(4*len(REGS)))])
    regions=C.B.load_regions(raw)
    for at,body in blocks:
        assert not any(a<at+len(body) and at<a+len(b) for a,b in regions),hex(at)
        regions.append((at,body))
    # Fixed native frame boundary, outside its hardware loops, after rendering.
    after=C.S.to_bytes(0x063e00000000|CODE)+bytes(2)
    image=bytearray(raw);C.B.write_span(image,C.S.code_address(SITE),after)
    image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(image),flash_ready=False)
    doc['sample_cursor']=dict(spans=spans,entry=hex(CODE),code_bytes=len(code),
        labels={k:hex(v) for k,v in labels.items()},preserved_registers=REGS,
        system_register_fixes=fixes,patch=dict(site=hex(SITE),before=old.hex(),after=after.hex()),
        voices=16,record_base=hex(RECORDS),reply_offset='0xa9c',word_bytes=2,
        track_mapping_connected=False,
        remaining=['Map physical-voice telemetry to the selected UI track using native allocation state.',
                   'Complete MAIN/DSP/FS composition and hardware validation.'])
    (out/'section_7.bin').write_bytes(image)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=doc['section7_sha256'],cursor=doc['sample_cursor']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
