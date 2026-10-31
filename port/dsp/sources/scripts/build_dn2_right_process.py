#!/usr/bin/env python3
"""Native DN2 effects-only block processor for independent right audio."""
from pathlib import Path
import argparse,json,struct
import build_dn2_right_engine as E
C,B,A,O=E.C,E.B,E.P.A,E.P.O
BASE=C.ROOT/'output/dn2-research/dn2-right-engine-20261009/section_7.bin'
SHA='57fd34521bc1a546bf590514e7aa8714f6f3f4dec3949e7807a7535bdadb90c8'
LO,HI,CODE=0x1c8ef1,0x1c9c5d,0x175000
BRIDGE,RETURN=0x175e00,0x175e40
TABLE_OLD,TABLE,TABLE_SIZE=0x8052db90,0x805d9400,0x4c
STOCK=C.ROOT/'firmware/dn2-1.11/section_7_blob.bin'


def mapped(v,*,required=False):
    if LO<=v<HI:return CODE+v-LO
    if TABLE_OLD<=v<TABLE_OLD+TABLE_SIZE:return TABLE+v-TABLE_OLD
    return v


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    base=BASE.read_bytes();assert C.SHA(base)==SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');m=k.ldr.LoadedMemory.from_stream(STOCK.read_bytes())
    code,changes,listing=B.relocate(k,m,LO,HI,CODE,mapper=mapped)
    code=bytearray(code);patches=[]
    # Preserve native parameter, filter, AMP and envelope state updates.
    # Suppress only synth setters and oscillator generation; input is already
    # rendered by the paired sampler. Final pan/mix belongs to DT2's matrix.
    for name,pc,source in [
        ('skip-synth-setters',0x1c909f,f'JUMP {mapped(0x1c90d4):#x} (DB);'),
        ('skip-oscillator-render',0x1c93cd,f'JUMP {BRIDGE:#x};'),
        ('return-before-mono-pan',0x1c9ad6,f'JUMP {RETURN:#x};')]:
        asm=out/(name+'.asm');asm.write_text('.SECTION/PM seg_pmco;\n'+source+'\n')
        be,_=A._selas(asm,out);raw=O.load_bytes(be);assert len(raw)==6
        offset=2*(pc-LO);before=bytes(code[offset:offset+6]);code[offset:offset+6]=raw
        patches.append(dict(name=name,pc=hex(pc),target=hex(mapped(pc)),before=before.hex(),after=raw.hex()))
    stubs=[]
    for name,at,source in [('effects-entry',BRIDGE,f'''R13 = 16;
      I5 = DM(-24, I6);
      R10 = DM(-34, I6);
      JUMP {mapped(0x1c944c):#x};'''),('effects-return',RETURN,f'''I12 = DM(M7, I6);
      JUMP {mapped(0x1c9b33):#x};''')]:
        asm=out/(name+'.asm');asm.write_text('.SECTION/PM seg_pmco;\n'+source+'\n')
        be,_=A._selas(asm,out);stubs.append((C.S.code_address(at),O.load_bytes(be)))
    table=m.read(TABLE_OLD,TABLE_SIZE)
    values=struct.unpack('<19I',table);assert all(LO<=x<HI for x in values)
    table=struct.pack('<19I',*(mapped(x) for x in values))
    blocks=[(C.S.code_address(CODE),bytes(code)),*stubs,(TABLE,table)]
    placed=[]
    for at,raw in blocks:
        assert not any(a<at+len(raw) and at<a+len(b) for a,b in (*C.B.load_regions(base),*placed))
        placed.append((at,raw))
    image=C.B.insert_before_final(base,b''.join(C.B.block(a,b) for a,b in blocks))
    (out/'section_7.bin').write_bytes(image)
    (out/'native-process.asm').write_text('\n'.join(listing)+'\n')
    doc=dict(section7_sha256=C.SHA(image),baseline_sha256=SHA,stock_sha256=C.SHA(STOCK.read_bytes()),entry=hex(CODE),bytes=len(code),relocations=changes,patches=patches,
             tables=dict(source=hex(TABLE_OLD),target=hex(TABLE),entries=[hex(x) for x in values]),
             contract='Linked native ABI R4=right engine, R8=16 native parameter records, R12=runtime I/O descriptor. Input right audio is already rendered and sample-level processed. Native effects modify each buffer in place; no output mixing. Engine must be initialized separately.',
             hook_installed=False,flash_ready=False,remaining=['Audio-thread startup/block/reset routing','Native DT2 stereo pan/output','Host sample allocator/load/preview','Source/SLICE UI and firmware integration'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps({key:doc[key] for key in ('section7_sha256','entry','bytes','patches')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
