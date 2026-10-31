#!/usr/bin/env python3
"""Snapshot Recorder controls before the native conditional audio-frame copy."""
from pathlib import Path
import argparse,json
import build_dt2_recorder_diagnostic_ownership as P
C,B,A,O,R=P.C,P.B,P.A,P.O,P.R
SITE,RESUME,CODE,SAVE=0x1c2872,0xbf55f6,0xbfa880,0x200f4348
SAVES={'I0':SAVE,'I4':SAVE+4,'L4':SAVE+8}


def build(parent,out):
    raw=(parent/'section_7.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
    assert C.SHA(raw)==doc['section7_sha256'] and 'recorder_diagnostic_ownership' in doc
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    memory=B.decode_view(k,raw);before=memory.read_sw(SITE,6)
    assert before==C.S.to_bytes(0x063e00000000|RESUME),before.hex()
    # Native 1C2767 stores this received-frame pointer; the existing guard
    # reads the same stack slot even when it skips the large audio-data copy.
    # DAG registers have no SIMD companion. L4=0 prevents indexed wrapping;
    # no ALU operation can disturb the SV predicate used by the old guard.
    source='.SECTION/PM seg_pmco;\n'
    source+=''.join(f'      DM({a:#x}) = {r};\n' for r,a in SAVES.items())
    source+='      I4 = DM(-32, I6);\n      L4 = 0;\n      NOP;\n'
    for off in range(0,28,4):
        source+=f'      I0 = DM({(0xa80+off)//4:#x}, I4);\n      DM({R.WIRE+off:#x}) = I0;\n'
    source+=''.join(f'      {r} = DM({a:#x});\n' for r,a in SAVES.items())
    source+=f'      JUMP {RESUME:#x};\n'
    out.mkdir(parents=True,exist_ok=False);asm=out/'recorder-control-snapshot.asm';asm.write_text(source)
    obj,offsets=A._selas(asm,out);code=O.load_bytes(obj)
    physical=C.S.code_address(CODE,window='l2')
    assert physical==0x200f5100 and physical+len(code)<=0x200f5800
    assert SAVE+12<=0x200f4380
    blocks=[(SAVE,bytes(12)),(physical,code)];regions=C.B.load_regions(raw)
    for a,data in blocks:
        assert not any(a<b+len(body) and b<a+len(data) for b,body in regions),(hex(a),len(data))
    image=bytearray(raw);after=C.S.to_bytes(0x063e00000000|CODE)
    C.B.write_span(image,C.S.code_address(SITE),after)
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,data) for a,data in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=C.SHA(raw),section7_sha256=C.SHA(result),flash_ready=False)
    doc['recorder_control_snapshot']=dict(base=str(parent.resolve()/'section_7.bin'),base_sha256=C.SHA(raw),
        code=hex(CODE),physical=hex(physical),bytes=len(code),instruction_offsets=offsets,
        scratch=hex(SAVE),scratch_bytes=12,scratch_fields={r:hex(a) for r,a in SAVES.items()},
        hook=dict(site=hex(SITE),resume=hex(RESUME),before=before.hex(),after=after.hex()),
        source='DM(-32,I6) + 0xA80',wire=hex(R.WIRE),control_bytes=28,rx_buffers=['0x2c29d0','0x2c39d0'],
        contract='Snapshot the current received Recorder controls before the unchanged conditional native audio-data copy. Both native copy and skip paths deliver enable, close and parameter changes.',
        unchanged=['Existing native copy guard and 0xA80 copy length','All status flags, SIMD mode and universal registers','Existing post-copy Recorder snapshot','USB frame size, audio arithmetic and diagnostic ownership gates'],
        limits=['Instruction execution checks do not model physical SPI or DMA timing.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=doc['section7_sha256'],code_bytes=len(code),scratch_bytes=12),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('parent',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.parent,a.out)
