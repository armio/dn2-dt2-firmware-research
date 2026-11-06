"""Reduce the native STRETCH inter-grain offset modulo the actual sample length."""
import argparse
import json
import re
from pathlib import Path

from build_dt2_dsp_stereo_rate_fix import A, B, C, O

PARENT_SHA = '65d2587813736e010ce23601f79da019b101a6d43c09b7487f341ad8a3fec3ce'
OUTPUT_SHA = '2b05931155bb097798e3f3926b1667f97629356baf78ee1c2efa294ce3a50c0e'
SITE, RESUME, CODE = 0xbc87aa, 0xbc87ae, 0xbcb0a0


def build(parent, out):
    raw = parent.read_bytes()
    doc = json.loads((parent.parent/'build-receipt.json').read_text())
    if C.SHA(raw) != PARENT_SHA or doc['section7_sha256'] != PARENT_SHA:
        raise ValueError('wrong parent DSP')
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    displaced = memory.read_sw(SITE, 8)
    if displaced.hex() != '089d7b00089a7e01':
        raise ValueError('unexpected native grain-offset store')
    out.mkdir(parents=True, exist_ok=True)
    # R1:R0 contains the signed Q31 grain offset. R15:R14 is the full
    # integral sample length in Q31. All work registers below are overwritten
    # by the native path before they are consumed. The 31 fractional bits stay
    # exact. Binary remainder takes at most 32 iterations, once per block.
    source = '''.SECTION/PM seg_pmco;
      R2 = LSHIFT R0 BY -31;
      R3 = LSHIFT R1 BY 1;
      R2 = R2 OR R3;
      R4 = LSHIFT R14 BY -31;
      R3 = LSHIFT R15 BY 1;
      R4 = R4 OR R3;
      COMP(R4, R9);
      IF LE JUMP 0x0; // -> done.
      R3 = R2;
      COMP(R2, R9);
      IF LT R3 = -R3;
      COMPU(R3, R4);
      IF LT JUMP 0x0; // -> done.
      R7 = LEFTZ R4;
      R8 = LEFTZ R3;
      R7 = R7 - R8;
      R8 = LSHIFT R4 BY R7;
.GLOBAL remainder.;
remainder.:
      COMPU(R3, R8);
      IF GE R3 = R3 - R8;
      R8 = LSHIFT R8 BY -1;
      R7 = R7 - 1;
      COMP(R7, R9);
      IF GE JUMP 0x0; // -> remainder.
      COMP(R2, R9);
      IF GE JUMP 0x0; // -> pack.
      COMP(R3, R9);
      IF NE R3 = R4 - R3;
.GLOBAL pack.;
pack.:
      R4 = 0x7fffffff;
      R0 = R0 AND R4;
      R4 = LSHIFT R3 BY 31;
      R0 = R0 OR R4;
      R1 = LSHIFT R3 BY -1;
.GLOBAL done.;
done.:
      DM(-5, I6) = R0;
      R2 = DM(-2, I5);
      JUMP 0xbc87ae;
'''
    asm = out/'stretch-span.asm'
    asm.write_text(source)
    _, offsets = A._selas(asm, out)
    labels = {name:CODE+value for name,value in O.symbols((out/'stretch-span.doj').read_bytes()).items()}
    source = re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',
                    lambda m: m[1]+hex(labels[m[3]])+m[2], source)
    asm.write_text(source)
    be, again = A._selas(asm, out)
    if offsets != again:
        raise ValueError('unstable instruction widths')
    code = O.load_bytes(be)
    # Copy exact native compact memory op encodings into the replay.
    replay = 2*(labels['done.']-CODE)
    if len(code)-replay != 14:
        raise ValueError('unexpected replay size')
    code = code[:replay] + displaced + code[replay+8:]
    physical = C.S.code_address(CODE, window='l2')
    if any(a < physical+len(code) and physical < a+len(v)
           for a,v in C.B.load_regions(raw)):
        raise ValueError('DSP helper overlaps loaded storage')
    patch = C.S.to_bytes(0x063e00000000 | CODE) + b'\x01\x00'
    image = bytearray(raw)
    C.B.write_span(image, C.S.code_address(SITE, window='l2'), patch)
    result = C.B.insert_before_final(bytes(image), C.B.block(physical,code))
    walk = C.B.walk(result)
    first,last = walk.blocks[7],walk.blocks[-1]
    result = result[:first.offset]+C.B.block(first.target,flags=first.flags,
              argument=last.offset-first.offset)+result[first.end:]
    if not C.B.walk(result).complete:
        raise ValueError('incomplete DSP load stream')
    doc.update(section7_sha256=C.SHA(result),baseline_sha256=PARENT_SHA)
    doc['dsp_stretch_span_fix'] = dict(site=hex(SITE),resume=hex(RESUME),
        before=displaced.hex(),after=patch.hex(),code=hex(CODE),physical=hex(physical),
        code_bytes=len(code),instruction_offsets=offsets,
        labels={name:hex(value) for name,value in labels.items()})
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    return doc['section7_sha256']


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('parent',type=Path);parser.add_argument('out',type=Path)
    args=parser.parse_args()
    print(build(args.parent,args.out))
