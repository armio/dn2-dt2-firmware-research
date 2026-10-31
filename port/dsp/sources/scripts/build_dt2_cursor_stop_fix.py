#!/usr/bin/env python3
"""Hide stale sample cursors once the native DN2 AMP voice is fully idle."""
from pathlib import Path
import argparse, json, re
import build_dt2_dsp_stereo_rate_fix as Q
C, B, A, O = Q.C, Q.B, Q.A, Q.O
BASE = C.ROOT/'output/dn2-research/dt2-dsp-stretch-rate-fix-20261010/section_7.bin'
SHA = '99d3e909eb1c423a60933f1eaeff27a617358c475e296444a096956196017bf0'
CODE, SITE, RESUME, EPILOGUE = 0xbf6600, 0xbe8813, 0xbe8816, 0xbe8836
AMP = 0x2547a0


def build(out):
    raw = BASE.read_bytes(); assert C.SHA(raw) == SHA
    doc = json.loads((BASE.parent/'build-receipt.json').read_text())
    k = C.M.Digikit(C.SRC/'toolchains/digikit'); k.ldr.L2_BYTE_LIMIT = 0x20100000
    m = B.decode_view(k, raw)
    displaced = m.read_sw(SITE, 6)
    assert displaced == C.S.to_bytes(0xa80f00000063)
    # R13/R14/R15 have already been saved by the original linked getter.
    # R4 is the physical voice. R14 can retain I4 until native length loading.
    source = f'''.SECTION/PM seg_pmco;
.GLOBAL cursor_amp_idle.;
cursor_amp_idle.:
      R14 = I4;
      R0 = LSHIFT R4 BY 5;
      R1 = LSHIFT R4 BY 3;
      R0 = R0 + R1;
      R1 = LSHIFT R4 BY 2;
      R0 = R0 + R1;
      R1 = {AMP:#x};
      R0 = R0 + R1;
      I4 = R0;
      R0 = DM(7, I4);
      R1 = 5;
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> original_position.
      R0 = DM(10, I4);
      R1 = 0x7fffffff;
      R0 = R0 AND R1;
      R0 = PASS R0;
      IF NE JUMP 0x0; // -> original_position.
      // Finished native fade, including either representation of zero.
      // Keep sample phase/ACTIVE and AMP records completely unchanged.
      R12 = -1;
      I4 = R14;
      JUMP {EPILOGUE:#x};
.GLOBAL original_position.;
original_position.:
      I4 = R14;
      R15 = DM(99, I4);
      JUMP {RESUME:#x};
'''
    out.mkdir(parents=True, exist_ok=False)
    asm = out/'cursor-stop.asm'; asm.write_text(source)
    be, offsets = A._selas(asm, out)
    labels = {n:CODE+v for n,v in O.symbols((out/'cursor-stop.doj').read_bytes()).items()
              if n in ('cursor_amp_idle.', 'original_position.')}
    source = re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))', lambda x:x[1]+hex(labels[x[3]])+x[2], source)
    asm.write_text(source); be, again = A._selas(asm, out); assert again == offsets
    code = O.load_bytes(be)
    physical = C.S.code_address(CODE, window='l2')
    assert physical + len(code) <= 0x20100000
    assert not any(a < physical+len(code) and physical < a+len(v) for a,v in C.B.load_regions(raw))
    patch = C.S.to_bytes(0x063e00000000 | CODE)
    image = bytearray(raw); C.B.write_span(image, C.S.code_address(SITE, window='l2'), patch)
    result = C.B.insert_before_final(bytes(image), C.B.block(physical, code))
    walk = C.B.walk(result); first, last = walk.blocks[7], walk.blocks[-1]
    result = result[:first.offset]+C.B.block(first.target, flags=first.flags, argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=SHA, section7_sha256=C.SHA(result), flash_ready=False)
    doc['cursor_stop_fix'] = dict(base=str(BASE), base_sha256=SHA,
        code=hex(CODE), code_physical=hex(physical), code_bytes=len(code),
        labels={n:hex(v) for n,v in labels.items()}, instruction_offsets=offsets,
        hook=dict(site=hex(SITE), resume=hex(RESUME), epilogue=hex(EPILOGUE), before=displaced.hex(), after=patch.hex()),
        native_amp=dict(base=hex(AMP), stride=44, stage_offset=28, gain_offset=40, idle_stage=5),
        criterion='stage == 5 and (gain_bits & 0x7fffffff) == 0',
        native_evidence=dict(constructor='0xb8030c: stage+28=5, gain+40=0',
            fade='0xb804c2..0xb804ee: stage5 linearly fades to zero over a block',
            release='0xb804f1..0xb8051b: stage4 decay remains visible',
            order='native engine call1c3044 completes before cursor publisher1c309a'),
        contract='Display-only. Original sample position retained for every non-idle AMP state; no audio, sampler, envelope, transport, or allocation state is written.',
        limits=['Physical STOP and stopped-transport keyboard confirmation pending.'])
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), code_bytes=len(code), hook=doc['cursor_stop_fix']['hook'])))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--out', type=Path, required=True)
    build(p.parse_args().out)
