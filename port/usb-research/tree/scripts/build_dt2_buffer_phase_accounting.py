#!/usr/bin/env python3
"""Account for consumed, skipped audio notifications on exact R003; offline only."""
from pathlib import Path
import argparse
import json

import build_dt2_codec_stage_commit as P

C = P.C
BASE = C.ROOT / 'output/dn2-research/recorder-stable-backport-20261031/dsp/section_7.bin'
BASE_SHA = 'c03f91a0ebda33b22a2c71432ccba4069d9155523d7ebe1751b0bfc4fedfcda8'
SITE, RESUME, CODE = 0xbf043d, 0xbf0440, 0xbf0540
PHASE = 0x268a38
BEFORE = 0x1101200e1220
# All encodings are copied from audited native/installed instructions. The
# observer has already saved R0/R1/R2 and status and disabled SIMD. Its unsigned
# count > 1 branch is the only caller. Native wait consumed exactly one event.
WORDS = (BEFORE, 0x100000268a38, 0x023e00320020,
         0x110200268a38, 0x063e00000000 | RESUME)
ASM = '''.SECTION/PM seg_pmco;
phase_skip_entry:
    DM(0x200e1220) = R1; // displaced backlog-counter store
    R0 = DM(0x268a38);
    R2 = BTGL R0 BY 0;
    DM(0x268a38) = R2; // one consumed skipped notification, one phase advance
    JUMP 0xbf0440; // existing full restore and unchanged native dispatch
'''


def build(out):
    raw = BASE.read_bytes()
    if C.SHA(raw) != BASE_SHA:
        raise ValueError('requires exact R003 DSP')
    doc = json.loads(BASE.with_name('build-receipt.json').read_text())
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    m = P.B.decode_view(k, raw)
    guards = {SITE: BEFORE, 0xbf0435: 0x060400bf0440,
              0xbf0457: 0x023e00320020, 0x1c9fee: 0x063e00bf2cfc}
    for pc, word in guards.items():
        if m.read_sw(pc, 6) != C.S.to_bytes(word):
            raise ValueError(f'unsupported scheduler at {pc:#x}')
    code = b''.join(C.S.to_bytes(w) for w in WORDS)
    physical = C.S.code_address(CODE, window='l2')
    if any(physical < a+len(v) and a < physical+len(code)
           for a, v in C.B.load_regions(raw)):
        raise ValueError('phase code overlaps an existing loaded region')
    patch = C.S.to_bytes(0x063e00000000 | CODE)
    image = bytearray(raw)
    C.B.write_span(image, C.S.code_address(SITE, window='l2'), patch)
    result = C.B.insert_before_final(bytes(image), C.B.block(physical, code))
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    result = (result[:first.offset] + C.B.block(first.target, flags=first.flags,
              argument=last.offset-first.offset) + result[first.end:])
    if not C.B.walk(result).complete:
        raise ValueError('incomplete DSP loader stream')
    doc.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    doc['buffer_phase_accounting'] = dict(
        base=str(BASE), base_sha256=BASE_SHA, code=hex(CODE),
        code_physical=hex(physical), code_bytes=len(code),
        instruction_offsets=list(range(0, len(code), 6)),
        hooks=[dict(site=hex(SITE), before=C.S.to_bytes(BEFORE).hex(),
                    after=patch.hex(), entry=hex(CODE), resume=hex(RESUME))],
        phase=hex(PHASE), new_data_bytes=0,
        contract='Advance shared audio phase once after each consumed unsigned >1 '
                 'notification; counts 0/1 retain native behavior. Existing invalidation, '
                 'register/SIMD restore, native dispatch and control-frame ordering remain.',
        unchanged=['DMA descriptors/configuration and callback', 'codec staging and ownership checks',
                   'normal and special render completion', 'SPI control/reply selector',
                   'ColdFire USB collector and ring'],
        limits=['Logical phase accounting does not bound task/IRQ latency or recover lost hardware interrupts.',
                'Hardware audio validation remains required; no claim that all USB artifacts are fixed.'])
    out.mkdir(parents=True, exist_ok=False)
    (out/'phase-accounting.asm').write_text(ASM)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(ok=True, section7_sha256=C.SHA(result), code_bytes=len(code),
                          new_data_bytes=0, hook=hex(SITE)), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    build(p.parse_args().out)
