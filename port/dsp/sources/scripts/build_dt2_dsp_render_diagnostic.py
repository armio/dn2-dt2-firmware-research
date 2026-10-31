#!/usr/bin/env python3
"""Add inner render checkpoints to the T1D9 D907 hardware freeze.

Only scalar universal moves and non-delayed jumps are added. The checkpoints use the
existing two DSP reply pages and leave their heartbeat, entry counter and
native word at offset 0x14 untouched. This is instrumentation, not a fix.
"""
from pathlib import Path
import argparse
import json

import build_dt2_dsp_startup_fix as B

C = B.C
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-playback-diagnostic-20261010/section_7.bin'
BASE_SHA = '38fd9e115ec7e3d55d0bdb8949210c6d3393b51cf0dd648347347592d31e3c53'
CODE = 0xbf2000  # Physical 0x200e4000; fatal diagnostic owns 0x200e2000.
SAVE = 0x200e5000
PAGES = (0x2c49d0, 0x2c59d0)
HOOKS = (
    (1, 'right-call-arguments-ready', 0xbcb72e, 0x1108200aa618, ('R4', 'R8', 'R12')),
    (2, 'native-render-entry', 0x185000, 0x1587ffffffe6, ('MODE1', 'I6', 'I7')),
    (3, 'forward-resampling-loop-preparation', 0x1851c1, 0x1601000001bb, ('MODE1', 'I0', 'L3')),
    (4, 'reverse-resampling-loop-preparation', 0x1853d6, 0x1602000001bb, ('MODE1', 'I0', 'L3')),
    (5, 'right-render-returned', 0xbcb738, 0x10000030dc94, ('I6', 'I7', 'M7')),
)


def ureg_copy(source, destination=16):
    """Unconditional Type5a universal copy, with an empty compute field."""
    return (0x700000000000 | ((source >> 2) << 38) | (31 << 33)
            | ((source & 3) << 31) | (destination << 23))

def build(out, *, replace=False):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    receipt = json.loads((BASE.parent / 'build-receipt.json').read_text())
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    image = bytearray(raw)
    code = bytearray()
    hooks = []
    # Copy to the scalar DAG register before publishing: direct Rn stores
    # have implicit SIMD companions. No instruction writes status or MODE1.
    for checkpoint, name, site, expected, registers in HOOKS:
        ins = k.st.decode_at(memory, None, site)
        assert ins.length_bytes == 6 and ins.raw == expected, (hex(site), hex(ins.raw))
        entry = CODE + len(code) // 2
        body = []
        # I0 is a universal DAG register without a SIMD complement. R0 would
        # also transfer S0 under MODE1.SSE and corrupt adjacent reply cells.
        body.append(0x111000000000 | SAVE)  # DM(SAVE) = I0
        for offset, register in zip((12, 16, 24), registers):
            if register == 'I0':
                body.append(0x101000000000 | SAVE)
            else:
                body.append(ureg_copy(k.st.UREG_CODES[register]))
            body.extend(0x111000000000 | (page + offset) for page in PAGES)
        marker = 0x4f53da00 | checkpoint
        raw_marker = ((marker << 16) | (marker >> 16)) & 0xffffffff
        body.append(0x0f1000000000 | raw_marker)  # I0 = raw marker
        body.extend(0x111000000000 | (page + 4) for page in PAGES)
        body.append(0x101000000000 | SAVE)  # I0 = DM(SAVE)
        marker_bytes = len(body) * 6
        body.append(expected)  # Replay the original instruction exactly.
        body.append(0x063e00000000 | (site + 3))
        emitted = b''.join(C.S.to_bytes(word) for word in body)
        code.extend(emitted)
        target = C.S.code_address(site, window='l2') if site >= 0xb80000 else C.S.code_address(site)
        C.B.write_span(image, target, C.S.to_bytes(0x063e00000000 | entry))
        hooks.append(dict(checkpoint=checkpoint, name=name, site=hex(site),
                          entry=hex(entry), replay=hex(entry + marker_bytes // 2),
                          resume=hex(site + 3), before_instruction=hex(expected),
                          marker=hex(marker), raw_dsp_marker=hex(raw_marker),
                          bytes=len(emitted), added_instructions_max=len(body),
                          payload=[dict(cf_word=word, register=reg, decode='swap16(CF big-endian word)')
                                   for word, reg in zip((3, 4, 6), registers)]))
    physical = C.S.code_address(CODE, window='l2')
    blocks = [(physical, bytes(code)), (SAVE, bytes(4))]
    regions = C.B.load_regions(raw)
    for address, data in blocks:
        assert 0x200dca2c <= address < address + len(data) < 0x200f0000
        assert not any(address < a + len(b) and a < address + len(data) for a, b in regions)
        regions.append((address, data))
    result = C.B.insert_before_final(bytes(image), b''.join(C.B.block(a, b) for a, b in blocks))
    # Appended blocks change the second application's serialized FIRST span.
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    assert first.flags == 0x50 and last.flags == 0x80
    header = C.B.block(first.target, flags=first.flags, argument=last.offset - first.offset)
    result = result[:first.offset] + header + result[first.end:]
    assert C.B.walk(result).complete
    receipt.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    receipt['dsp_render_diagnostic'] = dict(
        purpose='Locate T1D9 D907 paired-render freeze; no playback fix.',
        hooks=hooks, scratch=hex(SAVE), code=hex(CODE), code_physical=hex(physical),
        code_bytes=len(code), reply_pages=[hex(p) for p in PAGES],
        cf_reply='0x800053a4', schema_page='0xda',
        untouched_cf_words=[0, 2, 5], preserved_register='I0',
        status_and_mode='No arithmetic, computation, status or mode writes in added code.',
        limitations=[
            'Payload publication is not atomic; marker is written after payload on each checkpoint.',
            'Native renderer and loop checkpoints can be reached by either channel; intervening right-return marker distinguishes the first completed channel.',
            'The pre-loop checkpoint observes PCM base I0 and circular length L3 before deriving the first read cursor.',
            'Additional L2 moves perturb timing slightly; no physical failure is corrected or claimed.'])
    out.mkdir(parents=True, exist_ok=replace)
    # A regenerated candidate must not retain a check of the previous image.
    (out / 'render-diagnostic-check.json').unlink(missing_ok=True)
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(section7_sha256=receipt['section7_sha256'], hooks=len(hooks),
                          code_bytes=len(code), code_physical=hex(physical)), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--replace', action='store_true',
                        help='Replace an explicitly selected unpublished candidate.')
    args = parser.parse_args()
    build(args.out, replace=args.replace)
