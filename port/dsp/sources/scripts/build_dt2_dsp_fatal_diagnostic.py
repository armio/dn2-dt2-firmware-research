#!/usr/bin/env python3
"""Publish native SHARC fatal reason/PC before the original EMU halt.

Adds telemetry to T1D9; it does not change the exception's fatal outcome.
"""
from pathlib import Path
import argparse
import json

import build_dt2_dsp_playback_diagnostic as P

C, B = P.C, P.B
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-playback-diagnostic-20261010/section_7.bin'
BASE_SHA = '38fd9e115ec7e3d55d0bdb8949210c6d3393b51cf0dd648347347592d31e3c53'
CODE, SAVE = 0xbf1000, 0x200e3000
PAGES = P.PAGES
NATIVE_HALT = 0x1c07c6
ORIGINAL_JUMP = 0x063e001c07c6
HOOKS = ((0, 'EMUI', 0xb8b55c, 0x507),
         (1, 'ILOPI', 0xb8b579, 0x501),
         (2, 'PARI', 0xb8b594, 0x502))
PAYLOAD = ((12, 0x26ef8c, 'native_reason'),
           (16, 0x26ef90, 'native_fault_pc'),
           (24, 0x26ef88, 'native_header'))


def build(out, *, base=BASE, base_sha=BASE_SHA):
    raw = base.read_bytes()
    assert C.SHA(raw) == base_sha
    receipt = json.loads((base.parent / 'build-receipt.json').read_text())
    assert receipt['section7_sha256'] == base_sha
    assert 'dsp_playback_diagnostic' in receipt
    assert 'dsp_fatal_diagnostic' not in receipt
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    image, code, hooks = bytearray(raw), bytearray(), []
    for number, name, site, reason in HOOKS:
        ins = k.st.decode_at(memory, None, site)
        assert ins.length_bytes == 6 and ins.raw == ORIGINAL_JUMP
        entry = CODE + len(code) // 2
        body = [0x111000000000 | SAVE]  # DM(SAVE) = I0; no SIMD companion.
        for offset, source, _ in PAYLOAD:
            body.append(0x101000000000 | source)  # I0 = DM(source).
            body.extend(0x111000000000 | (page + offset) for page in PAGES)
        marker = 0x4f53dae0 + number
        raw_marker = ((marker << 16) | (marker >> 16)) & 0xffffffff
        body.append(0x0f1000000000 | raw_marker)
        body.extend(0x111000000000 | (page + 4) for page in PAGES)
        body.append(0x101000000000 | SAVE)
        replay = entry + 3 * len(body)
        body.append(ORIGINAL_JUMP)  # Preserve original fatal exit, including EMU.
        emitted = b''.join(C.S.to_bytes(word) for word in body)
        code.extend(emitted)
        C.B.write_span(image, C.S.code_address(site, window='l2'),
                       C.S.to_bytes(0x063e00000000 | entry))
        hooks.append(dict(name=name, site=hex(site), entry=hex(entry),
                          replay=hex(replay), marker=hex(marker),
                          raw_dsp_marker=hex(raw_marker), expected_reason=hex(reason),
                          before_instruction=hex(ORIGINAL_JUMP), bytes=len(emitted)))
    physical = C.S.code_address(CODE, window='l2')
    blocks = [(physical, bytes(code)), (SAVE, bytes(4))]
    regions = C.B.load_regions(raw)
    for address, data in blocks:
        assert 0x200e2000 <= address < address + len(data) < 0x200f0000
        assert not any(address < a + len(b) and a < address + len(data)
                       for a, b in regions), hex(address)
        regions.append((address, data))
    result = C.B.insert_before_final(bytes(image), b''.join(C.B.block(a, b) for a, b in blocks))
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    assert first.flags == 0x50 and last.flags == 0x80
    header = C.B.block(first.target, flags=first.flags, argument=last.offset - first.offset)
    result = result[:first.offset] + header + result[first.end:]
    assert C.B.walk(result).complete
    receipt.update(baseline_sha256=base_sha, section7_sha256=C.SHA(result), flash_ready=False)
    receipt['dsp_fatal_diagnostic'] = dict(
        purpose='Publish native EMUI/ILOPI/PARI record before original fatal halt; no playback fix.',
        base=str(base.resolve()), base_sha256=base_sha,
        code=hex(CODE), code_physical=hex(physical), code_bytes=len(code), scratch=hex(SAVE),
        hooks=hooks, reply_pages=[hex(p) for p in PAGES], cf_reply='0x800053a4',
        payload=[dict(cf_word=offset // 4, source=hex(source), name=name,
                      decode='swap16(CF big-endian word)') for offset, source, name in PAYLOAD],
        untouched_cf_words=[0, 2, 5], preserved_register='I0',
        native_halt=hex(NATIVE_HALT),
        native_pc_sources=dict(EMUI='linked frame return address +1',
                               ILOPI='core MMR 0x300EC masked to 24 bits',
                               PARI='PCSTK masked to 23 bits'),
        status_and_mode='Added instructions contain no arithmetic, status, mode, stack, or SIMD data-register operations.',
        limitations=['Record publication depends on the remaining reply transport observing the written page.',
                     'Only the three known native fatal core handlers are instrumented.',
                     'The original fault record is copied after native handler processing, not raw interrupted registers.',
                     'No recovery, hardware execution, or correction of the playback fault is claimed.'])
    out.mkdir(parents=True, exist_ok=False)
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), hooks=len(hooks),
                          code_bytes=len(code), code_physical=hex(physical)), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--base-sha', default=BASE_SHA)
    args = parser.parse_args()
    build(args.out, base=args.base, base_sha=args.base_sha)
