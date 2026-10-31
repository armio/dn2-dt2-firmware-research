#!/usr/bin/env python3
"""Capture runtime instruction bytes and the prior checkpoint on native fatal exit.

T1DB diagnostic only: preserves the original fatal halt and ordinary playback.
"""
from pathlib import Path
import argparse
import json

import build_dt2_dsp_fatal_diagnostic as F

C, B = F.C, F.B
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-render-fatal-diagnostic-20261010/section_7.bin'
BASE_SHA = 'e613ad335d2e31367213fe1b850d612118853809946f32c3981028704722bc2c'
CODE, SAVE = 0xbf3000, 0x200e7000
PAGES, NATIVE_HALT = F.PAGES, F.NATIVE_HALT
ORIGINAL_JUMP = F.ORIGINAL_JUMP
CODE_WORDS = ((0, 0x30aa8c, 0x00301007), (8, 0x30aa90, 0x703fdc00))


def build(out):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    receipt = json.loads((BASE.parent / 'build-receipt.json').read_text())
    assert receipt['section7_sha256'] == BASE_SHA
    assert 'dsp_code_diagnostic' not in receipt
    previous = receipt['dsp_fatal_diagnostic']
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    image, code, hooks = bytearray(raw), bytearray(), []
    for offset, address, expected in CODE_WORDS:
        physical = address + 0x28000000
        data = next(blob[physical - start:physical - start + 4]
                    for start, blob in C.B.load_regions(raw)
                    if start <= physical and physical + 4 <= start + len(blob))
        assert int.from_bytes(data, 'little') == expected
    for number, old in enumerate(previous['hooks']):
        site, old_entry = int(old['site'], 16), int(old['entry'], 16)
        before = 0x063e00000000 | old_entry
        ins = k.st.decode_at(memory, None, site)
        assert ins.length_bytes == 6 and ins.raw == before
        assert C.S.to_value(memory.read_sw(int(old['replay'], 16), 6)) == ORIGINAL_JUMP
        entry = CODE + len(code) // 2
        body = [0x111000000000 | SAVE]  # Save scalar I0, without a SIMD companion.
        # Capture both previous markers before changing either page's marker.
        for page_index, page in enumerate(PAGES):
            body.extend((0x101000000000 | (page + 4),
                         0x111000000000 | (SAVE + 4 + page_index * 4)))
        capture_end = entry + 3 * len(body)
        pc_source = 0x300ec if old['name'] == 'ILOPI' else 0x26ef90
        for offset, source in ((0, 0x30aa8c), (8, 0x30aa90),
                               (12, 0x26ef8c), (16, pc_source)):
            body.append(0x101000000000 | source)
            body.extend(0x111000000000 | (page + offset) for page in PAGES)
        for page_index, page in enumerate(PAGES):
            body.extend((0x101000000000 | (SAVE + 4 + page_index * 4),
                         0x111000000000 | (page + 24)))
        marker = 0x4f53dbe0 + number
        raw_marker = ((marker << 16) | (marker >> 16)) & 0xffffffff
        body.append(0x0f1000000000 | raw_marker)
        publish = entry + 3 * len(body)
        body.extend(0x111000000000 | (page + 4) for page in PAGES)
        body.append(0x101000000000 | SAVE)
        replay = entry + 3 * len(body)
        body.append(ORIGINAL_JUMP)
        emitted = b''.join(C.S.to_bytes(word) for word in body)
        code.extend(emitted)
        C.B.write_span(image, C.S.code_address(site, window='l2'),
                       C.S.to_bytes(0x063e00000000 | entry))
        hooks.append(dict(name=old['name'], site=hex(site), entry=hex(entry),
                          old_entry=hex(old_entry), before_instruction=hex(before),
                          capture_end=hex(capture_end), publish=hex(publish),
                          replay=hex(replay), marker=hex(marker),
                          raw_dsp_marker=hex(raw_marker), bytes=len(emitted),
                          expected_reason=old['expected_reason'], pc_source=hex(pc_source)))
    physical = C.S.code_address(CODE, window='l2')
    blocks = [(physical, bytes(code)), (SAVE, bytes(12))]
    regions = C.B.load_regions(raw)
    for address, data in blocks:
        assert 0x200e6000 <= address < address + len(data) < 0x200f0000
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
    receipt.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    receipt['dsp_code_diagnostic'] = dict(
        purpose='Capture actual decimator instruction bytes on fatal exit; diagnostic only, no playback fix.',
        base=str(BASE.resolve()), base_sha256=BASE_SHA,
        code=hex(CODE), code_physical=hex(physical), code_bytes=len(code),
        scratch=hex(SAVE), scratch_bytes=12, hooks=hooks,
        reply_pages=[hex(p) for p in PAGES], cf_reply='0x800053a4',
        payload=[
            dict(cf_word=0, source='0x30aa8c', name='instruction_word_0', expected='0x00301007', decode='swap16(CF BE32)'),
            dict(cf_word=1, name='fatal_schema_marker', decode='CF BE32'),
            dict(cf_word=2, source='0x30aa90', name='instruction_word_1', expected='0x703fdc00', decode='swap16(CF BE32)'),
            dict(cf_word=3, source='0x26ef8c', name='native_reason', decode='swap16(CF BE32)'),
            dict(cf_word=4, name='full_illegal_opcode_register_or_native_pc', decode='swap16(CF BE32); ILOPI PC=low24, uninterruptible=bit24'),
            dict(cf_word=6, name='previous_page_checkpoint', decode='CF BE32; already encoded marker, do not swap')],
        untouched_cf_words=[5], preserved_register='I0', native_halt=hex(NATIVE_HALT),
        prior_markers='Both pages captured separately before any new fatal marker is published.',
        replaces_dsp_fatal_diagnostic_hooks=True,
        status_and_mode='Only scalar universal loads/stores, immediate I0 and non-delayed jumps; no arithmetic, mode, status or stack change.',
        limitations=[
            'Fatal-only schema repurposes heartbeat/counter and the previous constant header; normal frames remain unchanged.',
            'Native CF consumer of reply+0x16 is preserved by leaving word5 untouched.',
            'Word6 has an existing RPC acknowledgment consumer and is repurposed only after native fatal outcome.',
            'Original fatal diagnostic bodies remain present but are bypassed by the three redirected exits.',
            'No actual exception, DMA, instruction cache, physical memory integrity or playback repair is proven.'])
    out.mkdir(parents=True, exist_ok=False)
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), hooks=len(hooks),
                          code_bytes=len(code), code_physical=hex(physical)), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
