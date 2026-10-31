#!/usr/bin/env python3
"""Add small T1D9 checkpoints to the hardware's frozen stage-2 playback path.

Only absolute moves and non-delayed jumps are added. The checkpoints use the
existing two DSP reply pages and leave their heartbeat, entry counter and
native word at offset 0x14 untouched. This is instrumentation, not a fix.
"""
from pathlib import Path
import argparse
import json

import build_dt2_dsp_startup_fix as B
import build_dt2_dsp_dma_l1 as L1
import build_dt2_voice_samples as V

C = B.C
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-dma-l1-20261010/section_7.bin'
BASE_SHA = '04913916103ea3ed81f40efdb6f4507e0e5bfacca4b656df90cad3e9c636945d'
CODE = 0xbf0000  # L2 physical 0x200e0000, beyond the prior append-only image.
SAVE = 0x200e1000
PAGES = (0x2c49d0, 0x2c59d0)
HOOKS = (
    (1, 'after-stage2-before-snapshot-refresh', 0x185c3d, 0x10000030dd78),
    (2, 'snapshot-refreshed-status-helper-returned', 0x185c61, 0x10000030dcf0),
    (3, 'before-pointer-active-quiet-guard', 0x185cb0, 0x10040030dc98),
    (4, 'inside-saved-setup-scope-before-dispatch', 0x1856af, 0x063e00bc959f),
    (5, 'native-oneshot-setup-entry', 0x16f800, 0x100f0030dc98),
    (6, 'setup-completed-before-paired-pass-or-restore', 0x185737, 0x063e00bcb6f0),
    (7, 'paired-render-entry', 0xbcb717, 0x1104200aa60c),
    (8, 'paired-render-return-before-level', 0x185d0a, 0x063e0016f4c0),
)


def build(out, *, replace=False):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    receipt = json.loads((BASE.parent / 'build-receipt.json').read_text())
    mv = lambda value: L1.mapped(B.mapped(value, receipt['dsp_startup_fix']['placements']))
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    image = bytearray(raw)
    code = bytearray()
    hooks = []
    # Values are published without arithmetic, leaving every status bit
    # unchanged. Their CF representation needs a 16-bit halfword swap.
    payloads = ((12, 0x30dcf0, 'latest_record_pcm_snapshot'),
                (16, mv(V.DESC), 'selected_descriptor_pcm'),
                (24, mv(V.DESC + 8), 'selected_descriptor_frames'))
    for checkpoint, name, site, expected in HOOKS:
        ins = k.st.decode_at(memory, None, site)
        assert ins.length_bytes == 6 and ins.raw == expected, (hex(site), hex(ins.raw))
        entry = CODE + len(code) // 2
        body = []
        # I0 is a universal DAG register without a SIMD complement. R0 would
        # also transfer S0 under MODE1.SSE and corrupt adjacent reply cells.
        body.append(0x111000000000 | SAVE)  # DM(SAVE) = I0
        for offset, source, _ in payloads:
            body.append(0x101000000000 | source)  # I0 = DM(source)
            body.extend(0x111000000000 | (page + offset) for page in PAGES)
        marker = 0x4f53d900 | checkpoint
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
                          bytes=len(emitted), added_instructions_max=len(body)))
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
    receipt['dsp_playback_diagnostic'] = dict(
        purpose='Locate the T1D8 hardware freeze between old playback stages 2 and 3; no playback fix.',
        hooks=hooks, scratch=hex(SAVE), code=hex(CODE), code_physical=hex(physical),
        code_bytes=len(code), reply_pages=[hex(p) for p in PAGES],
        cf_reply='0x800053a4', schema_page='0xd9',
        payload=[dict(cf_word=offset // 4, source=hex(source), name=name,
                      decode='swap16(CF big-endian word)') for offset, source, name in payloads],
        untouched_cf_words=[0, 2, 5], preserved_register='I0',
        status_and_mode='No arithmetic, computation, status or mode writes in added code.',
        limitations=[
            'Payload publication is not atomic; marker is written after payload on each checkpoint.',
            'Latest PCM snapshot reflects the existing adapter refresh point; descriptor payload is the latest completed lookup.',
            'The two setup-pass visits use the same checkpoint; this diagnostic does not label left versus right.',
            'Additional L2 moves perturb timing slightly; no physical failure is corrected or claimed.'])
    out.mkdir(parents=True, exist_ok=replace)
    # A regenerated candidate must not retain a check of the previous image.
    (out / 'playback-diagnostic-check.json').unlink(missing_ok=True)
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
