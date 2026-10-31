#!/usr/bin/env python3
"""Restore the original DT2 decimator's L2 instruction-memory placement.

This is a bounded placement-correction candidate, not a confirmed explanation
of the T1DB ILOPI. The routine, coefficients and linked return ABI are retained.
"""
from pathlib import Path
import argparse
import json

import build_dt2_dsp_code_diagnostic as P

C, B = P.C, P.B
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-code-diagnostic-20261010/section_7.bin'
BASE_SHA = 'cc8da242f322a93f0efbdbe8088e465fdce41c65e73a92af4d46a3d478caf3bf'
OLD, CODE, SIZE = 0x185500, 0xbf4000, 522
PHYSICAL = 0x200e8000
CALLER = 0x18538e
READS = ((0x30aa8c, PHYSICAL + 0x8c), (0x30aa90, PHYSICAL + 0x90))


def build(out):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    receipt = json.loads((BASE.parent / 'build-receipt.json').read_text())
    assert receipt['section7_sha256'] == BASE_SHA
    assert 'dsp_decimator_l2' not in receipt
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    body = memory.read_sw(OLD, SIZE)
    assert len(body) == SIZE
    assert C.SHA(body) == '59ba029fa1ed88cfa2dcd8ddfe41fdc5bc8f9bca3b2ecd2d5aaa6d0b234f226d'
    assert not any(PHYSICAL < a + len(data) and a < PHYSICAL + SIZE
                   for a, data in C.B.load_regions(raw))
    image, edits = bytearray(raw), []

    def patch(pc, before, after, purpose):
        ins = k.st.decode_at(memory, None, pc)
        assert ins.length_bytes == 6 and ins.raw == before, (hex(pc), hex(ins.raw))
        physical = C.S.code_address(pc, window='l2') if pc >= 0xb80000 else C.S.code_address(pc)
        C.B.write_span(image, physical, C.S.to_bytes(after))
        edits.append(dict(pc=hex(pc), physical=hex(physical), before=hex(before),
                          after=hex(after), bytes=6, purpose=purpose))

    patch(CALLER, 0x180400000000 | OLD, 0x180400000000 | CODE,
          'Retarget the sole linked delayed call; both delay slots remain unchanged.')
    # Each existing fatal body contains one scalar I0 load of each code word.
    for hook in receipt['dsp_code_diagnostic']['hooks']:
        start, end = int(hook['entry'], 16), int(hook['replay'], 16) + 3
        for old, new in READS:
            sites = [pc for pc in range(start, end, 3)
                     if k.st.decode_at(memory, None, pc).raw == (0x101000000000 | old)]
            assert len(sites) == 1, (hook['name'], hex(old), sites)
            patch(sites[0], 0x101000000000 | old, 0x101000000000 | new,
                  f"{hook['name']}: capture the relocated decimator's actual instruction bytes.")
    result = C.B.insert_before_final(bytes(image), C.B.block(PHYSICAL, body))
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    assert first.flags == 0x50 and last.flags == 0x80
    header = C.B.block(first.target, flags=first.flags, argument=last.offset - first.offset)
    result = result[:first.offset] + header + result[first.end:]
    assert C.B.walk(result).complete
    receipt.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    receipt['dsp_decimator_l2'] = dict(
        purpose='Placement-correction candidate: retain DT2 decimator code in its donor memory type.',
        base=str(BASE.resolve()), base_sha256=BASE_SHA,
        original=hex(OLD), code=hex(CODE), physical=hex(PHYSICAL), bytes=SIZE,
        routine_sha256=C.SHA(body), exact_original_bytes=True,
        edits=edits, caller=hex(CALLER), delay_slots_unchanged=['0x185391', '0x185392'],
        coefficients_unchanged=['0x30dc00', '0x30dc04', '0x30dc08', '0x30dc0c'],
        internal_relocations=[], relative_loop=dict(before='0x185587', after='0xbf4087',
                                                  end_before='0x1855d5', end_after='0xbf40d5'),
        fatal_code_reads=[dict(before=hex(a), after=hex(b)) for a, b in READS],
        former_fault_pc='0x185546', relocated_fault_pc='0xbf4046',
        old_body_retained=True,
        limitations=['No physical instruction-cache or bus-fault reproduction.',
                     'T1DB live DM instruction bytes were intact; placement is an isolated experiment, not a proven cause.',
                     'Hardware playback remains unverified.'])
    for payload in receipt['dsp_code_diagnostic']['payload']:
        if payload.get('source') in ('0x30aa8c', '0x30aa90'):
            payload['source'] = hex(dict(READS)[int(payload['source'], 16)])
    receipt['dsp_code_diagnostic']['instruction_read_retargeted_by'] = 'dsp_decimator_l2'
    out.mkdir(parents=True, exist_ok=False)
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), code=hex(CODE),
                          physical=hex(PHYSICAL), bytes=SIZE, edits=len(edits)), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
