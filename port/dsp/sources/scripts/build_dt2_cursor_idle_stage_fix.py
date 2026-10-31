#!/usr/bin/env python3
"""Use the native idle stage for cursor hiding, without exact float-zero gating."""
from pathlib import Path
import argparse, json
import build_dt2_cursor_stop_fix as P
C, B = P.C, P.B
BASE = C.ROOT/'output/dn2-research/dt2-dsp-cursor-stop-fix-20261010/section_7.bin'
SHA = '2be5e0cd265030bea5105bc66049fd96875cfcb5a820f76fd5c1de4ec4932f47'
SITE, IDLE = 0xbf6622, 0xbf6625
AMP, CODE = P.AMP, P.CODE


def build(out):
    raw = BASE.read_bytes(); assert C.SHA(raw) == SHA
    doc = json.loads((BASE.parent/'build-receipt.json').read_text())
    k = C.M.Digikit(C.SRC/'toolchains/digikit'); k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    # T1DI already tests stage5 before reaching this gain-dependent branch.
    # Native stage5 fades by repeated floating subtraction; nonzero rounding
    # residue is valid idle state and must not keep a sample cursor visible.
    before = memory.read_sw(SITE, 6)
    assert before == bytes.fromhex('2006bf002c66')
    after = C.S.to_bytes(0x063e00000000 | IDLE)
    physical = C.S.code_address(SITE, window='l2')
    result = bytearray(raw); C.B.write_span(result, physical, after); result = bytes(result)
    assert len(result) == len(raw) and C.B.walk(result).complete
    old_regions, new_regions = C.B.load_regions(raw), C.B.load_regions(result)
    assert len(old_regions) == len(new_regions)
    changed = []
    for (old_at, old), (new_at, new) in zip(old_regions, new_regions):
        assert old_at == new_at and len(old) == len(new)
        changed.extend(old_at+i for i,(a,b) in enumerate(zip(old,new)) if a != b)
    assert changed and all(physical <= at < physical+6 for at in changed)
    doc.update(baseline_sha256=SHA, section7_sha256=C.SHA(result), flash_ready=False)
    doc['cursor_idle_stage_fix'] = dict(
        base=str(BASE), base_sha256=SHA,
        patch=dict(site=hex(SITE), physical=hex(physical), before=before.hex(), after=after.hex(), idle_return=hex(IDLE)),
        criterion='native AMP stage == 5, independent of residual gain bits',
        native_evidence=dict(constructor='0xb8030c: initializes native AMP stage5',
            stage5='0xb804c2..0xb804ee: idle fade uses repeated floating subtraction, no forced zero store',
            stage4='0xb804f1..0xb8051b: release decay is distinct and remains visible',
            frame_order='native engine call1c3044 completes before cursor publisher1c309a'),
        supersedes='cursor_stop_fix exact-zero gain criterion',
        contract='Display only; no sampler, AMP, voice allocation, transport or audio data writes. Non-idle stages retain original cursor behavior.',
        limits=['Real hardware STOP/retrigger result pending. Legacy page2 telemetry is retained machine/PCM data, not live AMP state.'])
    out.mkdir(parents=True, exist_ok=False)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), patch=doc['cursor_idle_stage_fix']['patch']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
