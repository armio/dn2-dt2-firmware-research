#!/usr/bin/env python3
"""Restore current-block native USB MAIN alongside the existing track exports."""
from pathlib import Path
import argparse
import json

import build_dt2_codec_stage_commit as P

C, B = P.C, P.B
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-codec-stage-commit-20261012/section_7.bin'
BASE_SHA = 'ea75842fb5d37bf52caaadbf181e83ad4a3645ab8dc178cfdae03b93a7e5d13e'
PATCHES = (
    # Remove the diagnostic MAIN source/gain substitution.
    ('native_usb_main', 0x1c265b, 0x063e00bf14a7, 0x1596ffffff82, 'l1'),
    # T1DP has already recorded completion here. Resume its original native
    # page load directly instead of making an unused codec-PCM snapshot.
    ('remove_codec_snapshot_call', 0xbf0b84, 0x063e00bf1280, 0x100100268a38, 'l2'),
)


def build(out):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    doc = json.loads((BASE.parent / 'build-receipt.json').read_text())
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    before = B.decode_view(k, raw)
    image = bytearray(raw)
    patches = []
    for name, pc, expected, replacement, window in PATCHES:
        ins = k.st.decode_at(before, None, pc)
        assert ins.length_bytes == 6 and ins.raw == expected, (name, hex(ins.raw))
        at = C.S.code_address(pc, window=window)
        C.B.write_span(image, at, C.S.to_bytes(replacement))
        patches.append(dict(name=name, site=hex(pc), physical=hex(at),
                            raw_before=hex(expected), raw_after=hex(replacement),
                            before=before.read_sw(pc, 6).hex(),
                            after=C.S.to_bytes(replacement).hex()))
    result = bytes(image)
    assert len(result) == len(raw) and C.B.walk(result).complete
    out.mkdir(parents=True, exist_ok=False)
    doc.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    doc['usb_multitrack_tap'] = dict(
        base=str(BASE.resolve()), base_sha256=BASE_SHA, patches=patches,
        contract='Restore native current-block USB MAIN sources and gains. Native channels0..41 remain exported every normal block; class-compliant34-channel transport is a separate ColdFire component.',
        timing='MAIN0/1 and track2..33 now come from the same current DSP block. Physical codec delivery retains the T1DT one-block private-stage/early-commit pipeline.',
        completion='T1DT tail still enters original T1DP completion accounting. Its BF0B84 replay again loads native268A38 then jumps1C9E57, preserving native page toggle and removing only the obsolete snapshot invocation.',
        stereo='Post-fader track exports preserve the ported sampler stereo output. The class-compliant host component must select the existing POST source for34-channel mode.',
        unchanged=['All T1DT staging code, buffers, hooks and lifecycle',
                   'Codec DMA pages/descriptors and physical output configuration',
                   'Delivery, SPORT error, timing and scheduler diagnostic code',
                   'Native USB export call, all42 descriptor entries and track/effect/input streams',
                   'Image size and load-region layout'],
        inactive_legacy='Prior codec_usb_capture/fix receipt keys describe retained inert code/data; their two invocation hooks are superseded by this component.',
        limits=['No USB descriptor, packet size or channel-count change in this DSP component.',
                'Native USB MAIN is upstream of the codec-only final processing, as in stock firmware; it is no longer the diagnostic physical-PCM mirror.',
                'Static/native instruction restoration does not establish USB multichannel device enumeration or hardware throughput.'])
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), patches=patches), indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    build(ap.parse_args().out)
