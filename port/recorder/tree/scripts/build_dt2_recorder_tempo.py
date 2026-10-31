#!/usr/bin/env python3
"""Bind Recorder duration calculation to the live native DN2 tempo getter."""
from pathlib import Path
import argparse
import json
import shutil
import struct
import build_dt2_recorder_fonts as F
B = F.B
DONOR_GETTER, NATIVE_GETTER = 0x4002d744, 0x400257fa
DONOR_TEMPO, NATIVE_TEMPO = 0x402b62bc, 0x402a0dec


def tempo_binding(donor, native):
    a = donor[DONOR_GETTER-B.BASE:DONOR_GETTER-B.BASE+8]
    b = native[NATIVE_GETTER-B.BASE:NATIVE_GETTER-B.BASE+8]
    assert a == bytes.fromhex('2039')+B.BE(DONOR_TEMPO)+bytes.fromhex('4e75')
    assert b == bytes.fromhex('2039')+B.BE(NATIVE_TEMPO)+bytes.fromhex('4e75')
    assert donor[DONOR_TEMPO-B.BASE:DONOR_TEMPO-B.BASE+4] == native[NATIVE_TEMPO-B.BASE:NATIVE_TEMPO-B.BASE+4] == B.BE(14400)
    return {DONOR_GETTER: NATIVE_GETTER}, dict(donor_getter=hex(DONOR_GETTER),
        native_getter=hex(NATIVE_GETTER), donor_tempo=hex(DONOR_TEMPO), native_tempo=hex(NATIVE_TEMPO),
        default=14400, units='BPM * 120', native_getter_bytes=b.hex())


def build(parent, out):
    doc = json.loads((parent/'build-receipt.json').read_text())
    image, payload = bytearray((parent/'main-os.bin').read_bytes()), bytearray((parent/'runtime.bin').read_bytes())
    assert B.T.SHA(image) == doc['main_sha256']
    assert B.T.SHA(payload) == doc['runtime_sha256']
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16)-B.BASE, int(copy['destination'], 16)
    assert image[src:src+copy['bytes']] == payload
    bindings, proof = tempo_binding(B.M.S.DONOR.read_bytes(), B.M.RECIPIENT.read_bytes())
    assert image[NATIVE_GETTER-B.BASE:NATIVE_GETTER-B.BASE+8].hex() == proof['native_getter_bytes']
    patches = []
    for edit in doc['recorder_ui']['edits']:
        if int(edit['target'], 16) != DONOR_GETTER:
            continue
        at, old = int(edit['runtime'], 16), int(edit['binding'], 16)
        assert payload[at-base:at-base+4] == B.BE(old)
        assert payload[old-base:old-base+2] == bytes.fromhex('2039')
        private = struct.unpack_from('>I', payload, old-base+2)[0]
        assert payload[private-base:private-base+4] == bytes(4)
        payload[at-base:at-base+4] = B.BE(NATIVE_GETTER)
        patches.append(dict(address=hex(at), before=B.BE(old).hex(), after=B.BE(NATIVE_GETTER).hex(),
            abandoned_private_tempo=hex(private)))
        edit['binding'] = hex(NATIVE_GETTER)
    assert len(patches) == 1
    identity = 0x47aa5a0c-base
    assert payload[identity:identity+4] == b'T1F3'
    payload[identity:identity+4] = b'T1F4'
    image[src:src+len(payload)] = payload
    doc['recorder_tempo_binding'] = dict(proof=proof, patches=patches,
        cause='Recorder duration helper used a private, unmaintained zero tempo clone. Finite R.LEN draw divided by zero.',
        hardware_fault_pc='0x47ab8aa4', runtime_bytes_added=0,
        zero_policy='Use native live tempo, initialized14400 and maintained by native3600..36000 setter clamps; no arbitrary division fallback.')
    doc.update(baseline_sha256=doc['main_sha256'], main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(payload), flash_ready=False)
    out.mkdir(parents=True, exist_ok=False)
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S', 'bootstrap.asm', 'bootstrap.elf'):
        if (parent/name).exists():
            shutil.copyfile(parent/name, out/name)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], patches=patches, runtime_bytes_added=0)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.input, args.out)
