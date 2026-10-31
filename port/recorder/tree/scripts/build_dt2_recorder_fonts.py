#!/usr/bin/env python3
"""Bind Recorder and Slice editor fonts to byte-identical native DN2 assets."""
from pathlib import Path
import argparse
import json
import shutil
import struct
import build_dt2_directory_model as L
B = L.B

FONTS = ((0x402a4f6c, 0x4028fa9c, 1732), (0x402a6c30, 0x40291760, 1224))


def font_bindings(donor, native):
    bindings, proof = {}, []
    for old, new, size in FONTS:
        before = struct.unpack_from('>5I', donor, old-B.BASE)
        after = struct.unpack_from('>5I', native, new-B.BASE)
        assert before[:2] == after[:2]
        assert [x-old for x in before[2:]] == [x-new for x in after[2:]] == [20, 276, 788]
        a, b = donor[old-B.BASE+20:old-B.BASE+20+size], native[new-B.BASE+20:new-B.BASE+20+size]
        assert a == b and len(a) == size
        bindings[old] = new
        proof.append(dict(donor=hex(old), native=hex(new), payload_bytes=size, payload_sha256=B.T.SHA(a)))
    return bindings, proof


def build(parent, out):
    doc = json.loads((parent/'build-receipt.json').read_text())
    image = bytearray((parent/'main-os.bin').read_bytes())
    payload = bytearray((parent/'runtime.bin').read_bytes())
    assert B.T.SHA(image) == doc['main_sha256']
    assert B.T.SHA(payload) == doc['runtime_sha256']
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    assert image[src-B.BASE:src-B.BASE+copy['bytes']] == payload
    donor, native = B.M.S.DONOR.read_bytes(), B.M.RECIPIENT.read_bytes()
    bindings, proof = font_bindings(donor, native)
    for old, new, size in FONTS:
        assert image[new-B.BASE:new-B.BASE+20+size] == native[new-B.BASE:new-B.BASE+20+size]
    edits = []
    for component, expected in [('recorder_ui', 12), ('manual_slice_editor', 7)]:
        count = 0
        for edit in doc[component]['edits']:
            target = int(edit['target'], 16)
            if target not in bindings:
                continue
            at, old, new = int(edit['runtime'], 16), int(edit['binding'], 16), bindings[target]
            assert struct.unpack_from('>I', payload, at-base)[0] == old
            # Broken imports contain zero padding followed by unrelated text,
            # rather than the donor's complete 20-byte font descriptor.
            assert struct.unpack_from('>I', payload, old-base)[0] == 0
            payload[at-base:at-base+4] = B.BE(new)
            edits.append(dict(component=component, runtime=hex(at), before=hex(old), after=hex(new), donor=hex(target)))
            edit['binding'] = hex(new)
            count += 1
        assert count == expected, (component, count)
    image[src-B.BASE:src-B.BASE+len(payload)] = payload
    doc['recorder_fonts'] = dict(fonts=proof, edits=edits,
        reason='Raw zero-prefixed font descriptors had been resolved as empty strings.',
        runtime_bytes_added=0, graphics_code_unchanged=True)
    doc.update(baseline_sha256=doc['main_sha256'], main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(payload), flash_ready=False)
    out.mkdir(parents=True, exist_ok=False)
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S', 'bootstrap.asm', 'bootstrap.elf'):
        if (parent/name).exists():
            shutil.copyfile(parent/name, out/name)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], edited_operands=len(edits), runtime_bytes_added=0)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.input, args.out)
