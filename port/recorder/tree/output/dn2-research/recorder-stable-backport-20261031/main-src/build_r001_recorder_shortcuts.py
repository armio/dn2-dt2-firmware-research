#!/usr/bin/env python3
"""Restore donor SAMPLING+YES/NO actions within the DN2 Recorder page."""
from pathlib import Path
import argparse
import json
import re
import struct
import build_dt2_recorder_fonts as F
B = F.B


def build(parent, out, build_id="T1F3"):
    doc = json.loads((parent/'build-receipt.json').read_text())
    raw = (parent/'main-os.bin').read_bytes()
    payload = bytearray((parent/'runtime.bin').read_bytes())
    assert B.T.SHA(raw) == doc['main_sha256']
    assert B.T.SHA(payload) == doc['runtime_sha256']
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    assert raw[src-B.BASE:src-B.BASE+copy['bytes']] == payload
    cfg = doc['recorder_ui']

    def address(old):
        for span in cfg['spans']:
            if int(span['donor'], 16) <= old < int(span['end'], 16):
                return int(span['runtime'], 16)+old-int(span['donor'], 16)
        hits = {int(edit['binding'], 16) for edit in cfg['edits'] if int(edit['target'], 16) == old}
        assert len(hits) == 1, (hex(old), hits)
        return hits.pop()

    donor = B.M.S.DONOR.read_bytes()
    lo, hi = 0x40016b3a, 0x40016c2a
    callback = bytearray(donor[lo-B.BASE:hi-B.BASE])
    callback_at = base+len(payload)
    edits = []
    for at, target, _, _ in B.M.operands(B.M.S.disasm(donor, B.BASE, lo, hi)):
        binding = address(target)
        struct.pack_into('>I', callback, at-lo, binding)
        edits.append(dict(donor=hex(at), target=hex(target), runtime=hex(callback_at+at-lo), binding=hex(binding)))
    assert len(edits) == 13
    payload.extend(callback)
    payload.extend(bytes(-len(payload)%4))
    previous = int(doc['recorder_route']['methods']['recorder_page_event'], 16)
    symbols = dict(recorder_shortcut_event=callback_at, recorder_previous_route=previous)
    asm = ''.join(f'.equ {key},{value:#x}\n' for key, value in symbols.items())
    asm += (B.T.ROOT/'scripts/asm/dn2_recorder_shortcuts.S').read_text()
    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(asm, base+len(payload), out, 'recorder-shortcuts')
    nm = B.T.run([B.T.BIN/'binutils/nm-new', '-n', out/'recorder-shortcuts.elf'])
    linked = {m[2]: int(m[1], 16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$', nm)}
    payload.extend(code)
    slot = int(doc['recorder_route']['recorder_event_slot'], 16)
    assert struct.unpack_from('>I', payload, slot-base)[0] == previous
    struct.pack_into('>I', payload, slot-base, linked['recorder_shortcut_route'])
    identity = 0x47aa5a0c-base
    assert payload[identity:identity+4] == b'R001'
    payload[identity:identity+4] = build_id.encode('ascii')
    assert base+len(payload) <= int(doc['runtime_limit'], 16)
    image = bytearray(raw[:src-B.BASE])+payload
    boot = B.BASE+len(image)
    asm = (parent/'bootstrap.S').read_text()
    old, new = f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1'
    assert old in asm
    image.extend(B.R.assemble(asm.replace(old, new), boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+B.BE(boot)
    doc['recorder_shortcuts'] = dict(
        methods={**{key: hex(value) for key, value in symbols.items()}, 'recorder_shortcut_route': hex(linked['recorder_shortcut_route'])},
        state={key: hex(linked[key]) for key in ('shortcut_owner', 'shortcut_used', 'shortcut_key')},
        spans=[dict(name='recorder_shortcut_event', donor=hex(lo), end=hex(hi), runtime=hex(callback_at), kind='code')],
        edits=edits, event_slot=hex(slot), donor_callback_sha256=B.T.SHA(donor[lo-B.BASE:hi-B.BASE]),
        scope='Recorder page only; VOICE=DT2 SAMPLING raw key 0x32; existing FUNC+VOICE unison unchanged.',
        release='Both modifier release orders consume the complete chord without page switch or plain YES action.')
    doc['recorder_route']['methods']['recorder_page_event'] = hex(linked['recorder_shortcut_route'])
    doc.update(baseline_sha256=doc['main_sha256'], main_sha256=B.T.SHA(image), bytes=len(image),
        runtime_copy={**copy, 'bytes': len(payload)}, runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot), bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    for name, value in [('main-os.bin', image), ('runtime.bin', payload)]:
        (out/name).write_bytes(value)
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out/name).write_bytes((parent/name).read_bytes())
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], runtime_end=hex(base+len(payload)), callback_bytes=len(callback), wrapper_bytes=len(code))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--build', choices=('R001',), default='R001')
    args = parser.parse_args()
    build(args.input, args.out, args.build)
