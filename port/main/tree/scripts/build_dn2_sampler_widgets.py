#!/usr/bin/env python3
"""Install DT2 sampler drawers on the existing isolated encoder companions."""
from pathlib import Path
import argparse
import json
import struct

import build_dt2_directory_model as L
import dn2_sampler_widget_donor as W

B = L.B
GETTER = 0x400c2418


def build(folder, out):
    raw = (folder / 'main-os.bin').read_bytes()
    doc = json.loads((folder / 'build-receipt.json').read_text())
    assert B.T.SHA(raw) == doc['main_sha256']
    assert 'sampler_widgets' not in doc
    cfg, copy = doc['encoder_sensitivity'], doc['runtime_copy']
    previous = int(cfg['entry'], 16)
    assert raw[GETTER-B.BASE:GETTER-B.BASE+6] == b'\x4e\xf9' + B.BE(previous)
    source, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray((folder / 'runtime.bin').read_bytes())
    assert payload == raw[source-B.BASE:source-B.BASE+copy['bytes']]
    assert len(payload) % 4 == 0
    out.mkdir(parents=True, exist_ok=False)
    code, callbacks, evidence = W.build_callbacks(doc, base + len(payload), out)
    payload.extend(code)
    payload.extend(bytes(-len(payload) % 4))
    descriptors = W.donor_descriptors(B.M.S.DONOR.read_bytes())
    rows = [dict(native_id=r['native_id'], donor_id=r['donor_id'],
                 machine=r['machine'], name=r['name']) for r in cfg['rows']]
    for donor_id in (205, 214, 223, 232, 241, 251):
        rows.append(dict(native_id=doc['source_parameters']['records'][str(donor_id)]['native'],
                         donor_id=donor_id, name='SAMP'))
    rows.sort(key=lambda r: r['native_id'])
    assert len({r['native_id'] for r in rows}) == len(rows) == 41
    lookup = base + len(payload)
    indices = {r['native_id']:i+1 for i,r in enumerate(rows)}
    payload.extend(bytes(indices.get(n, 0) for n in range(368)))
    table = base + len(payload)
    for row in rows:
        donor = descriptors[row['donor_id']]
        row.update(flags=donor['flags'], donor_drawer=hex(donor['callback']),
                   drawer=hex(callbacks[donor['callback']]))
        payload.extend(struct.pack('>2I', row['flags'], int(row['drawer'], 16)))
    entry = base + len(payload)
    asm = f'''.text
.global sampler_widget_companion
sampler_widget_companion:
 move.l 4(%sp),%d0
 cmpi.l #367,%d0
 bhi.s stock_companion
 lea {lookup:#x},%a0
 mvz.b (%a0,%d0.l),%d1
 tst.l %d1
 beq.s stock_companion
 move.l %d2,-(%sp)
 subq.l #1,%d1
 move.l %d1,%d2
 move.l %d0,-(%sp)
 jsr {previous:#x}
 addq.l #4,%sp
 movea.l %d0,%a0
 lsl.l #3,%d2
 lea {table:#x},%a1
 adda.l %d2,%a1
 move.l (%a1)+,(%a0)
 move.l (%a1),32(%a0)
 move.l (%sp)+,%d2
 rts
stock_companion:
 jmp {previous:#x}
.balign 4
'''
    payload.extend(B.R.assemble(asm, entry, out, 'sampler-widgets'))
    assert base + len(payload) <= int(doc['runtime_limit'], 16)
    image = bytearray(raw[:source-B.BASE]) + payload
    before = image[GETTER-B.BASE:GETTER-B.BASE+6]
    after = b'\x4e\xf9' + B.BE(entry)
    image[GETTER-B.BASE:GETTER-B.BASE+6] = after
    boot = B.BASE + len(image)
    bootstrap = (folder / 'bootstrap.S').read_text().replace(
        f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    assert bootstrap != (folder / 'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    doc['sampler_widgets'] = dict(base=str(folder.resolve()), base_sha256=doc['main_sha256'],
        entry=hex(entry), previous_getter=hex(previous), lookup=hex(lookup), table=hex(table),
        rows=rows, donor_evidence=evidence,
        hook=dict(address=hex(GETTER), before=before.hex(), after=after.hex()),
        changed='Original DT2 flags, draw callbacks and bitmap assets per sampler control.',
        preserved='Encoder configuration, values, locks, callback ownership, stock descriptors and DSP.',
        limits=['Hardware display confirmation pending.'])
    doc.update(main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(payload), bytes=len(image),
               runtime_copy={**copy, 'bytes':len(payload)}, bootstrap=hex(boot),
               bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    (out / 'main-os.bin').write_bytes(image)
    (out / 'runtime.bin').write_bytes(payload)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((folder / name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], parameters=len(rows),
                         runtime_bytes=len(payload), free_bytes=int(doc['runtime_limit'],16)-base-len(payload))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.folder, args.out)
