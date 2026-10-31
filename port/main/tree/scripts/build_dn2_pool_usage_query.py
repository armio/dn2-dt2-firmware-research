#!/usr/bin/env python3
"""Connect the original DT2 pool usage callback to the native project caches.

This ports the getter, not the separately retained incremental cache producers.
It must not imply that cache refresh scheduling has been established.
"""
from pathlib import Path
import argparse
import json
import struct
import build_dt2_directory_model as L

B = L.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-project-sample-copy-20261010'
SHA = 'cab61d44ed15936b6ac2c19d81fdcc9378f09967234ceb410668696173868cd4'


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    donor = B.M.S.DONOR.read_bytes()
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    entry = base + len(payload)
    origin, end = 0x40016768, 0x40016792
    body = bytearray(donor[origin-B.BASE:end-B.BASE])
    query = int(doc['pool_references']['query'], 16)
    for operand, before, after in [(0x40016778, 0x401988a2, 0x4018a97a),
                                  (0x40016788, 0x4004210a, query)]:
        offset = operand-origin
        assert body[offset:offset+4] == B.BE(before)
        body[offset:offset+4] = B.BE(after)
    payload.extend(body)
    payload.extend(bytes(-len(payload) % 4))
    # A typed SamplePoolDirectory vtable entry, not an arbitrary word rewrite.
    edit = next(e for e in doc['pool_model']['edits']
                if e.get('operand') == '0x401ed4ac')
    assert edit['before'] == hex(origin) and edit['after'] == '0x47a624a0'
    site = 0x47a60280
    assert payload[site-base:site-base+4] == B.BE(int(edit['after'], 16))
    struct.pack_into('>I', payload, site-base, entry)
    edit['after'] = hex(entry)
    for component in ('pool_model', 'sample_list_view'):
        doc[component]['unresolved'] = [e for e in doc[component]['unresolved']
                                       if e['donor'] != hex(origin)]
    doc['pool_references']['connected_to_browser'] = True
    out.mkdir(parents=True, exist_ok=False)
    assert base + len(payload) <= int(doc['runtime_limit'], 16)
    image = bytearray(raw[:src-B.BASE]) + payload
    boot = B.BASE + len(image)
    source = (INPUT / 'bootstrap.S').read_text().replace(
        f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(source, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image), bytes=len(image),
               runtime_copy={**copy, 'bytes': len(payload)},
               runtime_sha256=B.T.SHA(payload), bootstrap=hex(boot),
               bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    doc['pool_usage_query'] = dict(entry=hex(entry), donor=[hex(origin), hex(end)],
        directory_vtable_slot=hex(site), project_getter='0x4018a97a',
        project_query=hex(query),
        behavior='Original bounds check and current-project lookup, then original three-cache query at DN2 member offsets.',
        limits=['Cache producer scheduling remains unconnected; this is getter linkage only.',
                'No hardware/browser-interaction validation.'])
    for name, data in [('main-os.bin', image), ('runtime.bin', payload)]:
        (out / name).write_bytes(data)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((INPUT / name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], runtime_bytes=len(payload),
                         pool_usage_query=doc['pool_usage_query']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
