#!/usr/bin/env python3
"""Use the retained native DT2-equivalent AUTO-PREVIEW setting on DN2."""
from pathlib import Path
import argparse
import json
import struct
import build_dt2_directory_model as L

B = L.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-pool-usage-query-20261010'
SHA = '1270845838cc07c7167f481fe282251c37bb63f83f275eeaaf3dc727257bbff2'


def build(out):
    raw = bytearray((INPUT / 'main-os.bin').read_bytes())
    assert B.T.SHA(raw) == SHA
    donor, native = B.M.S.DONOR.read_bytes(), B.M.RECIPIENT.read_bytes()
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    # The field exists on both instruments at settings header+0x49. Compare
    # full getters/setters; identical PC-relative displacement reaches the
    # corresponding native settings updater, not a relocated donor writer.
    evidence = []
    for old, new, size in [(0x400c12a2, 0x400bb8d2, 12),
                           (0x400c12ae, 0x400bb8de, 42),
                           (0x400c0ec8, 0x400bb4f8, 34),
                           (0x400c0e9e, 0x400bb4ce, 42),
                           (0x400c0d1c, 0x400bb34c, 30)]:
        a = bytearray(donor[old-B.BASE:old-B.BASE+size])
        b = native[new-B.BASE:new-B.BASE+size]
        for field in (0, 4, 8, 12, 0x49):
            a = a.replace(B.BE(0x4099d588+field), B.BE(0x405cd85c+field))
        assert a == b, (hex(old), hex(new))
        evidence.append(dict(donor=hex(old), native=hex(new), bytes=size,
                             kind='Complete body identical after settings-global relocation'))
    assert native[0x400bb42c-B.BASE:0x400bb432-B.BASE] == bytes.fromhex('13c0405cd8a5')
    assert native[0x400bb566-B.BASE:0x400bb56c-B.BASE] == bytes.fromhex('13c0405cd8a5')
    edits = []
    for old, new in [(0x400c12a2, 0x400bb8d2), (0x400c12ae, 0x400bb8de)]:
        sites = [e for e in doc['sample_manager']['edits'] if e.get('target') == hex(old)]
        assert len(sites) == 1
        e = sites[0]
        at = src-B.BASE+int(e['runtime'], 16)-base
        previous = int(e['binding'], 16)
        assert raw[at:at+4] == B.BE(previous)
        struct.pack_into('>I', raw, at, new)
        e['binding'] = hex(new)
        edits.append(dict(runtime=e['runtime'], donor=hex(old), before=hex(previous), after=hex(new)))
    payload = raw[src-B.BASE:src-B.BASE+copy['bytes']]
    doc.update(main_sha256=B.T.SHA(raw), runtime_sha256=B.T.SHA(payload), flash_ready=False)
    doc['sample_manager'].pop('pending_preferences', None)
    doc['browser_preferences'] = dict(getter='0x400bb8d2', setter='0x400bb8de',
        field='0x405cd8a5', header='0x405cd85c', header_offset='0x49',
        updater='0x400bb4f8', checksum='0x400bb34c', validator='0x400bb4c0',
        default=False, edits=edits, evidence=evidence,
        persistence='Existing native working settings header and backup restore; same field/default/migration as DT2.',
        limits=['Physical power-cycle persistence still needs device validation.'])
    out.mkdir(parents=True, exist_ok=False)
    for name, data in [('main-os.bin', raw), ('runtime.bin', payload)]:
        (out / name).write_bytes(data)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt', 'bootstrap.S'):
        (out / name).write_bytes((INPUT / name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], preferences=doc['browser_preferences']), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    build(p.parse_args().out)
