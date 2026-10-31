#!/usr/bin/env python3
"""Bind original DT2 cursor semantics to DN2's native telemetry receive buffer."""
from pathlib import Path
import argparse, json, struct
import build_dn2_source_page_route as P
B = P.B
INPUT = B.T.ROOT/'output/dn2-research/dn2-source-page-route-20261009'
SHA = 'ae24042aaac5cf76606c37c197fe21f5a42682aa101f009c5500c1a5043fd1d2'
READERS = ((0x400cd726, 0x400cfa98, 32, 'position_coarse'),
           (0x400cd746, 0x400cfab8, 30, 'position_fine'),
           (0x400cd764, 0x400cfad6, 30, 'active'))


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes(); assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT/'build-receipt.json').read_text())
    donor = B.M.S.DONOR.read_bytes()
    copy = doc['runtime_copy']; src = int(copy['source'], 16)
    base = int(copy['destination'], 16)
    image = bytearray(raw); payload = bytearray((INPUT/'runtime.bin').read_bytes())
    evidence, patches = [], []
    for old, native, count, name in READERS:
        original = bytearray(donor[old-B.BASE:old-B.BASE+count])
        body = raw[native-B.BASE:native-B.BASE+count]
        # Same algorithm and field index; only the native receive-buffer base
        # differs. Do not infer semantics from a similar-looking function.
        assert original[12:16] == B.BE(0x80001000)
        original[12:16] = B.BE(0x80001a20)
        assert bytes(original) == body, name
        evidence.append(dict(name=name, donor=hex(old), native=hex(native),
                             bytes=count, native_sha256=B.T.SHA(body)))
        for key, component in doc.items():
            if not isinstance(component, dict): continue
            for edit in component.get('edits', []):
                if edit.get('target') != hex(old): continue
                assert edit['kind'] == 'absolute operand'
                at = int(edit['runtime'], 16); before = int(edit['binding'], 16)
                assert payload[at-base:at-base+4] == B.BE(before)
                payload[at-base:at-base+4] = B.BE(native)
                edit['binding'] = hex(native)
                patches.append(dict(component=key, operand=hex(at),
                                    before=hex(before), after=hex(native), reader=name))
    assert len(patches) == 4
    image[src-B.BASE:src-B.BASE+len(payload)] = payload
    doc.update(baseline_sha256=SHA, main_sha256=B.T.SHA(image),
               runtime_sha256=B.T.SHA(payload), flash_ready=False)
    doc['sample_cursor_readers'] = dict(native_twins=evidence, patches=patches,
        receive_base='0x80001a20', field_byte_offset='0xa9c',
        methods={name:hex(native) for _,native,_,name in READERS},
        dsp_producer_connected=False,
        remaining=['Publish original DT2 sample-position words through the native DSP audio reply.',
                   'Complete MAIN/DSP/FS composition and hardware validation.'])
    out.mkdir(parents=True, exist_ok=False)
    (out/'main-os.bin').write_bytes(image); (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('bootstrap.S', 'fn_new_map.txt', 'ram_map.txt'):
        (out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], patches=patches,
                          dsp_producer_connected=False), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True); build(p.parse_args().out)
