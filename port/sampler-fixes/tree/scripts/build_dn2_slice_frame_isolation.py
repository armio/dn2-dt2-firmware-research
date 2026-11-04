#!/usr/bin/env python3
"""Keep saved SLICE keys out of native DSP marker fields on held blocks."""
from pathlib import Path
import argparse, json
from build_dt2_slice_live import B


def build(inp, out):
    doc = json.loads((inp/'build-receipt.json').read_text())
    image = bytearray((inp/'main-os.bin').read_bytes())
    runtime = bytearray((inp/'runtime.bin').read_bytes())
    parent_sha = B.T.SHA(image)
    assert parent_sha == doc['main_sha256']
    c = doc['runtime_copy']; src, base = int(c['source'], 16), int(c['destination'], 16)
    assert image[src-B.BASE:src-B.BASE+c['bytes']] == runtime
    entry = int(doc['slice_live']['methods']['slice_frame_hook'], 16)
    address = entry+0x24
    offset = address-base
    # The native marker producer is already bounded and preserves all live
    # frame registers. Its current caller alone skips held-note blocks.
    assert runtime[offset-8:offset+2] == bytes.fromhex('73f980005e820101673a')
    runtime[offset:offset+2] = bytes.fromhex('4e71')
    image[src-B.BASE:src-B.BASE+c['bytes']] = runtime
    doc.update(main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(runtime), flash_ready=False)
    doc['slice_frame_isolation'] = dict(parent=str(inp.resolve()), parent_main_sha256=parent_sha,
        patches=[dict(address=hex(address), before='673a', after='4e71')],
        producer=doc['slice_live']['original_marker_wrapper'], marker_fields=[238,242,246],
        cause='The held frame copied source slot40 from the SLF1 descriptor into the DSP loop marker. The DT2 setup adapter consumes marker fields on held blocks as well as triggers.',
        behavior='Run the existing original DT2 marker producer for every SLICE block, using the same live controls, note, and raw Sound or temporary snapshot. All other Machines retain native packing.',
        persistence='SLF1 descriptor bytes, companion files and native Sound save/load hooks are unchanged.',
        limits=['This fixes a demonstrated marker-field alias; the cause of the reported hour-idle audio stop remains unknown.',
                'Physical playback confirmation is pending.'])
    doc['slice_live']['limits'] = ['SLICE marker packing now runs on held blocks; original producer and bounds behavior remain in use.',
        'Physical playback confirmation for held marker isolation is pending.']
    out.mkdir(parents=True, exist_ok=False)
    (out/'main-os.bin').write_bytes(image); (out/'runtime.bin').write_bytes(runtime)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('bootstrap.S','fn_new_map.txt','ram_map.txt'):
        (out/name).write_bytes((inp/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], patch_address=hex(address), changed_bytes=2),indent=2))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True); p.add_argument('--out',type=Path,required=True)
    a=p.parse_args(); build(a.input,a.out)
