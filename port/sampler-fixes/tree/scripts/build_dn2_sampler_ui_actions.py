#!/usr/bin/env python3
"""Normalize the sampler Source clear action's current-page sentinel."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct

BASE = 0x40000400
NATIVE_CLEAR = 0x40018532
SHA = lambda data: hashlib.sha256(data).hexdigest()
BE = lambda value: struct.pack('>I', value)


def build(parent, out):
    raw = bytearray((parent/'main-os.bin').read_bytes())
    runtime = bytearray((parent/'runtime.bin').read_bytes())
    doc = json.loads((parent/'build-receipt.json').read_text())
    assert 'boot_tail' not in doc, 'Requires expanded parent image'
    assert 'sampler_ui_actions' not in doc
    assert SHA(raw) == doc['main_sha256'] and SHA(runtime) == doc['runtime_sha256']
    region = doc['runtime_copy']
    source, base = int(region['source'], 16), int(region['destination'], 16)
    assert len(runtime) == region['bytes']
    assert raw[source-BASE:source-BASE+len(runtime)] == runtime
    span = next(s for s in doc['source_view']['spans'] if s['name'] == 'source_vtables')
    site = int(span['runtime'], 16)+8+0xdc
    previous = struct.unpack_from('>I', runtime, site-base)[0]
    # DT2 Source accepts an explicit page. DN2's key handler passes -1 for
    # current page; its MultiSource override resolves that through vtable+88.
    assert runtime[previous-base:previous-base+16] == bytes.fromhex(
        '4e56fff02f0a2f0248780001242e000c')
    assert raw[0x401d49a0+0xdc-BASE:0x401d49a0+0xe0-BASE] == BE(NATIVE_CLEAR)
    assert raw[NATIVE_CLEAR-BASE:NATIVE_CLEAR-BASE+36] == bytes.fromhex(
        '4e56fff070ff2f0a2f02246e0008242e000cb082660e20522f0a206800884e90588f2400')
    runtime[site-base:site-base+4] = BE(NATIVE_CLEAR)
    raw[source-BASE:source-BASE+len(runtime)] = runtime
    doc['sampler_ui_actions'] = dict(
        parent_sha256=doc['main_sha256'], clear_vtable_site=hex(site),
        previous_clear=hex(previous), native_clear=hex(NATIVE_CLEAR),
        changed='Resolve current-page sentinel before native clear and undo handling.',
        samp_browser_changed=False, dsp_changed=False, hardware_validated=False)
    doc.update(main_sha256=SHA(raw), runtime_sha256=SHA(runtime), flash_ready=False)
    out.mkdir(parents=True, exist_ok=False)
    (out/'main-os.bin').write_bytes(raw)
    (out/'runtime.bin').write_bytes(runtime)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('bootstrap.S', 'fn_new_map.txt', 'ram_map.txt'):
        shutil.copyfile(parent/name, out/name)
    print(json.dumps(dict(main_sha256=doc['main_sha256'], **doc['sampler_ui_actions']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
