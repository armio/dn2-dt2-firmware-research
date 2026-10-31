#!/usr/bin/env python3
"""Stage exact DT2 browser code and operand references; never modify firmware.

This is the donor input for the native-browser port. Staging is deliberately
distinct from relocation: unresolved pool, view-owner and preview dependencies
must not be treated as DN2 addresses or replaced with success stubs.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, '@DIGIKIT@')
from dt2.coldfire import disasm

BASE = 0x40000400
DONOR = ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin'
SHA = '57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'
OUT = ROOT/'output/dn2-research/dt2-native-browser-port-20261009'
FUNCTIONS = {
    'source_open_browser': (0x40017ed0, 0x400181fe),
    'source_encoder': (0x400184ea, 0x400187c4),
    'list_set_slot': (0x4001e0ac, 0x4001e0f8),
    'list_set_mode': (0x4001e0f8, 0x4001e104),
    'list_set_preview_mode': (0x4001e104, 0x4001e110),
    'list_get_slot': (0x4001e17a, 0x4001e1fe),
    'list_close': (0x4001e1fe, 0x4001e268),
    'list_constructor': (0x4001e4ae, 0x4001e69e),
    'list_draw': (0x4001e78a, 0x4001ebc8),
    'list_event': (0x4001ebc8, 0x4001efac),
    'list_shared_factory': (0x40199eb2, 0x40199f22),
}
# The event dispatcher contains a 15-entry signed-relative jump table. It
# must be retained as data, not decoded as apparently valid instructions.
DATA = ((0x4001ebf8, 0x4001ec16),)


def main():
    raw = DONOR.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    OUT.mkdir(exist_ok=True)
    refs, staged = [], []
    for name, (start, end) in FUNCTIONS.items():
        blob = raw[start-BASE:end-BASE]
        (OUT/f'{name}.bin').write_bytes(blob)
        ranges = [(start, end)]
        for lo, hi in DATA:
            if start <= lo < end:
                ranges = [(start, lo), (hi, end)]
        lines = []
        for lo, hi in ranges:
            for pc, hx, mn, ops in disasm(raw, BASE, lo, hi):
                lines.append(f'{pc:08x} {hx:24s} {mn:10s} {ops}')
                code = bytes.fromhex(hx)
                for m in re.finditer(r'\$([0-9a-f]{8})', ops):
                    target = int(m[1], 16)
                    if not 0x40000000 <= target < 0x48000000:
                        continue
                    encoded = code.find(struct.pack('>I', target))
                    refs.append(dict(function=name, instruction=hex(pc),
                                     mnemonic=mn, operands=ops, target=hex(target),
                                     absolute_operand_offset=None if encoded < 0 else pc-start+encoded,
                                     staged_target=next((n for n,(a,b) in FUNCTIONS.items() if a<=target<b), None),
                                     dn2_resolution=None))
        (OUT/f'{name}.asm').write_text('\n'.join(lines)+'\n')
        staged.append(dict(name=name, start=hex(start), end=hex(end), bytes=len(blob),
                           sha256=hashlib.sha256(blob).hexdigest()))
    table = [0x4001ebf8+x for x in struct.unpack_from('>15h',raw,0x4001ebf8-BASE)]
    assert all(0x4001ec16 <= x < 0x4001efac and x % 2 == 0 for x in table)
    report = dict(donor=str(DONOR), donor_sha256=SHA, functions=staged,
                  references=refs, event_jump_table_targets=[hex(x) for x in table],
                  flash_ready=False, relocated=False,
                  limitation='Direct operand inventory only; indirect vtable/callback targets require explicit mapping.',
                  required_adapters=['DN2 view lifecycle and encoder routing',
                                     'Project pool slots, names and persistent sample identity',
                                     'Preview voice and commit/cancel callbacks',
                                     '+Drive directory navigation and quick assignment',
                                     'Automatic restoration of project samples',
                                     'Whole SAMP transport, OFF silence and sample locks'])
    (OUT/'donor-manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'functions':len(staged), 'donor_bytes':sum(x['bytes'] for x in staged),
                      'operand_references':len(refs), 'flash_ready':False, 'output':str(OUT)},indent=2))


if __name__ == '__main__':
    main()
