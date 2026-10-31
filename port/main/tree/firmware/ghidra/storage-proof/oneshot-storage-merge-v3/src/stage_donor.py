#!/usr/bin/env python3
"""Stage the DT2 donor name-chain for true byte relocation (M3b).

Extracts every function in the DT2 1.16 SAMP name path with its extent,
enumerates absolute-address operands needing relocation, and records the
data structures the donor expects. Offline; reads the frozen DT2 image only.
"""
import hashlib, json, re, struct
from pathlib import Path

ROOT = Path('@WORKSPACE@')
IMG = ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin'
IMG.mkdir(parents=True, exist_ok=True)
import subprocess
subprocess.run([str(ROOT/'elektron-firmware-tool'), '-i', str(ROOT/'firmware/Digitakt_II_OS1.16.syx'),
                '-d', '3', '-o', str(IMG)], check=True, capture_output=True)
img = (IMG/'section_3_MAIN_OS.bin').read_bytes()
BASE = 0x40000400
SHA = hashlib.sha256(img).hexdigest()

FUNCS = {
    'helper':      (0x400164E0, 0x40016560),  # name helper (this, value) -> local buffer -> format
    'clamp':       (0x401997A8, 0x401997B8),  # value > 0x400 -> 0
    'lookup':      (0x401537A8, 0x401537B8),  # table[value] -> entry pointer
    'strlen':      (0x4018A498, 0x4018A4AC),  # C strlen
    'format':      (0x401E7A64, 0x401E7AC6),  # entry -> copy + suffix into caller buffer
    'builder':     (0x401E75B6, 0x401E7680),  # heap string builder
}
STRINGS = {
    'empty':  (0x4023F364, 1),   # '' shown for out-of-range values
    'off':    (0x4023A62D, 4),   # 'OFF'
    'dash':   (0x40226ED6, 4),   # '---'
}
TABLE = 0x405BC768  # pool directory: 1024 x 4-byte pointers to name strings

manifest = {'schema': 'dn2-m3b-donor-stage-1', 'dt2_main_sha256': SHA, 'base': hex(BASE),
            'pool_table': hex(TABLE), 'functions': {}, 'strings': {}}
for name, (va, end) in FUNCS.items():
    off = va - BASE
    data = img[off:off+(end-va)]
    (IMG/f'{name}.bin').write_bytes(data)
    # enumerate 32-bit absolute operands: jsr/pea/lea absolute-long forms
    ops = []
    i = 0
    while i + 2 <= len(data):
        w = struct.unpack_from('>H', data, i)[0]
        if w in (0x4EB9, 0x4EF9, 0x4879, 0x45F9, 0x41F9, 0x2F3C, 0x203C, 0x227C, 0x247C, 0x2F2F and 0xFFFF):
            if i + 6 <= len(data):
                target = struct.unpack_from('>I', data, i+2)[0]
                if 0x40000000 <= target < 0x50000000:
                    ops.append({'offset': hex(i), 'site': hex(va+i), 'opcode': hex(w), 'target': hex(target)})
                    i += 6
                    continue
        i += 2
    manifest['functions'][name] = {'va': hex(va), 'end': hex(end), 'bytes': len(data),
                                   'sha256': hashlib.sha256(data).hexdigest(), 'absolute_operands': ops}
for name, (va, n) in STRINGS.items():
    off = va - BASE
    data = img[off:off+n]
    (IMG/f'str_{name}.bin').write_bytes(data)
    manifest['strings'][name] = {'va': hex(va), 'bytes': list(data), 'sha256': hashlib.sha256(data).hexdigest()}
(IMG/'donor-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({k: (v['va'], v['bytes'], [o['target'] for o in v['absolute_operands']])
                  for k, v in manifest['functions'].items()}, indent=1))
print('strings:', {k: bytes(s['bytes']) for k, s in manifest['strings'].items()})
