#!/usr/bin/env python3
"""T1D4: identify the first invalid native heap free-list publication or use."""
from pathlib import Path
import argparse
import json
import re
import build_dt2_directory_model as L

B = L.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-boot-heap-watch-20261010'
SHA = '8bfe1cc41125f09462cca6bc81bc7ed89e2e4953e9bf8c3d339e87bf60db756f'
SITES = [
    ('get', 0x4011fe00, '206f0004202f0008'),
    ('set', 0x4011fe1e, '206f0004202f0008'),
]


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray(raw[src - B.BASE:src - B.BASE + copy['bytes']])
    entry = base + len(payload)
    out.mkdir(parents=True, exist_ok=False)
    source = (
        '.equ WATCH_DONE,' + doc['boot_kit_watch']['methods']['boot_watch_done'] + '\n'
        '.equ WATCH_PROJECT,' + doc['boot_heap_watch']['methods']['boot_heap_project'] + '\n'
        + (B.T.ROOT / 'scripts/asm/dn2_boot_freelist_watch.S').read_text()
    )
    payload.extend(B.R.assemble(source, entry, out, 'boot-freelist-watch'))
    payload.extend(bytes(-len(payload) % 4))
    symbols = {
        match[2]: int(match[1], 16)
        for match in re.finditer(
            r'(?m)^([0-9a-f]+) [Tt] (boot_freelist_\w+)$',
            B.T.run([B.T.BIN / 'binutils/nm-new', '-n', out / 'boot-freelist-watch.elf']),
        )
    }
    assert base + len(payload) <= int(doc['runtime_limit'], 16)
    image = bytearray(raw[:src - B.BASE]) + payload
    patches = []
    for name, addr, hx in SITES:
        before = bytes.fromhex(hx)
        assert image[addr - B.BASE:addr - B.BASE + len(before)] == before
        after = b'\x4e\xf9' + B.BE(symbols['boot_freelist_' + name]) + b'\x4e\x71'
        image[addr - B.BASE:addr - B.BASE + len(before)] = after
        patches.append(dict(name=name, address=hex(addr), before=hx, after=after.hex()))
    boot = B.BASE + len(image)
    asm = (INPUT / 'bootstrap.S').read_text().replace(
        f'#{copy["bytes"] // 4},%d1', f'#{len(payload) // 4},%d1'
    )
    assert asm != (INPUT / 'bootstrap.S').read_text()
    image.extend(B.R.assemble(asm, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    doc.update(
        main_sha256=B.T.SHA(image), bytes=len(image),
        runtime_copy={**copy, 'bytes': len(payload)},
        runtime_sha256=B.T.SHA(payload), bootstrap=hex(boot),
        bootstrap_bytes=len(image) - (boot - B.BASE), flash_ready=False,
    )
    doc['boot_freelist_watch'] = dict(
        methods={key: hex(value) for key, value in symbols.items()},
        patches=patches, marker='54423444',
        purpose='Detect invalid native free-list heads before publication or consumption; no allocator repair.',
        allocator='0x4029eb9c', history_entries=22, history_entry_bytes=16,
        history_fields=['caller', 'order', 'new head', 'old head'],
        reasons={
            '61': 'getter head alignment/range/sentinel failure',
            '62': 'getter head overlaps live Project',
            '71': 'setter head alignment/range/sentinel failure',
            '72': 'setter head overlaps live Project',
        },
        stack_words=[
            'marker', 'reason', 'Project pointer', 'native caller', 'order',
            'proposed or observed head', 'previous or current head',
            'last setter caller for this order', 'last setter order',
            'last setter new head', 'last setter old head', 'native heap initialized flag',
        ],
        limits=[
            'Only native allocator object and orders 0..21 are watched.',
            'The watch ends at the first successful published Project Kit reset.',
            'A direct write is detected when a guarded getter next reads that head.',
            'History is zero until this diagnostic observes a successful native setter.',
        ],
    )
    for name, data in [('main-os.bin', image), ('runtime.bin', payload)]:
        (out / name).write_bytes(data)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((INPUT / name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'], freelist_watch=doc['boot_freelist_watch']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
