#!/usr/bin/env python3
"""Set the combined browser-performance candidate's T1E1 identity without device I/O."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


MAIN_BASE = 0x40000400
IDENTITY = 0x47AA5A0C
PARENT_MAIN = '28fa87afd36ee119c3183822920773761a2f611356ecc9a1757125a495f10eae'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(source, out):
    source, out = source.resolve(), out.resolve()
    assert not out.exists(), 'Choose a fresh release directory'
    doc = json.loads((source / 'build-receipt.json').read_text())
    raw = bytearray((source / 'main-os.bin').read_bytes())
    assert sha(raw) == doc['main_sha256']
    assert doc['sample_browser_names']['base_sha256'] == PARENT_MAIN
    assert not any(key.startswith('drum_') for key in doc), 'DRUM is excluded'
    copy = doc['runtime_copy']
    runtime = int(copy['source'], 16) - MAIN_BASE
    identity = runtime + IDENTITY - int(copy['destination'], 16)
    assert raw[identity:identity+4] == b'T1E0'
    before = sha(raw)
    raw[identity:identity+4] = b'T1E1'
    payload = raw[runtime:runtime+copy['bytes']]
    doc.update(main_sha256=sha(raw), runtime_sha256=sha(payload), flash_ready=False)
    doc['sample_browser_release'] = dict(
        base=str(source / 'main-os.bin'), base_sha256=before,
        identity_before='T1E0', identity_after='T1E1',
        runtime_address=hex(IDENTITY), changed_bytes=1)
    out.mkdir(parents=True)
    (out / 'main-os.bin').write_bytes(raw)
    (out / 'runtime.bin').write_bytes(payload)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    # Retain component sources and mappings, but no checks with the old hash.
    for path in source.iterdir():
        if (path.is_file() and path.name not in ('main-os.bin', 'runtime.bin')
                and path.suffix in ('.S', '.asm', '.txt', '.elf', '.bin')):
            shutil.copyfile(path, out / path.name)
    print(json.dumps(dict(build='T1E1', main_sha256=doc['main_sha256'],
                         runtime_end=hex(int(copy['destination'], 16)+copy['bytes'])), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    build(args.input, args.out)
