#!/usr/bin/env python3
"""Reserve bounded space after T1E2's private runtime; firmware bytes unchanged."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 0x47AD0000


def prepare(parent, out):
    doc = json.loads((parent / 'build-receipt.json').read_text())
    raw = (parent / 'main-os.bin').read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == doc['main_sha256']
    stable = json.loads((ROOT / 'firmware/Digitone_II_OS1.11_DT2_SAMPLERS_T1E2_STABLE.manifest.json').read_text())
    assert digest == stable['main_sha256']
    copy = doc['runtime_copy']
    start, old_limit = int(copy['destination'], 16), int(doc['runtime_limit'], 16)
    assert start + copy['bytes'] <= old_limit < LIMIT
    source = int(copy['source'], 16) - 0x40000400
    assert raw[source:source+copy['bytes']] == (parent / 'runtime.bin').read_bytes()
    owners = json.loads((ROOT / 'output/dn2-research/combined-ram-ownership-20261008/result.json').read_text())
    for region in owners['heap_regions'] + owners['task_stacks']:
        assert not (start < int(region['end'], 16) and int(region['start'], 16) < LIMIT), region
    reset_top = int(owners['reset_stack_top'], 16)
    assert reset_top - LIMIT >= 0x500000
    native = (ROOT / 'firmware/dn2-1.11/section_3_MAIN_OS.bin').read_bytes()
    config = int(owners['native_allocator_config_address'], 16) - 0x40000400
    assert raw[config:config+24] == native[config:config+24]
    # Task-creation argument sites remain native; runtime expansion must not
    # silently rely on stale ownership after moving an RTOS task's stack.
    for region in owners['task_stacks']:
        at = int(region['argument_bytes_address'], 16) - 0x40000400
        end = int(region['call'], 16) - 0x40000400 + 6
        assert raw[at:end] == native[at:end], region
    doc['runtime_limit'] = hex(LIMIT)
    doc['recorder_runtime_reservation'] = dict(
        previous_limit=hex(old_limit), limit=hex(LIMIT), added_bytes=LIMIT-old_limit,
        parent_main_sha256=digest, firmware_bytes_unchanged=True,
        native_allocator_and_task_creation_unchanged=True,
        reset_stack_top=hex(reset_top), reset_stack_distance=reset_top-LIMIT,
        scope='Excludes recovered heap/fixed task owners; physical maximum idle/exception stack depth is unmeasured.')
    out.mkdir(parents=True, exist_ok=False)
    for name in ('main-os.bin', 'runtime.bin', 'bootstrap.S', 'fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((parent / name).read_bytes())
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    print(json.dumps(doc['recorder_runtime_reservation'], indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('parent', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.parent, args.out)
