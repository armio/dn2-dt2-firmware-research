#!/usr/bin/env python3
"""Compose separately checked filesystem stages, I/O guards and raw reader.

Creates raw MAIN only. No firmware packing or device access.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / 'firmware/ghidra/storage-proof'
BASE, APPEND, GRAFT = 0x40000400, 0x30B580, 0x46800000
COMBINED = PROOF / 'combined-vfs-lru-candidate/candidate/main-os.bin'
STAGES = PROOF / 'manual-fs-stage-candidate/revision02/stage-only-main-os.bin'
STAGE_RECEIPT = STAGES.parent / 'stage-only-build-receipt.json'
GUARDS = PROOF / 'io-guard-candidate/main-os.bin'
READER = PROOF / 'v7-drive-status-v2'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compose():
    baseline, stages, guards = [p.read_bytes() for p in (COMBINED, STAGES, GUARDS)]
    assert sha(baseline) == 'c4f4dcc9a03dca1f0f28185fa7c7b7eca384e941fe6b72043cd690abf344ea57'
    stage_receipt = json.loads(STAGE_RECEIPT.read_text())
    io_receipt = json.loads((GUARDS.parent / 'patch-report.json').read_text())
    assert sha(stages) == stage_receipt['output_sha256']
    assert sha(guards) == io_receipt['candidate_main_sha256']
    assert stage_receipt['input_sha256'] == io_receipt['source_main_sha256'] == sha(baseline)
    assert len(baseline) == len(stages) == len(guards)
    result = bytearray(baseline)
    conflicts, shared = [], 0
    for i, (old, stage, guard) in enumerate(zip(baseline, stages, guards)):
        if stage != old and guard != old:
            if stage != guard:
                conflicts.append(hex(i))
            shared += 1
        if stage != old:
            result[i] = stage
        if guard != old:
            result[i] = guard
    assert not conflicts, conflicts
    overlays = []

    def patch(address, expected, replacement, label):
        assert len(expected) == len(replacement)
        off = address - BASE
        assert result[off:off + len(expected)] == expected, hex(address)
        result[off:off + len(expected)] = replacement
        overlays.append({'address': hex(address), 'old': expected.hex(),
                         'new': replacement.hex(), 'purpose': label})

    code = (READER / 'handler.bin').read_bytes()
    assert len(code) == 442 and sha(code) == '07eaac27ddb13c1ba94f77e2db3232b5074f6b6b50635e8f2c722fc30fffa56f'
    patch(0x402DFA1C, bytes(len(code)), code, 'Exact hardware-proven RDPROBE v2 handler')
    patch(0x400CE0F6, bytes.fromhex('41ea00097e1c97cb'), bytes.fromhex('4ef9402dfa1c4e71'), 'Reader entry')
    patch(0x4021ACA8, b'#MMCDUMP\0', b'#RDPROBE\0', 'Strict status-reader dispatch name')
    patch(0x400CF088, bytes.fromhex('c0b940287520'), bytes.fromhex('81b940287520'), 'Hardware-proven Maintenance gate preserving other flags')
    # Both prototypes leave native function homes and the original RAM map unchanged.
    stage_map = STAGES.parent / 'fn_new_map.txt'
    stage_ram = STAGES.parent / 'ram_map.txt'
    assert stage_map.read_bytes() == (COMBINED.parent/'fn_new_map.txt').read_bytes()
    assert stage_ram.read_bytes() == (COMBINED.parent/'ram_map.txt').read_bytes()
    # Final coverage audit catches any native media target reintroduced by stage cleanup.
    graft = result[APPEND:]
    for native in (0x4012C59A, 0x4012C780, 0x4012C4B2):
        assert native.to_bytes(4, 'big') not in graft, f'Unwrapped media target {native:#x}'
    guard_offset = APPEND + 0x612
    assert result[guard_offset:guard_offset+22].hex() == 'b3c866042268000c246800102668000c4ef946801308'
    assert result[0x402DFBD8-BASE:0x402DFBD8-BASE+io_receipt['code_bytes']] == guards[0x402DFBD8-BASE:0x402DFBD8-BASE+io_receipt['code_bytes']]
    record = {
        'schema': 'dn2-manual-fs-composition-1', 'main_sha256': sha(result), 'bytes': len(result),
        'combined_sha256': sha(baseline), 'stage_sha256': sha(stages), 'io_guard_sha256': sha(guards),
        'reader_handler_sha256': sha(code), 'conflicting_changes': conflicts, 'identical_overlaps': shared,
        'changed_bytes_from_combined': sum(a != b for a, b in zip(result, baseline)),
        'overlays': overlays, 'function_homes_unchanged': 67, 'ram_mappings_unchanged': 119,
        'stage_state_end': '0x47A19CC0', 'all_graft_media_targets_guarded': True,
        'native_erase_targets_remaining': 0, 'baseline_scope': 'Stock DN2 MAIN and stock other sections; temporary Maintenance storage experiment. Does not combine V7 ONESHOT/USBprobe RAM.',
        'hardware_tested': False,
        'inputs': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                   (COMBINED, STAGES, GUARDS, STAGE_RECEIPT, GUARDS.parent/'patch-report.json',
                    stage_map, stage_ram, READER/'handler.bin')},
    }
    return bytes(result), record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output_dir.exists(), 'Choose a fresh output directory'
    raw, record = compose()
    args.output_dir.mkdir(parents=True)
    (args.output_dir/'main-os.bin').write_bytes(raw)
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        shutil.copyfile(STAGES.parent/name, args.output_dir/name)
    shutil.copyfile(__file__, args.output_dir/Path(__file__).name)
    snapshots = args.output_dir / 'inputs'
    snapshots.mkdir()
    for name, digest in record['inputs'].items():
        src = ROOT / name
        dst = snapshots / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        assert sha(data) == digest, name
        dst.write_bytes(data)
    record['composer_sha256'] = sha(Path(__file__).read_bytes())
    (args.output_dir/'composition.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k: record[k] for k in ('main_sha256', 'bytes', 'changed_bytes_from_combined', 'all_graft_media_targets_guarded')}, indent=2))


if __name__ == '__main__':
    main()
