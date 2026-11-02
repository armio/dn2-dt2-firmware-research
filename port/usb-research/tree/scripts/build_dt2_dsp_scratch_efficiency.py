#!/usr/bin/env python3
"""Move only the stereo output wrappers' private register saves from DDR to L2."""
from pathlib import Path
import argparse
import json
import struct
import build_dt2_recorder_control_snapshot as P
import build_dt2_dsp_l1_code_fix as F

C, B, O = P.C, P.B, P.O
BASELINE_SHA = '7f54d9019a8658080d21616fcb2e827708eea9cc0be4de3dcba3c37bbc0e4739'
R004_SHA = '70a1ac7b68fe3f4eda796015af1586347f5b076ed73ce1bd632249b6f4f6f395'
START, END = 0x200f8d70, 0x200f9000
MOVES = [(0x805d9a00, START, 256), (0x805db000, START + 256, 396)]
WRAPPERS = [
    ('pan', 0xbcf000, 1042, 'dt2-stereo-pan-20261009', 'stereo-pan', 128),
    ('balance', 0xbd0000, 1046, 'dt2-stereo-balance-20261009', 'stereo-balance', 128),
    ('output', 0xbd1000, 5178, 'dt2-output-hook-20261009', 'output-hook', 198),
]


def literals(raw, lo, hi):
    visa, pointers = [], []
    for at, data in C.B.load_regions(raw):
        for off in range(0, len(data)-3, 2):
            upper, lower = struct.unpack_from('<HH', data, off)
            if lo <= (upper << 16 | lower) < hi:
                visa.append(at+off)
        for off in range((-at) & 3, len(data)-3, 4):
            if lo <= struct.unpack_from('<I', data, off)[0] < hi:
                pointers.append(at+off)
    return visa, pointers


def instructions(k, memory):
    for name, pc, size, folder, stem, expected in WRAPPERS:
        symbols = O.symbols((C.ROOT/'output/dn2-research'/folder/(stem+'.doj')).read_bytes())
        offsets = sorted(v*2 for n, v in symbols.items() if n.startswith('x_i')) + [size]
        for lo, hi in zip(offsets, offsets[1:]):
            yield name, pc+lo//2, F.decode_fixed(k, memory, pc+lo//2, hi-lo)


def build(parent, out):
    raw = (parent/'section_7.bin').read_bytes()
    doc = json.loads((parent/'build-receipt.json').read_text())
    assert C.SHA(raw) == doc['section7_sha256']
    assert (C.SHA(raw) in (BASELINE_SHA, R004_SHA) or
            doc.get('dsp_delivery_efficiency', {}).get('base_sha256') == BASELINE_SHA)
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    l2_regions = [(a, a+len(b)) for a, b in C.B.load_regions(raw)
                  if 0x20000000 <= a < 0x20100000]
    previous_end = max((end for _, end in l2_regions if end <= START), default=None)
    next_start = min((a for a, _ in l2_regions if a >= END), default=None)
    assert memory.read_sw(0x1c9b33, 6) == C.S.to_bytes(0x063e00bd1000)
    assert not any(a < END and START < a+len(b) for a, b in C.B.load_regions(raw))
    assert not any(literals(raw, START, END))
    alias_start, alias_end = 0xb80000+(START-0x20000000)//2, 0xb80000+(END-0x20000000)//2
    assert not any(literals(raw, alias_start, alias_end))
    image = bytearray(raw)
    patches = []
    for name, pc, ins in instructions(k, memory):
        if ins.length_bytes != 6 or ins.raw >> 40 not in (0x10, 0x11):
            continue
        address = ins.raw & 0xffffffff
        for old, new, size in MOVES:
            if not old <= address < old+size:
                continue
            assert ins.type_name == '14a'
            value = (ins.raw & ~0xffffffff) | (new+address-old)
            physical = C.S.code_address(pc, window='l2')
            before, after = C.S.to_bytes(ins.raw), C.S.to_bytes(value)
            C.B.write_span(image, physical, after)
            patches.append(dict(wrapper=name, pc=hex(pc), physical=hex(physical),
                old=hex(address), new=hex(new+address-old), before=before.hex(), after=after.hex()))
    for name, _, _, _, _, count in WRAPPERS:
        assert sum(p['wrapper'] == name for p in patches) == count
    closure = []
    for old, new, size in MOVES:
        visa, pointers = literals(raw, old, old+size)
        expected = {int(p['physical'], 16)+2 for p in patches if old <= int(p['old'], 16) < old+size}
        assert set(visa) == expected and not pointers
        assert not any(literals(bytes(image), old, old+size))
        closure.append(dict(old=hex(old), new=hex(new), bytes=size,
            absolute_references=len(visa), other_visa_literals=0, data_pointers=0))
    result = C.B.insert_before_final(bytes(image), C.B.block(START, bytes(END-START)))
    walk = C.B.walk(result)
    first, last = walk.blocks[7], walk.blocks[-1]
    result = result[:first.offset]+C.B.block(first.target, flags=first.flags,
        argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=C.SHA(raw), section7_sha256=C.SHA(result), flash_ready=False)
    doc['dsp_scratch_efficiency'] = dict(base=str((parent/'section_7.bin').resolve()),
        base_sha256=C.SHA(raw), original_dsp_sha256=R004_SHA if C.SHA(raw)==R004_SHA else BASELINE_SHA, patches=patches,
        moves=closure, reservation=[hex(START), hex(END)], initialized_bytes=END-START,
        trailing_guard_bytes=4,
        active_path='Native1C9B33 -> BD1000 -> BD0000 once per Machine5..10 voice; BCF000 pan ABI retained.',
        memory_audit=dict(loaded_or_fill_overlap=False, preexisting_visa_literals=0,
            preexisting_data_pointers=0, previous_loaded_end=hex(previous_end) if previous_end is not None else None,
            next_loaded_start=hex(next_start) if next_start is not None else None, native_dma_excluded=['0x200fa000','0x200fe000'],
            program_alias=[hex(alias_start),hex(alias_end)], preexisting_program_alias_references=0,
            direct_access_only=True, constructed_pointer_references=0,
            simd='Only existing Type14A literal addresses change. R/S companion accesses remain within the 256/396-byte reservations; final fields are unpaired M/system registers. Four trailing guard bytes retained.',
            limitation='Loaded/fill spans and literal closure exclude known owners; cannot prove absence of every arbitrary computed writer.'),
        ddr_register_save_bytes_per_block='792 + 512 * sampler_voice_count',
        contract='Keep every save/restore, register order, instruction width, branch, coefficient, state history, sample, effect and USB/Recorder operation. Only private serialized save destinations move to L2. Old DDR save bytes remain allocated but unreferenced.',
        limits=['Instruction count unchanged. Actual speedup and cache/arbitration effects require matched hardware timing.',
            'Retains the existing native scalar entry ABI. This is not a repair for forcing SIMD on during register saves.',
            'Elapsed render counters include interrupts and do not measure total DSP utilization.'])
    out.mkdir(parents=True, exist_ok=False)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result), patches=len(patches), reservation=[hex(START),hex(END)])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('parent', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
