#!/usr/bin/env python3
"""Move the remaining imported ONESHOT code out of data-cache-enabled L1 banks.

Code boundaries come from original producer metadata and classified donor
spans. Sample records, coefficients, transport state and other data stay put.
"""
from pathlib import Path
import argparse
import json
import struct

import build_dt2_dsp_startup_fix as B

C = B.C
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-decimator-l2-20261010/section_7.bin'
BASE_SHA = 'f4db86c53e7247fd914e042b6d9fae9605639fbf4c50634cac784846423f4d12'
INVENTORY = BASE.parent.parent / 'dt2-samplers-t1dc-20261010/l1-imported-code-inventory.json'


def mapped(value, rows):
    for row in rows:
        if row['old'] <= value < row['old'] + row['bytes'] // 2:
            return row['new'] + value - row['old']
    return value


def decode_fixed(k, memory, pc, size=None):
    import sharc_disasm as dis
    ins = k.st.decode_at(memory, None, pc)
    # A native-process splice replaces six bytes and leaves the rest of the
    # displaced ten-byte sequence unreachable before the next trusted label.
    if size is not None and size > 6 and ins.length_bytes == 6 and ins.raw >> 24 == 0x063e00:
        return ins
    if size is not None and ins.length_bytes != size:
        matches = [candidate for candidate in
                   [dis.decode_loaded_at(memory, pc),
                    *dis._narrow_candidates_from_words(dis._loaded_words(memory, pc), pc * 2, 64)]
                   if candidate.kind == 'confident' and candidate.length_bytes == size]
        assert len({(x.raw, x.type_name) for x in matches}) == 1, (hex(pc), size, ins)
        ins = matches[0]
    assert ins.kind != 'unknown' and ins.length_bytes in (2, 4, 6), hex(pc)
    return ins


def imported_instructions(k, memory, row):
    start, end = row['old'], row['old'] + row['bytes'] // 2
    offsets = row.get('instruction_offsets')
    if offsets is None:
        pc = start
        while pc < end:
            ins = decode_fixed(k, memory, pc)
            assert pc + ins.length_bytes // 2 <= end
            yield pc, ins
            pc += ins.length_bytes // 2
        assert pc == end
        return
    consumed = start
    for index, off in enumerate(offsets):
        pc = start + off // 2
        if pc < consumed:
            continue  # A guarded six-byte hook replaced several shorter original instructions.
        assert pc == consumed, (hex(pc), hex(consumed))
        nxt = offsets[index + 1] if index + 1 < len(offsets) else row['bytes']
        current = decode_fixed(k, memory, pc)
        if current.length_bytes == 6 and current.raw >> 24 == 0x063e00:
            ins = current
        else:
            ins = decode_fixed(k, memory, pc, nxt - off)
        assert pc + ins.length_bytes // 2 <= end
        yield pc, ins
        consumed = pc + ins.length_bytes // 2
    assert consumed == end, (row['name'], hex(consumed), hex(end))


def instruction_sources(k, memory, doc, rows):
    """All moved code, original native inbound sites and classified added code."""
    all_ins = {}
    for row in rows:
        all_ins.update(imported_instructions(k, memory, row))
    for pc in (0x1c2872, 0x1c9448):
        all_ins[pc] = decode_fixed(k, memory, pc)
    original = B.decode_view(k, B.BASE.read_bytes())
    for row in doc['dsp_startup_fix']['placements']:
        if row['kind'] != 'code':
            continue
        pcs = B.boundaries(k, original, row)
        for pc, nxt in zip(pcs, pcs[1:] + [row['old'] + row['bytes'] // 2]):
            current = row['new'] + pc - row['old']
            all_ins[current] = decode_fixed(k, memory, current, 2 * (nxt - pc))
    # Later diagnostics are scalar six-byte sequences, including replayed
    # six-byte original instructions. The native decimator has no new inbound
    # reference, but include its classified body in the closure audit.
    for key in ('dsp_playback_diagnostic', 'dsp_render_diagnostic',
                'dsp_fatal_diagnostic', 'dsp_code_diagnostic'):
        info = doc[key]
        start = int(info['code'], 16)
        for pc in range(start, start + info['code_bytes'] // 2, 3):
            all_ins[pc] = decode_fixed(k, memory, pc, 6)
    pc, end = 0xbf4000, 0xbf4000 + 522 // 2
    while pc < end:
        ins = decode_fixed(k, memory, pc)
        all_ins[pc] = ins
        pc += ins.length_bytes // 2
    assert pc == end
    return all_ins


def rewrite(ins, pc, dest, rows):
    import sharcinv
    f = sharcinv.merge_fields(ins.fields)
    raw, field, value = ins.raw, None, None
    if ins.type_name in ('25a_direct', '8a_abs'):
        field, value = 'addr24', f['addr']
    elif ins.type_name in ('25a_pcrel', '8a_rel'):
        field, value = 'rel24', pc + C.S.get_field(raw, 'rel24')
    elif ins.type_name in ('17a', '16a', '19a'):
        field, value = 'data32', f['data']
    elif ins.type_name in ('14a', '14d'):
        field, value = 'addr32', f['addr']
    if field is None:
        return raw, None
    target = mapped(value, rows)
    if target == value and (field != 'rel24' or dest == pc):
        return raw, None
    kind = field
    if field == 'rel24' and not -(1 << 23) <= target - dest < (1 << 23):
        assert ins.type_name == '8a_rel' and raw >> 40 == 7, (hex(pc), ins.type_name)
        raw &= ~(1 << 40)
        field, kind = 'addr24', 'relative-to-absolute'
    fixed = C.S.retarget(raw, field, dest, target)
    return fixed, dict(pc=hex(pc), new_pc=hex(dest), field=kind,
                       before=hex(value), after=hex(target),
                       before_instruction=hex(ins.raw), after_instruction=hex(fixed))


def build(out):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    doc = json.loads((BASE.parent / 'build-receipt.json').read_text())
    inv = json.loads(INVENTORY.read_text())
    assert inv['section7_sha256'] == BASE_SHA
    rows = []
    blocks = C.B.walk(raw).blocks
    for item in inv['active_or_conservatively_retained_code']:
        row = dict(index=item['block_index'], name=item['name'], kind='code',
                   old=int(item['sw'], 16), new=int(item['suggested_new_sw'], 16),
                   old_physical=int(item['physical'], 16),
                   new_physical=int(item['suggested_new_physical'], 16),
                   bytes=item['bytes'], code_sha256=item['code_sha256'],
                   producer=item['producer'])
        if 'instruction_offsets' in item:
            row['instruction_offsets'] = item['instruction_offsets']
        block = blocks[row['index']]
        assert block.target == row['old_physical'] and block.has_payload
        assert C.SHA(raw[block.payload_at:block.payload_at + row['bytes']]) == row['code_sha256']
        rows.append(row)
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    instructions = instruction_sources(k, memory, doc, rows)
    image = bytearray(raw)
    bodies = {row['old']: bytearray(memory.read_sw(row['old'], row['bytes'])) for row in rows}
    changes = []
    for pc, ins in sorted(instructions.items()):
        dest = mapped(pc, rows)
        fixed, event = rewrite(ins, pc, dest, rows)
        if event is None:
            continue
        assert ins.length_bytes == 6
        if dest == pc:
            physical = C.S.code_address(pc, window='l2') if pc >= 0xb80000 else C.S.code_address(pc)
            C.B.write_span(image, physical, C.S.to_bytes(fixed))
        else:
            owner = next(row for row in rows if row['old'] <= pc < row['old'] + row['bytes'] // 2)
            offset = (pc - owner['old']) * 2
            bodies[owner['old']][offset:offset + 6] = C.S.to_bytes(fixed)
        changes.append(event)
    # The only typed function pointer outside code is the legacy loader's
    # dispatch entry. Do not scan samples, float tables or state as pointers.
    pointers = []
    for entry in inv['function_pointer_data']:
        physical, old = int(entry['physical'], 16), int(entry['target'], 16)
        assert physical == 0x282de690 and old == 0x16eb00
        before = C.B.read_span(raw, physical, 4)
        assert struct.unpack('<I', before)[0] == old
        new = mapped(old, rows)
        C.B.write_span(image, physical, struct.pack('<I', new))
        pointers.append(dict(physical=hex(physical), before=hex(old), after=hex(new)))
    regions = C.B.load_regions(raw)
    appended = []
    for row in rows:
        address, body = row['new_physical'], bytes(bodies[row['old']])
        assert 0x200e9000 <= address < address + len(body) <= 0x200f0000
        assert not any(address < a + len(b) and a < address + len(body) for a, b in regions)
        regions.append((address, body))
        appended.append(C.B.block(address, body))
        row['relocated_sha256'] = C.SHA(body)
        row['instruction_count'] = sum(1 for _ in imported_instructions(k, memory, row))
    result = C.B.insert_before_final(bytes(image), b''.join(appended))
    walk = C.B.walk(result)
    first, final = walk.blocks[7], walk.blocks[-1]
    header = C.B.block(first.target, flags=first.flags, argument=final.offset - first.offset)
    result = result[:first.offset] + header + result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA, section7_sha256=C.SHA(result), flash_ready=False)
    doc['dsp_l1_code_fix'] = dict(
        purpose='Place all remaining imported executable ONESHOT code in L2, outside data-cache-enabled L1 banks1/2.',
        base=str(BASE.resolve()), base_sha256=BASE_SHA,
        inventory=str(INVENTORY.resolve()), inventory_sha256=C.SHA(INVENTORY.read_bytes()),
        placements=rows, relocations=changes, function_pointers=pointers,
        original_code_retained_but_unreferenced=True,
        data_unchanged_except_typed_function_pointer=True,
        classified_instructions_audited=len(instructions),
        native_inbound=['0x1c2872', '0x1c9448'],
        new_fault_pc=hex(mapped(0x185208, rows)),
        fatal_code_capture_unchanged=dict(pc='0xbf4046', dm='0x200e808c',
                                         marker_schema='DBE; full native ILOPI PC retained'),
        limitations=['Corrects a documented placement constraint; physical cache/bus failure mechanism is not emulated.',
                     'Old byte-identical code remains loaded as inert historical content.',
                     'No sample/LOOP algorithm or native cache-policy change.',
                     'Hardware playback remains unverified.'])
    out.mkdir(parents=True, exist_ok=False)
    (out / 'section_7.bin').write_bytes(result)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    (out / 'l1-imported-code-inventory.json').write_bytes(INVENTORY.read_bytes())
    print(json.dumps(dict(section7_sha256=C.SHA(result), spans=len(rows),
                          code_bytes=sum(row['bytes'] for row in rows),
                          changed_operands=len(changes), function_pointers=pointers,
                          sampler_entry=hex(mapped(0x185800, rows)),
                          renderer_entry=hex(mapped(0x185000, rows))), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
