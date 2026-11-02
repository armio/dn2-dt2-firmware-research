#!/usr/bin/env python3
"""Read-only SHARC encoding audit against native DN2 and DT2 instructions.

The stock-encoding/sign-extension audit approach is documented by Digiwerk
eb1cfa7d4fc3cd0a77a430e9e9226c5d9cc10979 (tools/dspsplice/audit.py and
tools/brickcheck/bc_dsp.py), crediting angellinares/dn2_firmware_explore's
silicon finding. This implementation uses our existing digikit decoder and
build receipts; it imports no Digiwerk code or temporary research snapshot.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'firmware/ghidra/oneshot-proof/v7-source'
sys.path[:0] = [str(SRC / 'src'), str(SRC / 'toolchains/digikit/tools')]
from dnfw.image import bootstream as B
import sharc_disasm as D
import sharc_visa_tables as VT
import sharcdb
import sharcflow
import sharcfn
import sharcldr
import sharcinv
import sharc_trace

SHIFT_OPS = {0, 1, 2, 8, 9}  # LSHIFT, ASHIFT, ROT, LSHIFT_OR, ASHIFT_OR


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def physical(sw):
    if 0xB80000 <= sw < 0xC00000:
        return 0x20000000 + 2 * (sw - 0xB80000)
    if 0 <= sw < 0x200000:
        return 0x28000000 + 2 * sw
    raise ValueError(f'Unsupported executable address {sw:#x}')


def fields(ins):
    """Merge split bit fields without discarding encoded extension bits."""
    result = {}
    for name, value in ins.fields.items():
        stem = name.split('[')[0]
        match = re.search(r'\[(\d+)(?::(\d+))?\]', name)
        shift = int(match[2] or match[1]) if match else 0
        result[stem] = result.get(stem, 0) | (value << shift)
    return result


def bad_shift(ins):
    f = fields(ins)
    if 'shiftimm' not in f:
        return None
    value = f['shiftimm']
    op, immediate = (value >> 16) & 63, (value >> 8) & 255
    if op not in SHIFT_OPS:
        return None
    expected = 15 if immediate & 128 else 0
    extension = f.get('dataex')
    if extension != expected:
        return dict(operation=op, immediate=immediate, extension=extension,
                    expected_extension=expected)
    return None


def exact_key(ins):
    raw = ins.raw
    for name, (hi, lo) in VT.get_type(ins.type_name)['fields'].items():
        if name.split('[')[0] in {'addr', 'reladdr', 'data'}:
            raw &= ~(((1 << (hi - lo + 1)) - 1) << lo)
    return ins.type_name, raw


class NoMemory:
    def read(self, *args):
        return None

    read_sw = read


def register_class_key(ins):
    """Only register renaming: retain operation, flags, widths and constants.

    Address/immediate fields already masked by exact_key are also masked in
    the decoder before rendering. A class match never establishes legality.
    """
    _, raw = exact_key(ins)
    entry = VT.get_type(ins.type_name)
    f = {name: (raw >> lo) & ((1 << (hi - lo + 1)) - 1)
         for name, (hi, lo) in entry['fields'].items()}
    masked = D.Instruction(0, ins.length_bytes, ins.type_name, f, raw, ins.kind)
    text = sharcfn.render_instruction(0, masked, NoMemory(), set(), collections.Counter(), [])[0]
    return ins.type_name, re.sub(r'\b([RFSIMBL])\d+\b', r'\1n', text)


def decode(data, width=None):
    """Use producer widths where present; never resynchronize by skipping bytes."""
    if width is None:
        return sharc_trace.decode_at(data + bytes(6), 0, 0)
    normal = sharc_trace.decode_at(data + bytes(6), 0, 0)
    # Existing six-byte hooks may replace more than one original short opcode.
    if normal.length_bytes == 6 and normal.raw >> 24 == 0x063e00:
        return normal
    if width not in (2, 4, 6) or len(data) < width:
        raise ValueError(f'Invalid/truncated instruction width {width}')
    raw = 0
    for off in range(0, width, 2):
        raw = (raw << 16) | int.from_bytes(data[off:off+2], 'little')
    matches = D.identify(raw, width * 8)
    if len(matches) != 1:
        if normal.kind != 'unknown' and normal.length_bytes == width:
            return normal
        raise ValueError(f'Ambiguous instruction of width {width}: {matches}')
    entry = VT.get_type(matches[0])
    f = {name: (raw >> lo) & ((1 << (hi - lo + 1)) - 1)
         for name, (hi, lo) in entry['fields'].items()}
    return D.Instruction(0, width, matches[0], f, raw,
                         'uncertain' if entry['uncertain'] else 'confident')


def native_corpus(path):
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    indices = sharcdb.KNOWN_CODE_BLOCKS.get(sha)
    if indices is None:
        raise ValueError(f'Unclassified native image {path.name} ({sha}); refusing to guess code')
    blocks = {b['index']: b for b in sharcldr.parse_blocks(data)}
    rows = []
    for idx in indices:
        block = blocks[idx]
        payload = data[block['payload_offset']:][:block['payload_len']]
        start = sharcinv.sw_base_for_target(block['target_address'])
        for off, ins in sharcflow.aligned(payload, 8):
            if ins.kind != 'unknown' and ins.length_bytes:
                rows.append((start + off // 2, ins, idx, off))
    return data, sha, blocks, rows


def receipt_ranges(doc):
    """Executable annotations only; data, tables and arbitrary payloads excluded."""
    result = []
    relocations = [r for key in ('dsp_startup_fix', 'dsp_l1_code_fix')
                   for r in doc.get(key, {}).get('placements', []) if r.get('kind') == 'code']

    def add(start, size, name, offsets=None):
        start, size = integer(start), integer(size)
        for r in relocations:
            old, new = integer(r['old']), integer(r['new'])
            if old <= start and start + size // 2 <= old + integer(r['bytes']) // 2:
                start += new - old
        physical(start)
        if size <= 0 or size % 2:
            raise ValueError(f'Invalid executable span {name}: {size}')
        result.append(dict(start=start, bytes=size, name=name,
                           instruction_offsets=offsets))

    def visit(value, path):
        if isinstance(value, list):
            for i, row in enumerate(value):
                visit(row, f'{path}[{i}]')
        elif isinstance(value, dict):
            offsets = value.get('instruction_offsets')
            if value.get('kind') == 'code' and 'new' in value and 'bytes' in value:
                add(value['new'], value['bytes'], path, offsets)
            elif 'code' in value and isinstance(value['code'], (str, int)):
                size = value.get('code_bytes', value.get('bytes'))
                if size:
                    add(value['code'], size, path, offsets)
            if 'bridge' in value and 'bridge_bytes' in value:
                add(value['bridge'], value['bridge_bytes'], path + '.bridge', offsets)
            if 'donor' in value and 'target' in value and 'bytes' in value:
                add(value['target'], value['bytes'], path, offsets)
            if 'recipient_start' in value and 'bytes' in value:
                add(value['recipient_start'], value['bytes'], path, offsets)
            for key, row in value.items():
                if isinstance(row, (dict, list)):
                    visit(row, f'{path}.{key}')
    visit(doc, 'receipt')
    return result


def builder_widths(doc):
    """Reuse original producer boundaries for ambiguous short instructions."""
    if 'dsp_startup_fix' not in doc:
        return {}
    import build_dt2_dsp_l1_code_fix as P
    k = P.C.M.Digikit(P.C.SRC / 'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    before = P.B.decode_view(k, P.B.BASE.read_bytes())
    result = {}
    for row in doc['dsp_startup_fix']['placements']:
        if row['kind'] != 'code':
            continue
        starts = P.B.boundaries(k, before, row)
        for a, z in zip(starts, starts[1:] + [row['old'] + row['bytes'] // 2]):
            result[row['new'] + a - row['old']] = 2 * (z-a)
    if 'dsp_l1_code_fix' in doc:
        original = P.B.decode_view(k, P.BASE.read_bytes())
        for row in doc['dsp_l1_code_fix']['placements']:
            for pc, ins in P.imported_instructions(k, original, row):
                result[row['new'] + pc - row['old']] = ins.length_bytes
    return result


def check(section7: Path, stock: Path, donor: Path, *, receipt: Path | None = None,
          ranges: list[dict] | None = None):
    section7, stock, donor = map(Path, (section7, stock, donor))
    raw = section7.read_bytes()
    walk = B.walk(raw)
    if not walk.complete:
        raise ValueError('Incomplete candidate boot stream')
    digest = hashlib.sha256(raw).hexdigest()
    widths = {}
    if ranges is None:
        receipt = Path(receipt) if receipt else section7.parent / 'build-receipt.json'
        doc = json.loads(receipt.read_text())
        if doc.get('section7_sha256') != digest:
            raise ValueError('Build receipt does not identify candidate DSP bytes')
        ranges = receipt_ranges(doc)
        widths = builder_widths(doc)
    corpora = [native_corpus(stock), native_corpus(donor)]
    exact, classes = set(), set()
    for _, _, _, rows in corpora:
        for _, ins, _, _ in rows:
            exact.add(exact_key(ins))
            classes.add(register_class_key(ins))
    findings, counts, seen = [], collections.Counter(), set()
    covered = []

    def audit(pc, ins, origin):
        key = (pc, ins.raw, ins.length_bytes)
        if key in seen:
            return
        seen.add(key)
        bad = bad_shift(ins)
        level = ('exact_native' if exact_key(ins) in exact else
                 'register_class' if register_class_key(ins) in classes else 'unseen')
        counts[level] += 1
        if bad:
            findings.append(dict(severity='error', kind='bad_shift_extension', pc=hex(pc),
                                 form=ins.type_name, raw=hex(ins.raw), origin=origin, **bad))
        elif level != 'exact_native':
            findings.append(dict(severity='review', kind=level, pc=hex(pc),
                                 form=ins.type_name, raw=hex(ins.raw), origin=origin))

    # Native payload boundaries stay trustworthy, even for the overwritten
    # startup application. Audit changed instructions at those boundaries.
    native_raw, _, blocks, rows = corpora[0]
    consumed = {}
    for pc, prior, idx, off in rows:
        block = walk.blocks[idx]
        original = blocks[idx]
        if block.target != original['target_address'] or block.count != original['byte_count']:
            raise ValueError(f'Native block {idx} metadata changed; explicit map required')
        if off < consumed.get(idx, 0):
            continue
        candidate = raw[block.payload_at+off:block.end]
        old = native_raw[original['payload_offset']+off:][:prior.length_bytes]
        if candidate[:prior.length_bytes] == old:
            counts['unchanged_native'] += 1
            continue
        ins = decode(candidate)
        if ins.kind == 'unknown':
            findings.append(dict(severity='error', kind='undecodable_native_patch', pc=hex(pc), note=ins.note))
            continue
        consumed[idx] = off + ins.length_bytes
        audit(pc, ins, f'native block {idx}')

    regions = B.load_regions(raw)

    def read(start, n):
        # Append-only stream may contain overwritten areas; latest load wins.
        result = bytearray(n)
        present = bytearray(n)
        for base, data in regions:
            lo, hi = max(start, base), min(start+n, base+len(data))
            if lo < hi:
                result[lo-start:hi-start] = data[lo-base:hi-base]
                present[lo-start:hi-start] = b'\1' * (hi-lo)
        if not all(present):
            raise ValueError(f'Executable bytes absent at {start:#x}+{n:#x}')
        return bytes(result)

    for row in ranges:
        start, size = integer(row['start']), integer(row['bytes'])
        name = row.get('name', hex(start))
        try:
            data = read(physical(start), size)
        except ValueError as error:
            findings.append(dict(severity='review', kind='unmapped_executable_annotation',
                                 pc=hex(start), origin=name, note=str(error)))
            covered.append(dict(name=name, start=hex(start), bytes=size, decoded_bytes=0))
            continue
        offsets = row.get('instruction_offsets')
        if offsets is not None and (not isinstance(offsets, list) or not offsets or
                any(not isinstance(v, int) or v < 0 or v >= size or v % 2 for v in offsets) or
                offsets[0] != 0 or offsets != sorted(set(offsets))):
            raise ValueError(f'Invalid producer instruction offsets for {name}')
        boundaries = dict(zip(offsets, offsets[1:] + [size])) if offsets else {}
        offset = 0
        while offset < size:
            try:
                width = boundaries[offset] - offset if offset in boundaries else widths.get(start+offset//2)
                ins = decode(data[offset:], width)
                if ins.kind == 'unknown' or not ins.length_bytes or offset+ins.length_bytes > size:
                    raise ValueError(ins.note or 'Instruction extends beyond span')
                audit(start + offset // 2, ins, name)
                if width and width > 6 and ins.length_bytes == 6 and ins.raw >> 24 == 0x063e00:
                    counts['declared_unreachable_padding_bytes'] += width - 6
                    offset += width
                else:
                    offset += ins.length_bytes
            except ValueError as error:
                findings.append(dict(severity='review', kind='incomplete_decode',
                                     pc=hex(start+offset//2), origin=name, note=str(error)))
                break
        covered.append(dict(name=name, start=hex(start), bytes=size, decoded_bytes=offset))

    return dict(ok=not any(f['severity'] == 'error' for f in findings),
                review_required=bool(findings), dsp_sha256=digest,
                native_corpora=[dict(sha256=c[1], instructions=len(c[3])) for c in corpora],
                findings=findings, coverage=dict(counts=counts, spans=covered,
                    whole_image_certified=False,
                    declared_spans_complete=all(r['bytes'] == r['decoded_bytes'] for r in covered),
                    classification='native instruction boundaries plus build-receipt executable annotations'),
                limitations=[
                    'Exact match masks only address, branch-displacement and data immediates; it does not prove operand validity, runtime ABI or silicon timing.',
                    'Register-class and unseen encodings require review; they are not silently accepted as native-exact.',
                    'Only explicitly classified code is decoded. Unclassified added payload/data is excluded; incomplete spans are reported.',
                    'No hardware execution, DMA scheduling, cache coherency or whole-firmware safety proof.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('section7', type=Path)
    p.add_argument('--stock', type=Path, required=True)
    p.add_argument('--donor', type=Path, required=True)
    p.add_argument('--receipt', type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    inputs = [a.section7, a.stock, a.donor,
              a.receipt or a.section7.parent / 'build-receipt.json']
    if a.output and any(a.output.resolve() == x.resolve() or
                        (a.output.exists() and x.exists() and a.output.samefile(x)) for x in inputs):
        p.error('--output must not overwrite an input')
    try:
        result = check(a.section7, a.stock, a.donor, receipt=a.receipt)
    except (ValueError, OSError, KeyError, IndexError) as error:
        result = dict(ok=False, review_required=True, findings=[dict(
            severity='error', kind='invalid_input', note=str(error))], coverage={},
            limitations=['Audit could not complete; no safety conclusion.'])
    text = json.dumps(result, indent=2) + '\n'
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(text)
    else:
        print(text, end='')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
