#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline DN2 recovery/container audit; no device access or firmware writes.

Uses this project's existing dnfw parser, codec and integrity implementation.
Recovery-check categories informed by Digiwerk's GPL-2.0-or-later brickcheck
(eb1cfa7, tools/brickcheck/README.md); no upstream implementation copied.
Ranges below are OS 1.11, not Digiwerk's OS 1.12 addresses. The streaming margin
walk follows the existing MIT-derived dnfw.codec.aplib grammar and tracks its
input cursor; it is a static model, not execution of the device depacker.
"""
from pathlib import Path
from dataclasses import replace
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / 'port/tools/dnfw/src'
sys.path.insert(0, str(LIB))
from dnfw.codec import aplib, limits
from dnfw.container import ele3
from dnfw.firmware.load import load
from dnfw.integrity import checksum, digest
from dnfw.syx import transport

BASE = 0x40000400
STOCK_SHA = '2af43e65e3d8390b41c9f66222620f8cce027d73ed87db00c80b440f628472e0'
STOCK_MAIN_SHA = '57b06a7960b7c3dc9803bde6b31896b89a2fbdcc404a932ff503f3856d4d7a61'
MAX_CONTAINER = 0x200000
MAX_OUTPUT = 0x800000
# 1.11 panel addresses read from updater operands at 400DBACC/400DBB64/400DBB6C;
# driver and writer boundaries independently checked in stock 1.11.
# The pinned stock input supplies the bytes; none are included here.
PROTECTED = (
    ('panel updater and UART helpers', 0x400DB8C4, 0x400DBC4A),
    ('panel MCU blob including version', 0x402F7800, 0x402FAF54),
    ('NOR driver', 0x40134748, 0x40135F3C),
    ('in-OS upgrade writer', 0x40138E24, 0x40138F6C),
    ('in-OS upgrade validator', 0x400DBC4C, 0x400DBC80),
    ('content checksum', 0x40122418, 0x40122452),
    ('HMAC trailer verifier', 0x400D2A60, 0x400D2B3E),
    ('HMAC and SHA256', 0x4011E560, 0x4011E9D8),
    ('SHA256 constants', 0x402078E8, 0x402079E8),
    ('seal seed', 0x40210592, 0x4021059D),
    ('seal mask', 0x4021B537, 0x4021B557),
)
LIMITATIONS = [
    'Static audit only: no device depacker, cold-boot, STARTUP-menu, flash-writer or hardware execution.',
    'Unchanged protected code does not rule out new indirect calls or writes from other code.',
    'Margins model unread compressed bytes at each output write; they do not model instruction or DMA timing.',
    'Intended images identify build outputs, not behavioral correctness; memory allocation and DSP execution need separate checks.',
    'Only the pinned stock OS 1.11 profile is supported; other versions fail closed.',
    'The 0x40200000 margin concerns conditional section4/board-test boot, distinct from normal boot and STARTUP DIN receive.',
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def section_layout(stream):
    """Validate raw section ranges before permissive object parsing/depacking."""
    require(len(stream) >= 40 and stream[8:12] == b'ELE3', 'missing ELE3 at preamble offset 8')
    size = int.from_bytes(stream[:4], 'big')
    require(64 <= size <= MAX_CONTAINER and size + 8 <= len(stream), 'invalid/oversized declared container')
    require(not any(stream[8 + size:]), 'nonzero transport padding')
    data = stream[8:8 + size]
    count = int.from_bytes(data[28:32], 'big')
    require(0 < count <= 16 and 32 + 16 * count <= size - 32, 'invalid section count/table')
    entries = [struct.unpack_from('>4I', data, 32 + 16 * i) for i in range(count)]
    require(len({e[0] for e in entries}) == count, 'duplicate section IDs')
    end = 32 + 16 * count
    for sid, offset, length, dest in sorted(entries, key=lambda e: e[1]):
        require(offset % 16 == 0 and length > 0, f'section {sid}: invalid alignment/length')
        require(offset >= end, f'section {sid}: overlapping header or section')
        require(offset + length <= size - 32, f'section {sid}: exceeds payload boundary')
        require(not any(data[end:offset]), f'section {sid}: nonzero inter-section padding')
        end = offset + length
    require(digest.offset(end) + 32 == size, 'noncanonical trailer placement')
    require(not any(data[end:size - 32]), 'nonzero trailer padding')
    return entries


def decode_with_margin(stored):
    """Strict bounded aPLib decode + min(consumed_input - produced_output).

    The unread source starts at stage + 8 + bits.pos. Output ends exclusively
    at BASE + len(out). Checking token ends is sufficient: reads precede each
    literal/match and every match writes monotonically without new input reads.
    """
    require(len(stored) >= 8, 'short compressed section')
    length, total = struct.unpack_from('>II', stored)
    require(0 < length <= len(stored) - 8, 'compressed length out of bounds')
    require(len(stored) % 4 == 0 and len(stored) - 8 - length < 4, 'invalid compressed padding length')
    require(not any(stored[8 + length:]), 'nonzero compressed padding')
    stream = stored[8:8 + length]
    require(sum(stream) & 0xffffffff == total, 'compressed stream checksum mismatch')
    bits = aplib._Bits(stream)
    out, last, minimum, maximum_offset, maximum_match = bytearray(), 1, 0, 0, 0
    witnesses, token_index = {}, 0
    while True:
        output_start = len(out)
        if bits.bit():
            value = bits.byte()
            require(not bits.exhausted, 'truncated literal')
            require(len(out) < MAX_OUTPUT, 'decoded output exceeds audit bound')
            out.append(value)
        else:
            gamma = bits.gamma()
            if gamma == aplib.REUSE_GAMMA:
                offset = last
            else:
                raw = ((gamma << 8) + bits.byte()) & 0xffffffff
                require(not bits.exhausted, 'truncated match')
                if raw == aplib.OFFSET_BIAS:
                    require(bits.pos == len(stream) and out, 'early end marker or empty output')
                    break
                offset = raw - aplib.OFFSET_BIAS
                last = offset
            short = 2 * bits.bit() + bits.bit()
            count = (short if short else bits.gamma() + 2) + 1 + (offset > aplib.FAR_THRESHOLD)
            require(not bits.exhausted and 0 < offset <= len(out), 'invalid or truncated backreference')
            require(len(out) + count <= MAX_OUTPUT, 'decoded output exceeds audit bound')
            require(offset < limits.WINDOW and count <= limits.MAX_MATCH, 'backreference exceeds existing codec limits')
            maximum_offset, maximum_match = max(maximum_offset, offset), max(maximum_match, count)
            if offset >= count:
                out.extend(out[len(out) - offset:len(out) - offset + count])
            else:
                chunk = bytes(out[-offset:])
                out.extend((chunk * ((count + offset - 1) // offset))[:count])
        token_index += 1
        if bits.pos < len(stream):
            minimum = min(minimum, bits.pos - len(out))
            for stage in (0x40400000, 0x40200000):
                unread_start, unread_end = stage + 8 + bits.pos, stage + 8 + len(stream)
                write_start, write_end = BASE + output_start, BASE + len(out)
                if max(write_start, unread_start) < min(write_end, unread_end) and hex(stage) not in witnesses:
                    witnesses[hex(stage)] = dict(token=token_index, input_consumed=bits.pos,
                        unread_bytes=len(stream)-bits.pos, output_start=output_start, output_end=len(out),
                        write_start=hex(write_start), write_end_exclusive=hex(write_end),
                        unread_start=hex(unread_start), unread_end_exclusive=hex(unread_end))
    return bytes(out), dict(consumed=bits.pos, output_bytes=len(out), minimum_relative_gap=minimum,
                           max_offset=maximum_offset, max_match=maximum_match, overlap_witnesses=witnesses)


def protected_ranges(stock, candidate):
    return [dict(name=name, start=hex(lo), end=hex(hi), ok=(
        hi - BASE <= len(candidate) and candidate[lo-BASE:hi-BASE] == stock[lo-BASE:hi-BASE]))
        for name, lo, hi in PROTECTED]


def audit(candidate_syx: Path, stock_syx: Path, *, intended_main: Path | None = None,
          intended_dsp: Path | None = None):
    result = dict(schema='dn2-static-recovery-audit-1', ok=False, profile='Digitone II OS 1.11',
                  findings=[], coverage=[], limitations=LIMITATIONS.copy(), hashes={})
    def add(check, ok, detail, **extra):
        result['findings'].append(dict(check=check, ok=bool(ok), detail=detail, **extra))
        if ok:
            result['coverage'].append(check)
    try:
        stock_raw = Path(stock_syx).read_bytes()
        require(sha(stock_raw) == STOCK_SHA, 'stock SHA256 is not the supported OS 1.11')
        raw = Path(candidate_syx).read_bytes()
        require(len(raw) <= 3 * MAX_CONTAINER, 'SysEx file exceeds audit input bound')
        result['hashes'] = dict(stock_syx_sha256=sha(stock_raw), candidate_syx_sha256=sha(raw))
        add('stock_identity', True, 'Pinned vendor OS 1.11 input')
        tx = transport.decode(raw)
        entries = section_layout(tx.stream)
        add('section_layout', True, 'Nonoverlapping aligned sections and bounded zero padding', sections=[
            dict(id=sid, offset=offset, length=length, destination=hex(dest)) for sid,offset,length,dest in entries])
        size = int.from_bytes(tx.stream[:4], 'big')
        require(transport.encode(tx.stream[:size + 8], tx.envelope) == raw,
                'noncanonical transport framing, counters, markers or checksums')
        require(tx.packets * 101 <= MAX_CONTAINER, 'receive-buffer packet extent exceeds 2 MiB')
        add('transport', True, 'Exact canonical SysEx roundtrip; packet extent fits receive buffer')
        stock = load(stock_raw)
        # Never discover keys by decompressing untrusted candidate sections.
        # Reuse the pinned stock key and verify its HMAC before any candidate decode.
        candidate = replace(stock, envelope=tx.envelope,
            container=ele3.parse(tx.stream[8:], size), raw_container=tx.stream[8:],
            stored_checksum=int.from_bytes(tx.stream[4:8], 'big'))
        require(candidate.envelope.device == stock.envelope.device and
                candidate.envelope.base == stock.envelope.base and
                candidate.envelope.marker_info[:4] == stock.envelope.marker_info[:4],
                'transport device/seed/start counter differ from stock')
        require(candidate.container.product == 52, 'wrong product')
        require(checksum.content(candidate.raw_container[:size]) == candidate.stored_checksum, 'container checksum mismatch')
        require(digest.verify(stock.key.value, candidate.raw_container[:size]), 'container HMAC mismatch')
        add('integrity', True, 'Product, content checksum and stock-key HMAC verified; no key material emitted')
        sc, cc = stock.container, candidate.container
        require([s.id for s in cc.sections] == [s.id for s in sc.sections], 'section order/IDs differ from stock')
        require(cc.head[:0x13] == sc.head[:0x13] and cc.head[0x1c:0x20] == sc.head[0x1c:0x20], 'non-version header change')
        for old,new in zip(sc.sections, cc.sections):
            require(old.dest == new.dest, f'section {old.id}: destination differs')
            if old.id not in (3, 7):
                require(old.stored == new.stored, f'protected section {old.id} changed')
        i = [s.id for s in sc.sections].index(2)
        require(cc.head[32+i*16:48+i*16] == sc.head[32+i*16:48+i*16], 'bootstrap table entry changed')
        add('recovery_sections', True, 'Bootstrap section/entry, board-test, metadata and auxiliary section unchanged')
        decoded = {}
        profiles = {}
        for sid in (2, 3, 7, 8):
            decoded[sid], profiles[sid] = decode_with_margin(cc.find(sid).stored)
            require(decoded[sid] == cc.find(sid).unpack(), f'section {sid}: independent cursor walk differs from existing decoder')
        add('strict_depack', True, 'Compressed sections strictly bounded; stream ends/padding and existing decoder agree')
        stock_main = sc.find(3).unpack()
        require(sha(stock_main) == STOCK_MAIN_SHA, 'stock MAIN hash differs')
        for sid, path in ((3, intended_main), (7, intended_dsp)):
            name = 'main' if sid == 3 else 'dsp'
            result['hashes'][name + '_sha256'] = sha(decoded[sid])
            if path is None:
                same = decoded[sid] == sc.find(sid).unpack()
                add('intended_' + name, same, 'Stock bytes match' if same else 'Changed section requires explicit intended image')
            else:
                expected = Path(path).read_bytes()
                add('intended_' + name, decoded[sid] == expected, 'Exact decoded image comparison', expected_sha256=sha(expected))
        spans = protected_ranges(stock_main, decoded[3])
        add('protected_main', all(s['ok'] for s in spans), 'Version-specific panel, flash writer/driver and validator closure', ranges=spans)
        board = cc.find(4).stored
        for pc in (0x80003590, 0x800035b0):
            off = pc - 0x80000400
            require(board[off:off+6] == bytes.fromhex('487940200000'), 'section4 stage instruction differs')
        require(board[0x533e:0x5340] == bytes.fromhex('5088'), 'section4 depacker header skip differs')
        relative = profiles[3]['minimum_relative_gap']
        margins = [dict(stage=hex(stage), path=('normal_boot' if stage == 0x40400000 else 'section4_board_test_boot'),
                        minimum_unread_gap=stage + 8 - BASE + relative)
                   for stage in (0x40400000, 0x40200000)]
        add('depack_margins', all(m['minimum_unread_gap'] >= 1 for m in margins),
            'Static byte-consumption model; one-byte minimum safety margin at both loader stages', stages=margins, overlap_witnesses=profiles[3]['overlap_witnesses'])
        main = decoded[3]
        capacity = []
        for pc, opcode in ((0x400cf54c, b'\x2f\x3c'), (0x400cf5ac, b'\x0c\x80'),
                           (0x400cf576, b'\x2f\x3c'), (0x400cf5e4, b'\x0c\x82')):
            off = pc - BASE
            require(main[off:off+2] == opcode, f'unrecognized DSP capacity instruction at {pc:#x}')
            capacity.append(int.from_bytes(main[off+2:off+6], 'big'))
        require(capacity[0] == capacity[1] == 0x100000, 'unknown DSP compressed-input allocation/guard')
        require(capacity[2] == capacity[3] and capacity[2] in (0x100000, 0x200000), 'unknown DSP output allocation/guard')
        add('dsp_loader_capacity', len(cc.find(7).stored) <= capacity[0] and len(decoded[7])+1 <= capacity[2],
            'Capacity read from actual MAIN operands; recognizes intentional 2 MiB output expansion',
            compressed_capacity=capacity[0], output_capacity=capacity[2], output_with_prefix=len(decoded[7])+1)
    except (OSError, ValueError, TypeError, IndexError, struct.error) as exc:
        add('input_or_structure', False, str(exc))
    result['ok'] = bool(result['findings']) and all(f['ok'] for f in result['findings'])
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--stock', type=Path, required=True)
    p.add_argument('--intended-main', type=Path)
    p.add_argument('--intended-dsp', type=Path)
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    if a.out:
        inputs = [a.candidate, a.stock, a.intended_main, a.intended_dsp]
        for path in inputs:
            if path and (a.out.resolve() == path.resolve() or
                         (a.out.exists() and path.exists() and a.out.samefile(path))):
                p.error('--out must not overwrite an input')
    result = audit(a.candidate, a.stock, intended_main=a.intended_main, intended_dsp=a.intended_dsp)
    text = json.dumps(result, indent=2) + '\n'
    if a.out:
        a.out.write_text(text)
    else:
        print(text, end='')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
