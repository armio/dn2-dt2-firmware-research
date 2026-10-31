#!/usr/bin/env python3
"""Place CC capture packets in native USB SRAM; no device I/O.

This is a bounded transport candidate. Native Overbridge uses the same USB
queue with 1012-byte SRAM payloads; that supports this placement, but does not
prove that the T1DV DDR payloads caused silence or the USB-mode freeze.
"""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'output/dn2-research/dn2-usb-multitrack-efficient-20261012'
SHA = '116b21a48406f3feffa4d6d3d70c69e227ba8dd3129dcf8510353f8aa3cacd9c'
BASE = 0x40000400
RING, SLOTS, STRIDE = 0x80009800, 16, 1024


def digest(value):
    return hashlib.sha256(value).hexdigest()


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert digest(raw) == SHA
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy = doc['runtime_copy']
    source = int(copy['source'], 16)
    runtime_base = int(copy['destination'], 16)
    runtime = bytearray((INPUT / 'runtime.bin').read_bytes())
    assert len(runtime) == copy['bytes']
    assert runtime == raw[source - BASE:source - BASE + len(runtime)]
    old = doc['usb_multitrack']
    methods = {key: int(value, 16) for key, value in old['methods'].items()}
    assert int(old['ring'], 16) == 0x47AA7800
    assert old['ring_slots'] == SLOTS and old['ring_stride'] == STRIDE
    assert int(old['stage'], 16) == 0x47AAB800
    assert 0x80009700 <= RING < RING + SLOTS * STRIDE <= 0x8000DB40
    assert RING % STRIDE == 0
    patches = []

    def patch(name, address, before, after):
        at = address - runtime_base
        assert len(before) == len(after)
        assert runtime[at:at + len(before)] == before, (name, hex(address))
        runtime[at:at + len(before)] = after
        patches.append(dict(name=name, address=hex(address),
                            image_address=hex(source + at),
                            before=before.hex(), after=after.hex()))

    patch('startup_capture_ring', methods['usb_native_40003b92'],
          bytes.fromhex('068247aa7800'), b'\x06\x82' + RING.to_bytes(4, 'big'))
    patch('writer_capture_ring', methods['usb_native_40003dc6'],
          bytes.fromhex('068147aa7800'), b'\x06\x81' + RING.to_bytes(4, 'big'))
    # Cover complete LEA and MOVEM instructions. Tail dispatch sees exactly the
    # caller's native stack and registers; the old cache routine is unreachable.
    patch('sram_queue_tail_dispatch', methods['usb_queue_capture'],
          bytes.fromhex('4feffff048d70303'), bytes.fromhex('4ef940005a864e71'))
    patch('identity', 0x47AA5A0C, b'T1DV', b'T1DW')
    image = bytearray(raw)
    image[source - BASE:source - BASE + len(runtime)] = runtime
    allowed = set()
    for item in patches:
        start = int(item['image_address'], 16) - BASE
        allowed.update(range(start, start + len(bytes.fromhex(item['before']))))
    changed = [i for i, (a, b) in enumerate(zip(raw, image)) if a != b]
    assert len(image) == len(raw) and set(changed) <= allowed
    assert image[:source - BASE] == raw[:source - BASE]
    assert image[source - BASE + len(runtime):] == raw[source - BASE + len(runtime):]

    cfg = dict(
        base=str(INPUT / 'main-os.bin'), base_sha256=SHA,
        ring=hex(RING), ring_end=hex(RING + SLOTS * STRIDE),
        ring_slots=SLOTS, ring_stride=STRIDE, max_packet_bytes=952,
        previous_ring=old['ring'], previous_ring_retained_unused=True,
        stage=old['stage'], stage_bytes=old['stage_bytes'],
        queue_entry=hex(methods['usb_queue_capture']), native_queue='0x40005a86',
        patches=patches,
        changed_byte_addresses=[hex(BASE + i) for i in changed],
        identity=dict(address='0x47aa5a0c', before='T1DV', after='T1DW'),
        cache='No CPUSHL on capture packets: the SRAM queue entry tail-jumps to the native queue.',
        native_sram_evidence=dict(
            mode5_capture_descriptors=['0x80008000', '0x80008800'],
            mode5_return_descriptors=['0x80008800', '0x80008c00'],
            mode5_feedback_descriptors=['0x80008c00', '0x80009000'],
            mode5_original_capture_packets=['0x80009000', '0x80009380'],
            mode5_return_packets=['0x80009380', '0x80009700'],
            common_next_descriptor_pool='0x8000db40',
            mode5_clear=dict(entry='0x400036ac', start='0x80008000', bytes=0x5B40),
            mode6_clear=dict(entry='0x40003698', start='0x80008000', bytes=0x5B40),
            mode6_capture=dict(writer='0x40003118', packet_start='0x80008c00',
                               packet_end='0x8000cb40', slots=16, stride=1012,
                               native_queue='0x40005a86', endpoint=7),
            mode6_endpoint_type='Interrupt; do not copy its endpoint mode or QH into class-compliant isochronous capture.',
        ),
        preserves='T1DV collector, DDR stage, dTDs, packet lengths, endpoint descriptors, POST routing, USB return, feedback, DSP and bootstrap are unchanged.',
        limits=[
            'A candidate based on native SRAM transport placement; DDR/cache causality is not proven.',
            'Mode5 and mode6 are exclusive; the new ring overlaps only the inactive mode6 payload reservation.',
            'USB capture, mode switching and sustained recording require hardware confirmation.',
            'No hardware test, flash or DSP modification performed.',
        ],
    )
    doc.update(main_sha256=digest(image), runtime_sha256=digest(runtime),
               bytes=len(image), flash_ready=False)
    doc['usb_multitrack_sram'] = cfg
    out.mkdir(parents=True, exist_ok=False)
    (out / 'main-os.bin').write_bytes(image)
    (out / 'runtime.bin').write_bytes(runtime)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    for name in ('bootstrap.S', 'fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((INPUT / name).read_bytes())
    (out / 'README.md').write_text(
        '# T1DW capture SRAM candidate\n\n'
        'Only the active class-compliant capture ring moved to '
        '`80009800..8000D800` (16 x 1024 bytes). The queue wrapper now '
        'tail-jumps to native `40005A86`; no cache operation runs on SRAM. '
        'The DDR collection stage and all packet/endpoint logic are unchanged.\n\n'
        'Native Overbridge sends 1012-byte payloads from the same on-chip SRAM '
        'reservation through the same queue. Its original ring base cannot '
        'be reused in mode5 because that would overlap feedback descriptors '
        'and playback payloads. The selected range begins after the native '
        'mode5 playback ring ends at `80009700` and ends before the common '
        'descriptor pool at `8000DB40`. Both native mode initializers clear '
        'the entire audio reservation.\n\n'
        'This is a targeted transport candidate, not a demonstrated cause or '
        'hardware-confirmed fix for silent USB audio or mode-switch freezing. '
        'See `build-receipt.json` for exact sites and allocation evidence.\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],
                          runtime_sha256=doc['runtime_sha256'],
                          changed_bytes=len(changed), usb_multitrack_sram=cfg), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
