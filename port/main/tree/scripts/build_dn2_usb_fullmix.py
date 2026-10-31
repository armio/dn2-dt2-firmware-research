#!/usr/bin/env python3
"""Expose native MAIN, tracks, wet effects and inputs as 42 USB24 channels.

Append-only ColdFire component on exact stable T1DW; no device I/O. The SHARC
image, host return, feedback and MIDI are unchanged.  Capture uses the proven
SRAM ring and preserves the native signed24-bit source precision.
"""
from pathlib import Path
import argparse
import json
import re

import build_dn2_usb_multitrack as P
import dn2_usb_multitrack_descriptors as D

B = P.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-usb-multitrack-sram-20261012'
SHA = '7067ea3c1b62c0bb563f8232f2ff3106a95d2d4cf809a213769d4d39d5e1c475'
CHANNELS, FRAMES = 42, 32
STAGE_FRAME_BYTES, FRAME_BYTES = 168, 126
STAGE, RING = 0x47AA7800, 0x80009800
CHANNEL_ORDER = ['MAIN L', 'MAIN R'] + [
    f'T{track} {side}' for track in range(1, 17) for side in ('L', 'R')
] + [f'{name} {side}' for name in ('DELAY', 'REVERB', 'CHORUS', 'INPUT') for side in ('L', 'R')]


def scale(reg, value):
    return f' move.l %d6,-(%sp)\n move.l #{value},%d6\n mulu.l %d6,{reg}\n move.l (%sp)+,%d6'


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    c = doc['runtime_copy']
    src, base = int(c['source'], 16), int(c['destination'], 16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']])
    prior_end = base + len(payload)
    old = doc['usb_multitrack']
    efficient = doc['usb_multitrack_efficient']
    sram = doc['usb_multitrack_sram']
    assert int(sram['ring'], 16) == RING
    assert sram['previous_ring_retained_unused'] and int(sram['previous_ring'], 16) == STAGE
    assert int(old['ring'], 16) == STAGE and old['ring_slots'] * old['ring_stride'] == 16384
    assert STAGE + FRAMES * STAGE_FRAME_BYTES <= STAGE + 16384 <= int(old['stage'], 16)
    assert not any(payload[STAGE-base:STAGE-base+FRAMES*STAGE_FRAME_BYTES])
    payload.extend(bytes(-len(payload) % 16))
    entry = base + len(payload)

    # The exact original native routines remain the source of every unchanged
    # control-flow instruction; prior USB images have entry JMPs and are not used
    # as a disassembly source for these two bounded clones.
    native = (P.INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(native) == P.SHA
    startup = {
        0x40003b86: ' moveq #10,%d0\n lsl.l %d0,%d2',
        0x40003b88: '', 0x40003b8a: ' pea 756', 0x40003b8e: '', 0x40003b90: '',
        0x40003b92: f' addi.l #{RING:#x},%d2',
        0x40003bae: ' move.l #0x02f40080,%d0', 0x40003bb4: ' move.l #756,%d1',
        0x40003be2: ' bsr.w usb_queue_capture',
    }
    writer = {
        0x40003dbe: ' moveq #10,%d5', 0x40003dc0: ' lsl.l %d5,%d1',
        0x40003dc2: '', 0x40003dc4: '', 0x40003dc6: f' addi.l #{RING:#x},%d1',
        # Destination partial offset and queued byte count use packed 24-bit frames.
        0x40003dd2: scale('%d0', FRAME_BYTES),
        0x40003e3a: scale('%d1', FRAME_BYTES),
        # Input offset/count remain Q31; native >>2 yields 42 samples per frame,
        # including odd-frame fragments. No 126-byte truncation is performed.
        0x40003dde: scale('%d0', STAGE_FRAME_BYTES),
        0x40003df2: scale('%d5', STAGE_FRAME_BYTES),
        # Native sources have 24 valid high bits. Emit USB little-endian24;
        # logical shifts preserve all 24 bits, including both signed rails.
        0x40003e06: ' lsr.l #8,%d5',
        0x40003e08: ''' move.b %d5,(%a1)+
 lsr.l #8,%d5
 move.b %d5,(%a1)+
 lsr.l #8,%d5
 move.b %d5,(%a1)+''',
        0x40003e0c: ' move.l %d4,%d0\n' + scale('%d0', FRAME_BYTES) + '\n move.l %d0,-(%sp)',
        0x40003e50: ' move.l %d1,%d4', 0x40003e52: ' swap %d4',
        0x40003e6a: ' bsr.w usb_queue_capture',
    }
    mac = ' .long 0xa0030900\n .word 0xa1c0\n move.l %d0,(%a4)+\n'
    tdm = ' move.l (%a0)+,%d0\n lsl.l #8,%d0\n' + mac
    pair = ''' move.w (%a1)+,%d0
 swap %d0
 clr.w %d0
 move.w (%a1)+,%d1
 move.l %d1,%d2
 andi.l #0xff00,%d2
 or.l %d2,%d0
''' + mac + ''' swap %d1
 clr.w %d1
 move.w (%a1)+,%d0
 andi.l #0xffff,%d0
 or.l %d1,%d0
 lsl.l #8,%d0
''' + mac
    asm = f'''.text
.global usb_fullmix_collect
usb_fullmix_collect:
 tst.l 0x4058dee8
 beq.w usb_collect_inactive
 lea -56(%sp),%sp
 movem.l %d0-%d7/%a0-%a5,(%sp)
 lea {STAGE:#x},%a4
 tst.b 0x80005362
 beq.w usb_collect_zero
 move.l #0x80000000,%d3
 move.l -56(%fp),%d0
 moveq #11,%d1
 lsl.l %d1,%d0
 lea 0x4e6df100,%a0
 adda.l %d0,%a0
 lea 0x800053c0,%a1
 moveq #32,%d5
usb_collect_frame:
''' + tdm * 14 + ' lea 8(%a0),%a0\n' + pair * 14 + f''' subq.l #1,%d5
 bne.w usb_collect_frame
 bra.w usb_collect_send
usb_collect_zero:
 pea {FRAMES*STAGE_FRAME_BYTES}
 pea {STAGE:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
usb_collect_send:
 pea 32
 pea {STAGE:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
 movem.l (%sp),%d0-%d7/%a0-%a5
 lea 56(%sp),%sp
usb_collect_inactive:
 jmp 0x400279a2

.global usb_fullmix_silence
usb_fullmix_silence:
 tst.l 0x4058dee8
 beq.w usb_silence_inactive
 pea {FRAMES*STAGE_FRAME_BYTES}
 pea {STAGE:#x}
 jsr 0x40133ebc
 addq.l #8,%sp
 pea 32
 pea {STAGE:#x}
 bsr.w usb_native_40003d00
 addq.l #8,%sp
usb_silence_inactive:
 jmp 0x40027a4e

usb_queue_capture:
 jmp 0x40005a86

.global usb_native_40003b32
''' + P.native_clone(native, 0x40003b32, 0x40003c02, startup) + '''
.global usb_native_40003d00
''' + P.native_clone(native, 0x40003d00, 0x40003ede, writer) + '.balign 4\n'

    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(asm, entry, out, 'usb-fullmix')
    payload.extend(code)
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new', '-n', out/'usb-fullmix.elf']))}
    assert base + len(payload) <= int(doc['runtime_limit'], 16)
    identity = 0x47aa5a0c
    assert payload[identity-base:identity-base+4] == b'T1DW'
    payload[identity-base+3] = ord('X')
    image = bytearray(raw[:src-B.BASE]) + payload
    patches = []

    def patch(name, at, before, after):
        i = at - B.BASE
        assert len(before) == len(after) and image[i:i+len(before)] == before, (name, hex(at))
        image[i:i+len(before)] = after
        patches.append(dict(name=name, address=hex(at), before=before.hex(), after=after.hex()))

    for name, at, oldtarget, target, suffix in (
        ('collect', 0x400276b2, efficient['methods']['usb_multitrack_collect_efficient'], 'usb_fullmix_collect', b''),
        ('silence', 0x400279ba, efficient['methods']['usb_multitrack_silence_efficient'], 'usb_fullmix_silence', b''),
        ('startup', 0x40003b32, old['methods']['usb_native_40003b32'], 'usb_native_40003b32', b''),
        ('writer', 0x40003d00, old['methods']['usb_native_40003d00'], 'usb_native_40003d00', b'\x4e\x71')):
        patch(name, at, b'\x4e\xf9'+B.BE(int(oldtarget,16))+suffix,
              b'\x4e\xf9'+B.BE(symbols[target])+suffix)
    patch('capture_qh_max882', 0x400040e8, bytes.fromhex('43b80000'), bytes.fromhex('43720000'))

    # Pin complete current UAC2 configuration/device before changing capture only.
    expected_cfg = bytearray(D.CONFIG_BEFORE)
    for at, value in ((D.CAPTURE_TERMINAL_CHANNELS, b'\x22'), (D.CAPTURE_AS_CHANNELS, b'\x22'),
                      (D.CAPTURE_PACKET_SIZE, (952).to_bytes(2,'little'))):
        o = at - D.CONFIG_ADDRESS
        expected_cfg[o:o+len(value)] = value
    assert image[D.CONFIG_ADDRESS-B.BASE:D.CONFIG_ADDRESS-B.BASE+len(expected_cfg)] == expected_cfg
    expected_dev = bytearray(D.DEVICE_BEFORE)
    expected_dev[D.DEVICE_REVISION-D.DEVICE_ADDRESS:D.DEVICE_REVISION-D.DEVICE_ADDRESS+2] = b'\x01\x01'
    assert image[D.DEVICE_ADDRESS-B.BASE:D.DEVICE_ADDRESS-B.BASE+len(expected_dev)] == expected_dev
    for name, at, before, after in (
        ('capture_terminal_channels', D.CAPTURE_TERMINAL_CHANNELS, b'\x22', b'\x2a'),
        ('capture_as_channels', D.CAPTURE_AS_CHANNELS, b'\x22', b'\x2a'),
        ('capture_subslot', 0x402fb49e, b'\x04', b'\x03'),
        ('capture_valid_bits', 0x402fb49f, b'\x20', b'\x18'),
        ('capture_endpoint_max', D.CAPTURE_PACKET_SIZE, (952).to_bytes(2,'little'), (882).to_bytes(2,'little')),
        ('device_revision', D.DEVICE_REVISION, b'\x01\x01', b'\x02\x01')):
        patch(name, at, before, after)

    boot = B.BASE + len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    assert bootstrap != (INPUT/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    cfg = dict(base=str(INPUT/'main-os.bin'), base_sha256=SHA,
        capture_channels=CHANNELS, channels=CHANNELS, return_channels=2, sample_rate=48000,
        subslot_bytes=3, valid_bits=24, stage_frame_bytes=STAGE_FRAME_BYTES, frame_bytes=FRAME_BYTES,
        channel_order=CHANNEL_ORDER, max_frames=7, max_packet_bytes=882, nominal_packet_bytes=756,
        ring=hex(RING), ring_slots=16, ring_stride=1024, stage=hex(STAGE), stage_bytes=FRAMES*STAGE_FRAME_BYTES,
        stage_reuses='T1DW inactive 16KiB DDR capture ring; active DMA packets remain in SRAM.',
        code=hex(entry), code_bytes=len(code), previous_runtime_end=hex(prior_end),
        methods={k:hex(v) for k,v in symbols.items()}, patches=patches,
        identity=dict(address=hex(identity), before='T1DW', after='T1DX', changed_bytes=1),
        source=dict(native_getter='0x400253d0', tdm_channels=14, tdm_stride=64,
                    packed_channels=28, packed_stride=84, packed_base='0x800053c0', frames=32,
                    arithmetic='Native full-level EMAC retained; signed Q31 high 24 bits emitted little-endian.'),
        packetizer=dict(source_bytes_per_frame=168, destination_bytes_per_frame=126,
                        samples_per_frame=42, conversion='logical>>8, lowbyte, >>8, lowbyte, >>8, lowbyte'),
        preserves='T1DW DSP, physical audio buffer handoff, host return, feedback, MIDI, native mode control and SRAM queue unchanged.',
        limits=['42-channel hardware enumeration and sustained capture pending.',
                'Native USB precision is 24 bits; 3-byte subslots retain those 24 bits without resampling.',
                'No hardware, flash or final package performed.'])
    doc.update(main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(payload), bytes=len(image),
               runtime_copy={**c,'bytes':len(payload)}, bootstrap=hex(boot), bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    doc['usb_fullmix'] = cfg
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out/name).write_bytes((INPUT/name).read_bytes())
    (out/'README.md').write_text(
        '# T1DX USB full mix component\n\n'
        'Class-compliant USB capture exposes 42 channels at 48 kHz: MAIN L/R, '
        'tracks 1–16 L/R, DELAY L/R, REVERB L/R, CHORUS L/R, then physical INPUT L/R. '
        'The effect pairs are wet outputs after their native mix-volume processing.\n\n'
        'Capture uses signed 24-bit little-endian samples in three-byte USB subslots. '
        'This preserves the native 24-bit transport precision and fits six or seven '
        'frames into 756 or 882 bytes per service interval. The host may expose these '
        'samples in a 32-bit container with eight unused low bits. There is no '
        'resampling or change to the two-channel host return.\n\n'
        'The efficient collector reads all 14 TDM channels and all 28 packed-reply '
        'channels into a 5,376-byte Q31 stage in the inactive old DDR capture ring. '
        'The packetizer uses a 168-byte source frame and a 126-byte destination frame; '
        'its sample loop emits exactly three bytes for each of 42 samples, including '
        'odd-frame partial packets. DMA continues to use the stable T1DW SRAM ring '
        '`80009800..8000D800`. Collection and silence remain gated by the native '
        'capture-enabled flag before any bulk work.\n\n'
        'This component changes MAIN only. The T1DW DSP, audio-buffer handoff, '
        'feedback and MIDI are retained. Hardware enumeration and sustained '
        '42-channel capture are pending; this directory is not a flash package.\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], usb_fullmix=cfg), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    build(parser.parse_args().out)
