#!/usr/bin/env python3
"""Guarded DN2 UAC2 descriptor transformation; no device or transport access.

The capture contract is fixed at 34 signed 32-bit channels / 48 kHz, ordered
MAIN L/R, then T1 L/R through T16 L/R. The stereo host-return descriptors and
MIDI descriptors stay byte-identical. This is only one part of the feature:
the CF packetizer/rings and DSP exporters must implement the same contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MAIN_BASE = 0x40000400
DEVICE_ADDRESS = 0x402FB50B
CONFIG_ADDRESS = 0x402FB3C3
TABLE_ADDRESS = 0x40287678
CLOCK_CUR_ADDRESS = 0x402FB527
CLOCK_RANGE_ADDRESS = 0x402FB52B
CAPTURE_CHANNELS = 34
RETURN_CHANNELS = 2
SAMPLE_RATE = 48000
SUBSLOT_BYTES = 4
VALID_BITS = 32
SERVICE_INTERVALS_PER_SECOND = 8000
NOMINAL_FRAMES_PER_PACKET = 6
MAX_FRAMES_PER_PACKET = 7
NOMINAL_PACKET_BYTES = CAPTURE_CHANNELS * SUBSLOT_BYTES * NOMINAL_FRAMES_PER_PACKET
MAX_PACKET_BYTES = CAPTURE_CHANNELS * SUBSLOT_BYTES * MAX_FRAMES_PER_PACKET
CHANNEL_ORDER = ("MAIN L", "MAIN R") + tuple(
    f"T{track} {side}" for track in range(1, 17) for side in ("L", "R"))

DEVICE_BEFORE = bytes.fromhex("12010002ef02014035193410010001020301")
# Extract the unchanged vendor descriptor from the user's official image.
_stock = (Path(__file__).resolve().parents[1] / 'firmware/dn2-1.11/section_3_MAIN_OS.bin').read_bytes()
CONFIG_BEFORE = _stock[CONFIG_ADDRESS-MAIN_BASE:CONFIG_ADDRESS-MAIN_BASE+328]
assert hashlib.sha256(CONFIG_BEFORE).hexdigest() == '47295ebca20200534ec684b31b197badceca82f6db2b19441a612ecfd84de41e'
del _stock
TABLE_PREFIX_BEFORE = bytes.fromhex(
    "400040a640004054402fb50b402fb3c300000148")
CLOCK_CUR_BEFORE = bytes.fromhex("80bb0000")
CLOCK_RANGE_BEFORE = bytes.fromhex("010080bb000080bb000000000000")

# Absolute fields in the exact OS1.11/T1DT descriptor layout.
CAPTURE_TERMINAL_CHANNELS = 0x402FB407
CAPTURE_AS_CHANNELS = 0x402FB494
CAPTURE_PACKET_SIZE = 0x402FB4A4
DEVICE_REVISION = 0x402FB517


def _offset(address: int) -> int:
    return address - MAIN_BASE


def _read(image: bytes, address: int, length: int) -> bytes:
    offset = _offset(address)
    if offset < 0 or offset + length > len(image):
        raise ValueError(f"MAIN image does not contain 0x{address:08X}+{length}")
    return image[offset:offset + length]


def _expect(image: bytes, address: int, expected: bytes, label: str) -> None:
    if _read(image, address, len(expected)) != expected:
        raise ValueError(f"Unexpected {label} at 0x{address:08X}; refusing transformation")


def transform_main(image: bytes, *, bcd_device: int = 0x0101) -> tuple[bytes, dict]:
    """Return a new image and receipt; the caller retains ownership of its input.

    The new bcdDevice is an enumeration revision hint, not a guarantee that a
    host has discarded every cached channel mapping. PID/serial stay unchanged.
    """
    if not isinstance(bcd_device, int) or isinstance(bcd_device, bool):
        raise ValueError("bcdDevice must be a BCD uint16")
    if not 0 <= bcd_device <= 0x9999 or any(
            ((bcd_device >> shift) & 15) > 9 for shift in (0, 4, 8, 12)):
        raise ValueError("bcdDevice must be a BCD uint16")
    if bcd_device == 0x0001:
        raise ValueError("bcdDevice must differ from the stereo descriptor revision 0x0001")
    for address, value, label in (
            (DEVICE_ADDRESS, DEVICE_BEFORE, "PID1034 device descriptor"),
            (CONFIG_ADDRESS, CONFIG_BEFORE, "UAC2 configuration"),
            (TABLE_ADDRESS, TABLE_PREFIX_BEFORE, "selected configuration table"),
            (CLOCK_CUR_ADDRESS, CLOCK_CUR_BEFORE, "48kHz CUR response"),
            (CLOCK_RANGE_ADDRESS, CLOCK_RANGE_BEFORE, "48kHz RANGE response")):
        _expect(image, address, value, label)

    patches = (
        (CAPTURE_TERMINAL_CHANNELS, bytes([CAPTURE_CHANNELS]), "capture terminal channels"),
        (CAPTURE_AS_CHANNELS, bytes([CAPTURE_CHANNELS]), "capture streaming channels"),
        (CAPTURE_PACKET_SIZE, MAX_PACKET_BYTES.to_bytes(2, "little"), "capture endpoint maximum"),
        (DEVICE_REVISION, bcd_device.to_bytes(2, "little"), "device enumeration revision"))
    output = bytearray(image)
    fields = []
    allowed_offsets = set()
    for address, replacement, label in patches:
        offset = _offset(address)
        previous = bytes(output[offset:offset + len(replacement)])
        output[offset:offset + len(replacement)] = replacement
        allowed_offsets.update(range(offset, offset + len(replacement)))
        fields.append({"address": f"{address:08X}", "field": label,
                       "before": previous.hex(), "after": replacement.hex()})
    output = bytes(output)
    changed = [i for i, (before, after) in enumerate(zip(image, output)) if before != after]
    if len(output) != len(image) or any(i not in allowed_offsets for i in changed):
        raise AssertionError("Descriptor-only transformation changed another MAIN byte")
    receipt = {
        "kind": "dn2_uac2_multitrack_descriptors",
        "input_sha256": hashlib.sha256(image).hexdigest(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "main_base": f"{MAIN_BASE:08X}", "capture_channels": CAPTURE_CHANNELS,
        "host_return_channels": RETURN_CHANNELS, "sample_rate": SAMPLE_RATE,
        "subslot_bytes": SUBSLOT_BYTES, "valid_bits": VALID_BITS,
        "nominal_packet_bytes": NOMINAL_PACKET_BYTES, "maximum_packet_bytes": MAX_PACKET_BYTES,
        "bcd_device": f"{bcd_device:04X}", "channel_order": list(CHANNEL_ORDER),
        "fields": fields, "changed_byte_addresses": [f"{MAIN_BASE + i:08X}" for i in changed],
        "configuration_length": len(CONFIG_BEFORE),
        "runtime_configuration_length_initializer_unchanged": "40006800",
        "channel_name_strings": "unchanged; numeric host channel labels are sufficient",
        "transport_implemented_by_this_helper": False,
        "hardware_enumeration_verified": False,
    }
    return output, receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, help="Optional new candidate MAIN; input is never overwritten")
    parser.add_argument("--bcd-device", type=lambda value: int(value, 0), default=0x0101)
    args = parser.parse_args()
    output, receipt = transform_main(args.input.read_bytes(), bcd_device=args.bcd_device)
    if args.output:
        if args.output.resolve() == args.input.resolve():
            parser.error("output must differ from input")
        with args.output.open("xb") as stream:
            stream.write(output)
        receipt["output"] = str(args.output.resolve())
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
