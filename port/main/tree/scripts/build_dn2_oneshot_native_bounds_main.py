#!/usr/bin/env python3
"""Compose reviewed native-boundary waveform code on the frozen keyboard MAIN."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.firmware.load import load

BASE = ROOT/'firmware/Digitone_II_OS1.11_oneshot_keyboard_v1_EXPERIMENTAL.syx'
BASE_SHA = 'a4a2104206d33c8d2e4191640d5454c785dfb01f6618c25c2f53a9f77b81ba58'
MAIN_SHA = '18963ebb2a9b0f546a80ad9f11f7a27963a14d831ac26f2d5bfa7b747d627854'
ROM_BASE, TAG_ADDRESS = 0x40000400, 0x402CF884
WIDGET_ROM, WIDGET_RAM, WIDGET_SIZE = 0x40330EC0, 0x47A52A00, 0x1000
OLD_WIDGET_SHA = '9c2b34dd658fcfb337e5f942347b6f4d21e596f010fdb63967b40c451e50d28f'
sha = lambda data: hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--widget', type=Path, required=True)
    parser.add_argument('--widget-receipt', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    require(not out.exists(), 'Choose a fresh output directory')
    packed = BASE.read_bytes()
    require(sha(packed) == BASE_SHA, 'Wrong frozen keyboard firmware')
    original = load(packed).container.find(3).unpack()
    require(sha(original) == MAIN_SHA, 'Wrong baseline MAIN')
    widget = args.widget.read_bytes()
    receipt = json.loads(args.widget_receipt.read_text())
    require(receipt['ok'] and receipt['sha256'] == sha(widget)
            and receipt['bytes'] == len(widget), 'Widget receipt differs')
    require(int(receipt['load'], 0) == WIDGET_RAM and len(widget) <= WIDGET_SIZE
            and len(widget) % 4 == 0, 'Widget exceeds its original reservation')
    symbols = receipt['symbols']
    require(int(symbols['os_wave_cache_poll'], 0) == WIDGET_RAM
            and int(symbols['os_wave_draw'], 0) == 0x47A52C20,
            'Public waveform entry moved')
    old_widget = (ROOT/'output/dn2-research/oneshot-gui-native-v1/widget.bin').read_bytes()
    require(sha(old_widget) == OLD_WIDGET_SHA, 'Old waveform component changed')
    offset = WIDGET_ROM-ROM_BASE
    before = original[offset:offset+WIDGET_SIZE]
    require(before == old_widget.ljust(WIDGET_SIZE, b'\0'), 'Widget reservation differs')
    new_region = widget.ljust(WIDGET_SIZE, b'\0')
    result = bytearray(original)
    result[offset:offset+WIDGET_SIZE] = new_region
    tag_at = TAG_ADDRESS-ROM_BASE
    old_tag = b'os1keys-v1'.ljust(16, b'\0')
    new_tag = b'os1bounds-v1'.ljust(16, b'\0')
    require(result[tag_at:tag_at+16] == old_tag, 'Old identity differs')
    result[tag_at:tag_at+16] = new_tag
    require(len(result) == len(original), 'MAIN size changed')
    reconstructed = bytearray(result)
    reconstructed[offset:offset+WIDGET_SIZE] = before
    reconstructed[tag_at:tag_at+16] = old_tag
    require(reconstructed == original, 'Unrelated MAIN bytes changed')
    out.mkdir(parents=True)
    (out/'main-os.bin').write_bytes(result)
    (out/'waveform-region.bin').write_bytes(new_region)
    report = dict(ok=True, main_sha256=sha(result), input_main_sha256=MAIN_SHA,
                  input_firmware_sha256=BASE_SHA, main_bytes=len(result),
                  tag='os1bounds-v1', protocol=4, only_tag_and_waveform_changed=True,
                  storage_voice_ISR_and_controls_exact=True,
                  widget_rom=hex(WIDGET_ROM), widget_ram=hex(WIDGET_RAM),
                  widget_region_bytes=WIDGET_SIZE, widget_sha256=sha(widget),
                  widget_region_sha256=sha(new_region), original_widget_region_sha256=sha(before),
                  widget_path=str(args.widget.resolve().relative_to(ROOT)),
                  widget_receipt_path=str(args.widget_receipt.resolve().relative_to(ROOT)),
                  widget_receipt_sha256=sha(args.widget_receipt.read_bytes()),
                  tag_address=hex(TAG_ADDRESS), builder_sha256=sha(Path(__file__).read_bytes()))
    (out/'build-receipt.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
