#!/usr/bin/env python3
"""Identify the keyboard-pitch build without changing the proven GUI/storage code."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.firmware.load import load

BASE = ROOT/'firmware/Digitone_II_OS1.11_oneshot_gui_v1_EXPERIMENTAL.syx'
BASE_SHA = '0d816a125a8df72f0db9888496d33dea881fa48d829ff96308fd2eeb4329576f'
MAIN_SHA = 'c0c796196792c817a18c98ba4ccfbf5acae4116bd7213220bebb7a5068d930a8'
TAG_ADDRESS = 0x402CF884
sha = lambda b: hashlib.sha256(b).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out.exists():
        raise RuntimeError('Choose a fresh output directory')
    image = BASE.read_bytes()
    assert sha(image) == BASE_SHA
    original = load(image).container.find(3).unpack()
    assert sha(original) == MAIN_SHA
    old = b'os1fs-gui-v1'.ljust(16, b'\0')
    new = b'os1keys-v1'.ljust(16, b'\0')
    offset = TAG_ADDRESS - 0x40000400
    assert original[offset:offset+16] == old
    assert original.count(old) == 1
    result = original[:offset] + new + original[offset+16:]
    assert len(result) == len(original)
    assert result[:offset] == original[:offset] and result[offset+16:] == original[offset+16:]
    out.mkdir(parents=True)
    (out/'main-os.bin').write_bytes(result)
    receipt = dict(ok=True, main_sha256=sha(result), input_main_sha256=MAIN_SHA,
                   input_firmware_sha256=BASE_SHA, main_bytes=len(result),
                   tag='os1keys-v1', protocol=4, only_tag_changed=True,
                   address=hex(TAG_ADDRESS), bytes=16, before=old.hex(), after=new.hex(),
                   all_GUI_storage_voice_and_ISR_code_exact=True,
                   builder_sha256=sha(Path(__file__).read_bytes()))
    (out/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
