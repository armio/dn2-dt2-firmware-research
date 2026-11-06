"""Stop a held sampler voice before binding a shorter PCM allocation."""
import argparse
import json
from pathlib import Path

from build_dt2_dsp_stereo_rate_fix import A, B, C, O

PARENT_SHA = '495a2de2cee75d5c7c9f61e2fb28daed3a40cadf0223de3f57ff24238664f58e'
OUTPUT_SHA = '65d2587813736e010ce23601f79da019b101a6d43c09b7487f341ad8a3fec3ce'
SITE, RESUME, CODE = 0xbcb01d, 0xbcb021, 0xbcb080


def build(parent, out):
    raw = parent.read_bytes()
    doc = json.loads((parent.parent/'build-receipt.json').read_text())
    if C.SHA(raw) != PARENT_SHA or doc['section7_sha256'] != PARENT_SHA:
        raise ValueError('wrong parent DSP')
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = B.decode_view(k, raw)
    displaced = memory.read_sw(SITE, 8)
    if displaced != bytes.fromhex('fe4d3f0ea40f6500'):
        raise ValueError('unexpected native valid-descriptor bind')

    out.mkdir(parents=True, exist_ok=True)
    asm = out/'rebind.asm'
    # BIND has already validated the incoming size. I4 points at the actual
    # left or right voice record, R12 is the new frame count. Production slots
    # fit inside the 400 MiB pool. R2 and M4 are overwritten on the native path.
    asm.write_text('''.SECTION/PM seg_pmco;
      R2 = DM(98, I4);
      COMPU(R2, R12);
      IF LE JUMP 0x0;
''')
    be, offsets = A._selas(asm, out)
    prefix = bytearray(O.load_bytes(be))
    # Reuse the native invalid-descriptor path's byte-width store to ACTIVE.
    # Subsequent note-on arms the updated record through the original code.
    set_offset = memory.read_sw(0xbcb014, 4)
    clear_active = memory.read_sw(0xbcb01a, 4)
    if set_offset.hex() != 'a40fb801' or clear_active.hex() != '3e49bc96':
        raise ValueError('native ACTIVE reset differs')
    unchanged = CODE + (len(prefix)+8)//2
    last = offsets[-1]
    prefix[last:] = C.S.to_bytes(C.S.retarget(C.S.to_value(prefix[last:]), 'addr24',
                                              CODE+last//2, unchanged))
    suffix = C.S.to_bytes(0x063e00000000 | RESUME)
    code = bytes(prefix) + set_offset + clear_active + displaced + suffix
    n = len(prefix)
    offsets = offsets + [n, n+4, n+8, n+12, n+16]
    physical = C.S.code_address(CODE, window='l2')
    if physical != 0x20096100 or any(
            addr < physical+len(code) and physical < addr+len(data)
            for addr, data in C.B.load_regions(raw)):
        raise ValueError('DSP code gap unavailable')
    patch = C.S.to_bytes(0x063e00000000 | CODE) + b'\x01\x00'
    image = bytearray(raw)
    C.B.write_span(image, C.S.code_address(SITE, window='l2'), patch)
    result = C.B.insert_before_final(bytes(image), C.B.block(physical, code))
    walk = C.B.walk(result)
    first, last_block = walk.blocks[7], walk.blocks[-1]
    header = C.B.block(first.target, flags=first.flags, argument=last_block.offset-first.offset)
    result = result[:first.offset]+header+result[first.end:]
    if not C.B.walk(result).complete:
        raise ValueError('incomplete DSP load stream')
    doc.update(section7_sha256=C.SHA(result), baseline_sha256=PARENT_SHA)
    doc['dsp_rebind_guard'] = dict(site=hex(SITE), resume=hex(RESUME), before=displaced.hex(),
                                   after=patch.hex(), code=hex(CODE), physical=hex(physical),
                                   code_bytes=len(code), instruction_offsets=offsets)
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    return doc['section7_sha256']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.parent, args.out))
