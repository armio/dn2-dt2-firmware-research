#!/usr/bin/env python3
"""Build a native-ISA-checked v2 raw MAIN RDPROBE patch; no device I/O."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / 'firmware/ghidra/oneshot-proof/v7-source/src'
sys.path.insert(0, str(LIB))
from dnfw.patch.coldfire import Asm
from dnfw.patch import cave as cave_lib
from dnfw.image.coldfire import LoadedImage
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_040

SOURCE = ROOT / 'firmware/ghidra/storage-proof/v7-maintenance/section_3_MAIN_OS.bin'
SOURCE_MANIFEST = ROOT / 'firmware/ghidra/storage-proof/v7-maintenance/MANIFEST.json'
OUT = ROOT / 'firmware/ghidra/storage-proof/v7-drive-status-v2'
BASE = 0x40000400
CAVE, CAPACITY = 0x402DFA1C, 896
HOOK, NAME, NEXT_COMMAND, LOOP = 0x400CE0F6, 0x4021ACA8, 0x400CE1C2, 0x400CD4E0
OLD_HOOK = bytes.fromhex('41ea00097e1c97cb')
ALLOC, FREE, READ, TRANSMIT = 0x4011FFE8, 0x401201EE, 0x4012C59A, 0x400053D4
LBAS = (0, 0x5D8000, 0x5D8040, 0x5D80C0, 0x5D8400)
MAGIC = b'DN2RD001'
HEADER_BYTES, PAYLOAD_BYTES, FRAME_STACK = 32, 512, 92
ISA_MANUAL = 'https://www.nxp.com/docs/en/reference-manual/CFPRM.pdf'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def u16(n):
    return (n & 0xFFFF).to_bytes(2, 'big')


def u32(n):
    return (n & 0xFFFFFFFF).to_bytes(4, 'big')


def emit_word(a, opcode, extension=b''):
    a.bytes(u16(opcode) + extension)


def moveq(a, register, value):
    assert -128 <= value <= 127
    emit_word(a, 0x7000 | register << 9 | value & 0xFF)


def imm(a, register, value):
    emit_word(a, 0x203C | register << 9, u32(value))


def cmp(a, register, value):
    emit_word(a, 0x0C80 | register, u32(value))


def clear(a, register):
    emit_word(a, 0x4280 | register)


def tst(a, register):
    emit_word(a, 0x4A80 | register)


def stack_adjust(a, amount):
    emit_word(a, 0x4FEF, u16(amount))


def header_word(a, offset, register=None, value=None):
    # Header is A4-relative. Never keep it in volatile A0/A1 across a native call.
    if register is not None:
        emit_word(a, 0x2940 | register, u16(offset))
    else:
        # ColdFire forbids MOVE.L #imm32,d16(An); use two legal instructions.
        imm(a, 0, value)
        emit_word(a, 0x2940, u16(offset))


def validate_native_isa(instructions):
    """Check every emitted form against CFPRM, independently of emulation.

    This deliberately accepts only instruction families used by this handler.
    It is not an arbitrary ColdFire binary validator. Page references are the
    printed Rev.3 manual pages, not PDF indices. MOVE's addressing combination
    table is essential: a Motorola 68040 decoder accepts illegal ColdFire forms.
    """
    rows = []
    for ins in instructions:
        raw = bytes(ins.bytes)
        w = int.from_bytes(raw[:2], 'big')
        mode, reg = (w >> 3) & 7, w & 7
        if len(raw) not in (2, 4, 6):
            raise ValueError(f'ColdFire instruction exceeds 48 bits at {ins.address:#x}: {raw.hex()}')
        rule = None
        if w >> 12 in (1, 2, 3):
            size = {1: 1, 2: 4, 3: 2}[w >> 12]
            dm, dr = (w >> 6) & 7, (w >> 9) & 7
            if mode == 7 and reg > 4:
                raise ValueError('Invalid MOVE source effective address')
            if dm == 7 and dr > 1:
                raise ValueError('Invalid MOVE destination effective address')
            if size == 1 and (mode == 1 or dm == 1):
                raise ValueError('Byte MOVE cannot use address-register direct')
            # CFPRM 4-48: source modes requiring extension(s) constrain dest.
            if (mode == 5 or (mode == 7 and reg == 2)) and (dm == 6 or dm == 7):
                raise ValueError('Forbidden displacement-source MOVE combination')
            extended_source = mode == 6 or (mode == 7 and reg in (0, 1, 3, 4))
            if extended_source and (dm in (5, 6, 7)):
                # ISA_B/C adds immediate -> d16 only for byte/word, not long.
                if not (mode == 7 and reg == 4 and dm == 5 and size in (1, 2)):
                    raise ValueError('Forbidden ColdFire extended-source MOVE destination')
            rule = 'MOVE/MOVEA;4-47..4-49, addressing-combination table4-48'
        elif w & 0xF100 == 0x7000:
            rule = 'MOVEQ;4-52'
        elif w & 0xF000 == 0x6000:
            if w & 0xFF != 0 or len(raw) != 4:
                raise ValueError('Handler branches must use supported signed16 displacement')
            rule = 'Bcc/BRA/BSR;4-13..4-14,4-20,4-23'
        elif w & 0xF1C0 == 0x41C0 or w in (0x4EB9, 0x4EF9) or w & 0xFFC0 == 0x4840:
            # LEA, absolute-long JSR/JMP, PEA: control addressing modes only.
            if mode not in (2, 5, 6, 7) or (mode == 7 and reg > 3):
                raise ValueError('Invalid control effective address')
            rule = 'LEA/JSR/JMP/PEA;4-40..4-44,4-68'
        elif w & 0xFB80 == 0x4880:
            if w & 0x40 == 0 or mode not in (2, 5):
                raise ValueError('ColdFire MOVEM requires long and indirect/displacement EA')
            rule = 'MOVEM;4-50..4-51'
        elif w & 0xFF00 in (0x4200, 0x4A00):
            size = (w >> 6) & 3
            if size == 3 or (mode == 1 and (w & 0xFF00 == 0x4200 or size == 0)):
                raise ValueError('Invalid CLR/TST size or address register')
            if mode not in (0, 1, 2, 3, 4, 5, 6, 7) or (mode == 7 and reg > (4 if w & 0xFF00 == 0x4A00 else 1)):
                raise ValueError('Invalid CLR/TST effective address')
            rule = 'CLR/TST;4-27,4-85 (TST.W/L An explicitly legal)'
        elif w & 0xFFF8 in (0x0C80, 0x0280, 0x0480):
            if len(raw) != 6:
                raise ValueError('Long immediate-to-Dn instruction must be48 bits')
            rule = 'CMPI.L/ANDI.L/SUBI.L Dn;4-30,4-10,4-78'
        elif w & 0xF1F8 == 0x5180:
            rule = 'SUBQ.L Dn;4-79'
        elif w & 0xF1C0 == 0x91C0 and mode == 1:
            rule = 'SUBA.L An,An;4-77'
        elif w & 0xF1F8 == 0x8080:
            rule = 'OR.L Dn,Dn;4-66'
        elif w & 0xF1F8 == 0xE188:
            rule = 'LSL.L immediate,Dn;4-44..4-45'
        elif w == 0x4E75:
            rule = 'RTS;4-72'
        else:
            raise ValueError(f'Unreviewed ColdFire form at {ins.address:#x}: {raw.hex()}')
        rows.append({'address': f'0x{ins.address:08X}', 'bytes': raw.hex(),
                     'instruction': f'{ins.mnemonic} {ins.op_str}', 'manual_rule': rule})
    return rows


def old_form_regressions(decoder):
    """Bind the negative gate to the actual frozen, hardware-failed v1 image."""
    prior = ROOT / 'firmware/ghidra/storage-proof/v7-drive-status/section_3_MAIN_OS.bin'
    raw = prior.read_bytes()
    assert sha(raw) == '6e192ea5d5e9abffbd09c7bcb79a116308650e0d80c20ff9d2b5ceb63366eb50'
    rows = []
    for va, hx in ((0x402DFB08, '297c444e32520000'),
                   (0x402DFB10, '297c443030310004'),
                   (0x402DFB2C, '297c00000000001c')):
        b = raw[va-BASE:va-BASE+8]
        assert b.hex() == hx
        try:
            validate_native_isa(list(decoder.disasm(b, va)))
        except ValueError as e:
            rows.append({'address': f'0x{va:08X}', 'bytes': hx, 'rejected': True,
                         'reason': str(e)})
        else:
            raise AssertionError('Native ISA gate accepted hardware-failed v1 form')
    return rows


def make_code():
    a = Asm()
    # Save every D0-D7/A0-A6 register and reserve an independent 32B header.
    # No dispatcher A6-relative local, global scratch or BSS is touched.
    stack_adjust(a, -FRAME_STACK)
    a.hex('48d77fff')
    clear(a, 2); clear(a, 3)
    moveq(a, 4, 1); moveq(a, 5, -1); clear(a, 6)
    a.hex('97cb')  # SUBA.L A3,A3: no allocated payload yet.
    a.hex('49ef003c')  # LEA 60(SP),A4: header follows saved registers.
    clear(a, 1)
    a.hex('122a0008')  # MOVE.B 8(A2),D1: exact separator after command.
    cmp(a, 1, 32); a.bne('header')
    a.hex('41ea0009')  # LEA 9(A2),A0.
    a._br('61', 'hex8'); tst(a, 1); a.beq('header')
    a.move_l_dd(0, 2)
    clear(a, 1); a.hex('1218')  # Consume separator after eight LBA digits.
    cmp(a, 1, 32); a.bne('header')
    a._br('61', 'hex8'); tst(a, 1); a.beq('header')
    a.move_l_dd(0, 3)
    a.hex('4a10'); a.bne('header')  # Exactly 26 characters, then NUL.
    cmp(a, 3, PAYLOAD_BYTES); a.bne('header')
    for lba in LBAS:
        cmp(a, 2, lba); a.beq('args_ok')
    a.bra('header')

    a.label('args_ok')
    a.hex('48780200'); a.jsr(ALLOC); stack_adjust(a, 4)
    a.hex('2640')  # MOVEA.L D0,A3; native allocator supplies 16B alignment.
    tst(a, 0); a.bne('prefill')
    moveq(a, 4, 2); a.bra('header')
    a.label('prefill')
    a.hex('204b')  # MOVEA.L A3,A0.
    imm(a, 0, 0xA5A5A5A5); imm(a, 7, PAYLOAD_BYTES // 4)
    a.label('fill')
    a.hex('20c0')  # MOVE.L D0,(A0)+, exactly 128 longwords.
    a.hex('5387'); a.bne('fill')
    a.hex('2f0b2f032f02'); a.jsr(READ)
    a.move_l_dd(0, 5)  # FIRST instruction after native read: bind raw D0.
    stack_adjust(a, 12)
    moveq(a, 4, 3); tst(a, 5); a.bne('header')
    clear(a, 4); imm(a, 6, PAYLOAD_BYTES)

    a.label('header')
    header_word(a, 0, value=int.from_bytes(MAGIC[:4], 'big'))
    header_word(a, 4, value=int.from_bytes(MAGIC[4:], 'big'))
    for offset, register in ((8, 2), (12, 3), (16, 4), (20, 5), (24, 6)):
        header_word(a, offset, register=register)
    header_word(a, 28, value=0)
    a.hex('2f0c48780020'); a.jsr(TRANSMIT); stack_adjust(a, 8)
    tst(a, 6); a.beq('free')
    a.hex('2f0b2f06'); a.jsr(TRANSMIT); stack_adjust(a, 8)
    a.label('free')
    a.hex('4a8b'); a.beq('done')
    a.hex('2f0b'); a.jsr(FREE); stack_adjust(a, 4)
    a.label('done')
    a.hex('4cd77fff'); stack_adjust(a, FRAME_STACK)
    a.jmp(LOOP)

    # Eight strict hexadecimal digits. D1=1 success or 0 failure; D0=value.
    # Lowercase a-f is accepted; separators/trailing bytes are checked above.
    a.label('hex8')
    clear(a, 0); moveq(a, 7, 8)
    a.label('digit')
    clear(a, 1); a.hex('1218')  # MOVE.B (A0)+,D1 after full-width clear.
    cmp(a, 1, 48); a.bcs('invalid')
    cmp(a, 1, 57); a._br('63', 'decimal')
    a.hex('0281000000df')  # ANDI.L #0xDF,D1: uppercase ASCII a-f.
    cmp(a, 1, 65); a.bcs('invalid')
    cmp(a, 1, 70); a.bhi('invalid')
    a.hex('048100000037'); a.bra('shift')
    a.label('decimal'); a.hex('048100000030')
    a.label('shift'); a.hex('e98880815387'); a.bne('digit')
    moveq(a, 1, 1); a.rts()
    a.label('invalid'); clear(a, 1); a.rts()
    code = a.link()
    assert len(code) <= CAPACITY
    return code, {name: CAVE + offset for name, offset in a._lab.items()}


def changed_ranges(old, new):
    result = []
    start = None
    for i, (x, y) in enumerate(zip(old, new)):
        if x != y and start is None:
            start = i
        if x == y and start is not None:
            result.append((start, i)); start = None
    if start is not None:
        result.append((start, len(old)))
    return [{'offset': f'0x{lo:08X}', 'virtual_address': f'0x{BASE+lo:08X}',
             'length': hi-lo, 'old': old[lo:hi].hex(), 'new': new[lo:hi].hex()}
            for lo, hi in result]


def make_patch(source):
    metadata = json.loads(SOURCE_MANIFEST.read_text())
    assert sha(source) == metadata['main_sha256'], 'Maintenance source identity mismatch'
    assert source[0x400CF088-BASE:0x400CF088-BASE+6] == bytes.fromhex('81b940287520')
    assert source[HOOK-BASE:HOOK-BASE+8] == OLD_HOOK
    assert source[NAME-BASE:NAME-BASE+9] == b'#MMCDUMP\0'
    assert source[READ-BASE:READ-BASE+8] == bytes.fromhex('4fefffec48d7043c')
    assert source[0x4012C60A-BASE:0x4012C60A-BASE+6] == bytes.fromhex('74ff60000152')
    assert source[0x4012C75E-BASE:0x4012C75E-BASE+2] == bytes.fromhex('4282')
    assert source[0x4012C774-BASE:0x4012C774-BASE+10] == bytes.fromhex('20024cd7043c4fef0014')
    image = LoadedImage(dest=BASE, content=source)
    runs = cave_lib.find_free_runs(image, 0x4026E000, 0x402E2000, 32)
    verdict = next(v for v in cave_lib.classify(image, runs, 0x4026E000, 0x402E2000)
                   if v.run.address == CAVE and v.run.size == CAPACITY)
    assert verdict.passes and not any(source[CAVE-BASE:CAVE-BASE+CAPACITY])
    # All existing V7 code remains outside our known padding reservation.
    occupied = json.loads((LIB/'dnfw/mods/usbprobe_code.json').read_text())['edits']
    for edit in occupied:
        lo, hi = edit['va'], edit['va'] + len(edit['new']) // 2
        assert not (lo < CAVE+CAPACITY and CAVE < hi)
    code, labels = make_code()
    decoder = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040)
    decoded = list(decoder.disasm(code, CAVE))
    assert sum(i.size for i in decoded) == len(code), 'Payload disassembly incomplete'
    native_isa = validate_native_isa(decoded)
    regressions = old_form_regressions(decoder)
    patched = bytearray(source)
    patched[NAME-BASE:NAME-BASE+9] = b'#RDPROBE\0'
    patched[HOOK-BASE:HOOK-BASE+8] = bytes.fromhex('4ef9') + u32(CAVE) + bytes.fromhex('4e71')
    patched[CAVE-BASE:CAVE-BASE+len(code)] = code
    patched = bytes(patched)
    assert len(patched) == len(source)
    allowed = [(NAME-BASE, NAME-BASE+9), (HOOK-BASE, HOOK-BASE+8), (CAVE-BASE, CAVE-BASE+len(code))]
    assert all(any(lo <= i < hi for lo, hi in allowed)
               for i, (x, y) in enumerate(zip(source, patched)) if x != y)
    report = {
        'schema': 'dn2-v7-drive-status-raw-patch-2',
        'source_main': str(SOURCE), 'before_sha256': sha(source),
        'after_sha256': sha(patched), 'bytes': len(patched),
        'changed_byte_count': sum(x != y for x, y in zip(source, patched)),
        'changed_ranges': changed_ranges(source, patched),
        'hook': {'virtual_address': f'0x{HOOK:08X}', 'old': OLD_HOOK.hex(),
                 'new': patched[HOOK-BASE:HOOK-BASE+8].hex(), 'return': f'0x{LOOP:08X}'},
        'placement': {'virtual_address': f'0x{CAVE:08X}', 'capacity': CAPACITY,
                      'used': len(code), 'labels': {k: f'0x{v:08X}' for k, v in labels.items()},
                      'zero_padding_static_verdict': verdict.as_dict(),
                      'no_overlap_with_existing_v7_edits': True,
                      'below_initializer_start': '0x402FC000',
                      'global_or_bss_scratch_bytes': 0,
                      'stack_reserved_bytes': FRAME_STACK, 'heap_allocation_bytes': PAYLOAD_BYTES,
                      'prefill': '128 longwords of 0xA5A5A5A5 before READ'},
        'protocol': {'command': '#RDPROBE XXXXXXXX 00000200', 'magic_ascii': MAGIC.decode(),
                     'header_bytes': HEADER_BYTES, 'byte_order': 'big-endian',
                     'fields': ['magic[8]', 'lba_u32', 'requested_count_u32', 'outcome_u32',
                                'raw_driver_result_u32', 'payload_length_u32', 'reserved_u32'],
                     'outcomes': {'0':'native_success', '1':'bad_arguments',
                                  '2':'allocation_failed', '3':'native_read_failed'},
                     'raw_driver_not_called': '0xFFFFFFFF',
                     'payload_length': '512 only if native D0==0, else0 and no payload transmitted',
                     'fixed_lbas': [f'0x{x:08X}' for x in LBAS],
                     'strict_syntax': 'exact26 characters; one space at8 and17; eight ASCII hex digits per argument'},
        'native_abi': {'read': {'entry':f'0x{READ:08X}', 'stack_args':['lba','byte_count','buffer'],
                              'success':'D0==0', 'failure':'D0!=0',
                              'proof':'4012C60A sets D2=-1;4012C75E clears D2 after completion waits/copy;4012C774 returns D0=D2'},
                       'allocate': {'entry':f'0x{ALLOC:08X}','stack_args':['byte_count'], 'result':'D0 pointer;16B aligned'},
                       'free': {'entry':f'0x{FREE:08X}','stack_args':['pointer']},
                       'transmit': {'entry':f'0x{TRANSMIT:08X}','stack_args':['byte_count','buffer'],
                                    'copies_into_ring_before_return':True,'delivery_acknowledgment':False},
                       'native_volatile_registers':['D0','D1','A0','A1'],
                       'wrapper_preserved_registers':'D0-D7,A0-A6 and original dispatcher SP'},
        'preservation': {'maintenance_gate_unchanged':True,'only_main_patched':True,
                         'source_console_task_and_native_driver_unchanged':True},
        'hardware_tested':False,'device_commands_sent':0,'firmware_transferred':False,
        'native_isa': {'all_passed': True, 'manual_url': ISA_MANUAL,
                       'manual_revision': 3, 'scope': 'All emitted handler instruction forms; not arbitrary stock bytes.',
                       'instructions': native_isa, 'rejected_old_forms': regressions},
        'limits':['Native read/transmit can wait internally; wrapper does not add a firmware timeout.',
                  'Native zero status is not power-cycle persistence, mount or file-loader proof.',
                  'Cave passes existing static classifier; runtime whole-boot write watch has not been performed.'],
        'disassembly': [{'address':f'0x{i.address:08X}','bytes':i.bytes.hex(),
                         'instruction':f'{i.mnemonic} {i.op_str}'} for i in decoded],
    }
    return patched, code, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=OUT)
    parser.add_argument('--replace-development', action='store_true')
    args = parser.parse_args()
    out = args.output_dir
    if (out/'section_3_MAIN_OS.bin').exists() and not args.replace_development:
        raise SystemExit('Refusing to overwrite raw candidate; choose a fresh output directory')
    source = SOURCE.read_bytes()
    patched, code, report = make_patch(source)
    out.mkdir(parents=True, exist_ok=True)
    (out/'section_3_MAIN_OS.bin').write_bytes(patched)
    (out/'handler.bin').write_bytes(code)
    shutil.copyfile(__file__, out/Path(__file__).name)
    report['builder_sha256'] = sha(Path(__file__).read_bytes())
    report['encoder_sha256'] = sha((LIB/'dnfw/patch/coldfire.py').read_bytes())
    (out/'patch-report.json').write_text(json.dumps(report, indent=2)+'\n')
    (out/'handler.asm').write_text('\n'.join(f"{i['address']}  {i['bytes']:20} {i['instruction']}" for i in report['disassembly'])+'\n')
    assert sha(SOURCE.read_bytes()) == report['before_sha256']
    print(json.dumps({'raw_main':str(out/'section_3_MAIN_OS.bin'),
                      'sha256':report['after_sha256'],'cave_bytes':len(code),
                      'report':str(out/'patch-report.json')},indent=2))


if __name__ == '__main__':
    main()
