#!/usr/bin/env python3
"""M3b: relocate the DT2 donor name chain into the v3 MAIN (true byte port).

Donor bytes verbatim; only the enumerated absolute operands are adapted
(the repo's relocation method). The helper's format call points at a
self-contained static-format stub (rev 2; see m3b_static_format.S and
m3b_receipt.json format_callee — the rev 1 native heap-format twin faulted
on hardware: EXCEPTION DS0059, the ~140-B-deep allocating chain overflowed
the GUI draw stack at its base) and its strlen call at the DN2 native
strlen (0x4017ED4C), a shallow stock leaf. Placement: appended at the image
end (RAM 0x47A53FA8+, the audit-verified unclaimed gap), covered by
extending the boot copier's fifth-blob count.

v2 (2026-10-09): the DN2 data adaptation for the flat 3-slot bank (the M3
doc's "slot = value") — the helper's out-of-range gate string repointed to
the donor OFF string, and the helper's bank-0 OFF divert (bnes at +0x4C)
made an unconditional branch so the baked pool table is indexed directly.
Plus the composition code: the bridge (assembled, register-preserving,
value-change cached) matching the drawer's call into the helper's donor ABI
(helper(this = a0 -> char* slot, value @ sp+0x1C)), and the 78-byte drawer
text region that draws the resolved name through the native text call.
Offline; reads frozen images only; assembles with the repo toolchain.
"""
import hashlib, json, struct, subprocess
from pathlib import Path

ROOT = Path('@WORKSPACE@')
D = ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin'
V3 = ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3'
BIN = ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/toolchain/build'

# placement (RAM 0x47A53FA8 = current blob end; file 0x332068 = image end)
HELPER_VA, HELPER_FILE = 0x47A53FA8, 0x332068
# the donor helper's true extent is 150 B (0x400164E0..0x40016576): the staged
# 128-B helper.bin was truncated before the format call + epilogue; the tail
# is byte-verified against the donor disassembly (helper_full.bin continuity).
HELPER_BYTES, HELPER_TAIL = 150, bytes.fromhex('2f042f024e924fef000c20024cd7041c4fef00144e75')
CLAMP_VA = HELPER_VA + 152                   # 150 + 2 pad, 4-aligned
LOOKUP_VA = CLAMP_VA + 16
STR_EMPTY_VA = LOOKUP_VA + 16          # '' (1B) | OFF (4B) | --- (4B)
STR_OFF_VA = STR_EMPTY_VA + 1
STR_DASH_VA = STR_EMPTY_VA + 5
TABLE_VA = STR_EMPTY_VA + 12           # 3 x 4B pointers, 4-aligned
NAMES_VA = TABLE_VA + 12               # SNARE\0 BASS\0 HI HAT\0
COUNT = 3
BRIDGE_VA = NAMES_VA + 20                    # 0x47A5408C, 4-aligned
STATIC_FMT_VA = BRIDGE_VA + 60               # 0x47A540C8 (12-B static format stub)
NAMESLOT_VA = STATIC_FMT_VA + 12             # 0x47A540D4 (char* slot, baked 0)
LASTVAL_VA = NAMESLOT_VA + 4                # 0x47A540D8 (cached value, baked -1)
DRAWER_TEXT_VA = 0x47A53B3C                   # replaced donor code-text region
DN2_STRLEN = 0x4017ED4C                       # DN2 native strlen twin (helper found-check)

def be32(v): return struct.pack('>I', v)

def assemble(src, va, name):
    work = V3/'src'/('.build-'+name)
    work.mkdir(exist_ok=True)
    out = work/(name+'.bin')
    def run(*argv):
        r = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        if r.returncode: raise RuntimeError(r.stdout+r.stderr)
        return r.stdout
    run(BIN/'gas/as-new', '-mcpu=5475', V3/'src'/src, '-o', work/(name+'.o'))
    run(BIN/'ld/ld-new', f'-Ttext={va:#x}', '-e', '0', '--no-warn-rwx-segments',
        work/(name+'.o'), '-o', work/(name+'.elf'))
    run(BIN/'binutils/objcopy', '-O', 'binary', '-j', '.text', work/(name+'.elf'), out)
    text = out.read_bytes()
    syms = {r[2]: int(r[0], 16) for line in
            run(BIN/'binutils/nm-new', '--defined-only', work/(name+'.elf')).splitlines()
            if len(r := line.split()) == 3}
    assert syms.get(name) == va, (name, syms)
    return text

def build():
    helper = bytearray((D/'helper_full.bin').read_bytes())
    assert len(helper) == HELPER_BYTES and helper[-len(HELPER_TAIL):] == HELPER_TAIL, 'donor helper tail mismatch'
    assert bytes(helper[:128]) == (D/'helper.bin').read_bytes(), 'helper_full.bin diverges from the staged 128-B helper.bin'
    clamp = bytearray((D/'clamp.bin').read_bytes())
    lookup = bytearray((D/'lookup.bin').read_bytes())
    patches = []
    def operand(buf, off, old, new, why):
        at = off + 2
        assert buf[at:at+4] == be32(old), (hex(off), buf[at:at+4].hex())
        buf[at:at+4] = be32(new)
        patches.append({'at': hex(off), 'old': hex(old), 'new': hex(new), 'why': why})
    # helper operands (offsets from the staged manifest)
    operand(helper, 0x16, 0x401E7A64, STATIC_FMT_VA,
            'format -> the static-format stub (rev 2): the native heap-format twin '
            '(format->builder->allocator->memcpy) is ~140 B deep and allocates per '
            'change inside the per-frame GUI draw call; on hardware (rev 1, DS0059) '
            'that overflowed the GUI stack at its base and faulted. The stub keeps '
            'the donor format ABI and write-through contract, resolved statically: '
            'no heap, no dispose needed, no deep calls.')
    operand(helper, 0x26, 0x4023F364, STR_OFF_VA, "out-of-range gate -> donor OFF string (M3 doc adaptation)")
    operand(helper, 0x30, 0x401997A8, CLAMP_VA, 'clamp relocated')
    operand(helper, 0x50, 0x4023A62D, STR_OFF_VA, 'OFF string relocated')
    operand(helper, 0x5A, 0x401537A8, LOOKUP_VA, 'lookup relocated')
    operand(helper, 0x68, 0x4018A498, DN2_STRLEN, 'strlen -> DN2 native twin')
    operand(helper, 0x76, 0x40226ED6, STR_DASH_VA, '--- string relocated')
    # the 0x3FF value gate -> count-1 (values beyond the bank display OFF)
    assert helper[0x1E:0x22] == be32(0x3FF)
    helper[0x1E:0x22] = be32(COUNT - 1)
    patches.append({'at': '0x1E', 'old': '0x3ff', 'new': hex(COUNT-1), 'why': 'pool clamp -> bank count'})
    # DN2 data adaptation (M3 doc "slot = value"): the donor diverts bank-0
    # values (raw 0..127) to OFF before the pool lookup; the DN2 bank is flat,
    # so the divert becomes an unconditional branch into the lookup.
    assert helper[0x4C:0x4E] == bytes.fromhex('660a')
    helper[0x4C:0x4E] = bytes.fromhex('600a')
    patches.append({'at': '0x4C', 'old': '660a', 'new': '600a',
                    'why': 'bank-0 OFF divert -> always lookup (DN2 flat bank, slot = value)'})
    # lookup table base -> our pool table
    operand(lookup, 0x4, 0x405BC768, TABLE_VA, 'pool table -> DN2 bank table')
    # data
    names = b'SNARE\0' + b'BASS\0' + b'HI HAT\0' + b'\0\0'   # name block padded to 4 (20 bytes)
    offs, at = [], NAMES_VA
    for nm in (b'SNARE\0', b'BASS\0', b'HI HAT\0'):
        offs.append(at); at += len(nm)
    table = b''.join(be32(o) for o in offs)
    strings = b'\0' + b'OFF\0' + b'---\0'
    strings_padded = strings + b'\0' * (12 - len(strings))
    # composition code (assembled): the bridge + the static format stub + the drawer text region
    bridge = assemble('m3b_bridge.S', BRIDGE_VA, 'm3b_bridge')
    assert len(bridge) == STATIC_FMT_VA - BRIDGE_VA, len(bridge)
    static_fmt = assemble('m3b_static_format.S', STATIC_FMT_VA, 'm3b_static_format')
    assert len(static_fmt) == NAMESLOT_VA - STATIC_FMT_VA, len(static_fmt)
    drawer_text = assemble('m3b_drawer_text.S', DRAWER_TEXT_VA, 'm3b_drawer_text')
    assert len(drawer_text) == 78, len(drawer_text)
    # baked scratch (copied at boot by the extended copier count)
    slot = be32(0) + be32(0xFFFFFFFF)
    helper_pad = b'\0' * (CLAMP_VA - HELPER_VA - len(helper))
    blob = (bytes(helper) + helper_pad + bytes(clamp) + bytes(lookup) + strings_padded
            + table + names + bridge + static_fmt + slot)
    assert CLAMP_VA == HELPER_VA + len(helper) + len(helper_pad), 'helper block layout'
    assert len(strings_padded) == 12 and TABLE_VA % 4 == 0 and NAMESLOT_VA % 4 == 0
    assert NAMESLOT_VA == HELPER_VA + len(blob) - 8, (hex(NAMESLOT_VA), hex(HELPER_VA + len(blob)))
    assert len(blob) % 4 == 0, len(blob)
    new_count = (8104 + len(blob)) // 4
    receipt = {'ok': True, 'schema': 'dn2-m3b-donor-relocation-3',
               'helper_va': hex(HELPER_VA), 'helper_bytes': len(helper), 'clamp_va': hex(CLAMP_VA), 'lookup_va': hex(LOOKUP_VA),
               'strings': {'empty': hex(STR_EMPTY_VA), 'off': hex(STR_OFF_VA), 'dash': hex(STR_DASH_VA)},
               'table_va': hex(TABLE_VA), 'names_va': hex(NAMES_VA), 'count': COUNT,
               'bridge_va': hex(BRIDGE_VA), 'bridge_bytes': len(bridge),
               'format_callee': {'kind': 'static-format stub (rev 2)', 'va': hex(STATIC_FMT_VA),
                                 'bytes': len(static_fmt),
                                 'why': 'rev 1 repointed the helper at the DN2 native heap-format twin; on hardware that chain is ~140 B deep and allocates per value change inside the per-frame GUI draw call and faulted (EXCEPTION DS0059, access error at the GUI stack base 0x00180000). The stub keeps the donor format ABI (this @ sp+4, text @ sp+8) and the write-through contract, resolved statically: no heap, no dispose, no deep calls; the baked names are stable for the life of the image.'},
               'nameslot_va': hex(NAMESLOT_VA), 'lastval_va': hex(LASTVAL_VA),
               'drawer_text_va': hex(DRAWER_TEXT_VA), 'drawer_text_bytes': len(drawer_text),
               'blob_bytes': len(blob), 'old_blob_bytes': 8104, 'copier_count': hex(new_count),
               'dn2_native': {'strlen': hex(DN2_STRLEN),
                              'note': 'the helper found-check keeps the DN2 native strlen twin (a shallow stock leaf); no other native callees remain'},
               'operand_patches': patches,
               'helper_sha256': hashlib.sha256(bytes(helper)).hexdigest(),
               'donor_helper_sha256': hashlib.sha256((D/'helper.bin').read_bytes()).hexdigest(),
               'scope': 'Offline donor relocation + composition code; no device access.'}
    (V3/'src/m3b_chain.bin').write_bytes(blob)
    (V3/'src/m3b_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    (V3/'src/m3b_drawer_text.bin').write_bytes(drawer_text)
    (V3/'src/m3b_revert.bin').write_bytes(bytes.fromhex('222f0024'))   # donor move.l 36(sp),d1
    # Rev 3: the donor epilogue expects 60 bytes of outstanding call args:
    # 24 from the border call + 36 from the skipped bank-letter call.
    # Reserve the skipped 36 bytes before branching; a bare branch leaves
    # SP 36 bytes above its entry value and restores registers from arguments.
    (V3/'src/m3b_skip.bin').write_bytes(bytes.fromhex('4fefffdc6028'))
    print(json.dumps({k: receipt[k] for k in ('ok','blob_bytes','copier_count','helper_va',
                                              'bridge_va','bridge_bytes','drawer_text_bytes')}, indent=1))
    print('operand patches:', len(patches))

if __name__ == '__main__':
    build()
