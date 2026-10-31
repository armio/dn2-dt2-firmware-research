#!/usr/bin/env python3
"""Merge-v3: apply the storage v1->v2 delta to the native-bounds candidate MAIN.

The native-bounds candidate already carries storage merge v1 (worker, FS
graft, relocated probe, snare bank). This builder applies surgical patches:
the three-slot bank at the identical offset, the v2 worker in-place inside
its padded slot, the M3a SAMP name formatter in the worker-slot padding,
the M3b donor name chain appended at the image end (covered by extending
the boot copier's fifth-blob count), the M3b drawer patches (value revert,
name text, bank-letter skip) in the copied widget blob, and the USB tag.
No other byte changes; the DSP section is unchanged.

M3b (2026-10-09): the DT2-donor name chain (src/m3b_chain.bin, 272 B at RAM
0x47A53FA8; receipt src/m3b_receipt.json) is appended at the image end and
covered by extending the boot copier count 0x7EA -> 0x82E longwords; the
SYN-page SAMP control (the relocated 288-byte donor drawer at 0x47A53AE2)
gets the donor value source back (moveq #1,d1 -> move.l 36(sp),d1), its
slot-code text region replaced with the bridge call + name draw, and its
bank-letter call skipped. Twisting encoder D then renders the DT2-donor
names (halved transport: raw 0/1 SNARE, 2/3 BASS, 4/5 HI HAT, then OFF).
"""
from pathlib import Path
import hashlib, json, struct, sys

sys.dont_write_bytecode = True
sys.path.insert(0, '@WORKSPACE@/firmware/ghidra/oneshot-proof/v7-source/src')
from dnfw.firmware.load import load

ROOT = Path('@WORKSPACE@')
J = ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3'
OUT = J/'runtime-candidate'
SHA = lambda b: hashlib.sha256(b).hexdigest()

N_SYX = ROOT/'firmware/Digitone_II_OS1.11_oneshot_native_bounds_v1_EXPERIMENTAL.syx'
N_MAIN = '99fd5e67aa0fdd8449d4debbd43877b6db00ead5af126ef5836634a61771c476'
BANK_OFF, BANK_BYTES = 0x323EC0, 47104
WORKER_OFF = 0x3300C0
SNARE = (ROOT/'firmware/ghidra/storage-proof/sample-file-v1/assets/sample-bank.bin').read_bytes()
BANK3 = (ROOT/'firmware/ghidra/storage-proof/sample-bank-multi-v2/assets/sample-bank.bin').read_bytes()
W1 = (ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v1/runtime-candidate/worker.bin').read_bytes()
W2 = (ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/runtime-candidate/worker.bin').read_bytes()
OLD_TAG, NEW_TAG = b'os1bounds-v1\0\0', b'os1fs-live-v2\0'
COPIER_OFF = 0x322510
SAMP_FMT = (ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3/src/samp_fmt.bin').read_bytes()
SAMP_FMT_OFF = 0x330A28          # file offset; RAM 0x47A52968 (worker-slot padding)
SAMP_FMT_VA = 0x47A52968
SAMP_TABLE = 0x401F80B8          # SAMP formatter table entry (pointer word)
WORKER_COPY_OLD = bytes.fromhex('223c0000025945f9403304c0')
WORKER_COPY_NEW = bytes.fromhex('223c0000025a45f9403304c0')
# M3b: donor name chain + drawer patches (see src/m3b_receipt.json)
M3B_DIR = ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3/src'
M3B_CHAIN = (M3B_DIR/'m3b_chain.bin').read_bytes()
M3B_RECEIPT = json.loads((M3B_DIR/'m3b_receipt.json').read_text())
assert M3B_RECEIPT['ok'] is True and M3B_RECEIPT['schema'] == 'dn2-m3b-donor-relocation-3'
M3B_APPEND_AT = 0x332068          # image end == current blob end (file offset)
COPIER_COUNT_OLD = bytes.fromhex('223c000007ea45f9403304c0')
COPIER_COUNT_NEW = struct.pack('>H', int(M3B_RECEIPT['copier_count'], 16)) + bytes.fromhex('45f9403304c0')
BLOB_BASE_RAM, BLOB_BASE_FILE = 0x47A52000, 0x3300C0
M3B_REVERT_OFF = 0x331BAE        # drawer+12: moveq #1,d1 / nop -> donor value load
M3B_TEXT_OFF = 0x331BFC          # drawer+0x5A: slot-code text region -> bridge + name draw
M3B_SKIP_OFF = 0x331C66          # drawer+0xC4: bank-letter call -> bra.s to the epilogue args
M3B_REVERT = (M3B_DIR/'m3b_revert.bin').read_bytes()
M3B_TEXT = (M3B_DIR/'m3b_drawer_text.bin').read_bytes()
M3B_SKIP = (M3B_DIR/'m3b_skip.bin').read_bytes()


def main():
    OUT.mkdir(exist_ok=True)
    raw = bytearray(load(N_SYX.read_bytes()).container.find(3).unpack())
    assert SHA(bytes(raw)) == N_MAIN, 'native-bounds MAIN changed'
    edits = []
    def patch(off, new, old, why):
        assert raw[off:off+len(new)] == old, (hex(off), why)
        raw[off:off+len(new)] = new
        edits.append({'file_offset': hex(off), 'old': old.hex(), 'new': new.hex(), 'why': why})
    # 1. bank swap at the identical offset
    patch(BANK_OFF, BANK3, SNARE, 'three-slot OSB1 bank replaces the snare bank')
    # 2. v2 worker in-place (2404 -> 2408 bytes; the slot's trailing padding stays zero)
    assert raw[WORKER_OFF:WORKER_OFF+len(W1)] == W1, 'v1 worker not at expected offset'
    assert not any(raw[WORKER_OFF+len(W1):WORKER_OFF+2408+64]), 'worker slot padding is not zero'
    patch(WORKER_OFF, W2, W1 + bytes(4), 'v2 worker (new pathname) in place; +4 bytes of former padding')
    # 3. No copier patch is needed: the native-bounds copier copies one contiguous
    # 8,104-byte blob (worker + widget + tail) from this file offset with count
    # 0x7EA longwords; the in-place worker swap keeps every subsequent byte at
    # the same file offset, so the single copy stays exact.
    assert bytes(raw[COPIER_OFF:COPIER_OFF+512]).count(bytes.fromhex('223c000007ea45f9403304c0')) == 1, \
        'worker blob copy loop differs'
    # 4. M3a SAMP formatter (DT2-donor shape): repoint the SAMP parameter's
    #    formatter table entry to a new function in the worker-slot padding that
    #    resolves the slot NAME from the live bank directory (0x47A3A000) and a
    #    baked name table, with the donor's OFF fallback.
    assert len(SAMP_FMT) <= 0x330AC0 - SAMP_FMT_OFF, 'formatter does not fit the padding'
    assert not any(raw[SAMP_FMT_OFF:SAMP_FMT_OFF+len(SAMP_FMT)]), 'padding not free'
    raw[SAMP_FMT_OFF:SAMP_FMT_OFF+len(SAMP_FMT)] = SAMP_FMT
    edits.append({'file_offset': hex(SAMP_FMT_OFF), 'old': bytes(len(SAMP_FMT)).hex(),
                  'new': SAMP_FMT.hex(), 'why': 'M3a SAMP name formatter (DT2 donor shape) in worker-slot padding'})
    patch(SAMP_TABLE - 0x40000400, struct.pack('>I', SAMP_FMT_VA), struct.pack('>I', 0x47A53C8C),
          'SAMP formatter table entry -> donor-shaped bank-name formatter')
    # 5. M3b drawer patches in the copied widget blob (RAM 0x47A52000):
    #    the SYN-page SAMP control is the relocated 288-byte donor drawer at
    #    0x47A53AE2 (file = BLOB_BASE_FILE + 0x1AE2).
    #    a) revert the GUI v1 "display slot 1" adaptation at drawer+12 so the
    #       drawer's real value argument reaches the name resolution
    #       (donor: move.l 36(sp),d1).
    assert M3B_REVERT_OFF == BLOB_BASE_FILE + (0x47A53AEE - BLOB_BASE_RAM), 'revert offset mapping'
    patch(M3B_REVERT_OFF, M3B_REVERT, bytes.fromhex('72014e71'),
          'M3b: SAMP control value source reverted to the donor load (real raw value)')
    #    b) replace the donor slot-code text region (drawer+0x5A..+0xA8, the
    #       "OFF"/"%d" branch pair) with the bridge call + native name draw.
    assert M3B_TEXT_OFF == BLOB_BASE_FILE + (0x47A53B3C - BLOB_BASE_RAM), 'text offset mapping'
    assert len(M3B_TEXT) == 78 and M3B_RECEIPT['drawer_text_va'] == hex(0x47A53B3C)
    donor_text_old = bytes.fromhex(
        '6626'                                       # bnes (slot != 0 -> the "%d" block)
        '487940210858'                               # pea OFF string
        '4879402170ba'                               # pea "XXX" style
        '42a74878' + '0001'                          # clr.l; pea 1
        '2f03' '2f08'                                # push y; push x (a2+12)
        '4879402941d0'                               # pea font ''
        '2f02' '4e93'                                # push canvas; jsr (a3)
        '4fef0020'                                   # pop 8 args
        '6026'                                       # bra (skip the "%d" block)
        '2f01'                                       # push slot
        '48794021222c'                               # pea "%d"
        '4879402170ba' '42a74878' + '0001' '2f032f08' '4879402941d0' '2f02' '4e93' '4fef0024')
    patch(M3B_TEXT_OFF, M3B_TEXT, donor_text_old,
          'M3b: slot-code text region -> bridge (donor name helper) + native name draw')
    #    c) skip the bank-letter call (drawer+0xC4): the DT2 bank letter has no
    #       meaning in the flat DN2 bank; branch straight to the epilogue args.
    assert M3B_SKIP_OFF == BLOB_BASE_FILE + (0x47A53BA6 - BLOB_BASE_RAM), 'skip offset mapping'
    patch(M3B_SKIP_OFF, M3B_SKIP, bytes.fromhex('2006ee807207'),
          'M3b rev3: reserve skipped bank-letter arguments (36 bytes), then branch to donor epilogue')
    # 6. M3b donor name chain appended at the image end; the boot copier's
    #    fifth-blob count is extended so the appended chain reaches RAM
    #    (0x47A53FA8+, the audit-verified unclaimed gap).
    assert len(raw) == M3B_APPEND_AT, (hex(len(raw)), 'image end moved')
    at = bytes(raw).find(COPIER_COUNT_OLD)
    assert bytes(raw).count(COPIER_COUNT_OLD) == 1, 'boot copier fifth-blob loop pattern not unique'
    assert COPIER_COUNT_OLD[4:6] == bytes.fromhex('07ea') and COPIER_COUNT_NEW[:2] == struct.pack('>H', int(M3B_RECEIPT['copier_count'], 16))
    patch(at + 4, COPIER_COUNT_NEW[:2], COPIER_COUNT_OLD[4:6],
          'M3b: boot copier fifth-blob count 0x7EA -> %s longwords (covers the appended chain)' % M3B_RECEIPT['copier_count'])
    raw[M3B_APPEND_AT:M3B_APPEND_AT+len(M3B_CHAIN)] = M3B_CHAIN
    edits.append({'file_offset': hex(M3B_APPEND_AT), 'old': '', 'new': M3B_CHAIN.hex(),
                  'why': 'M3b: DT2 donor name chain + bridge + scratch appended (see src/m3b_receipt.json)'})
    # 7. USB tag swap (same length, same cave slot)
    count = bytes(raw).count(OLD_TAG)
    assert count == 1, f'expected one tag, found {count}'
    at = bytes(raw).find(OLD_TAG)
    patch(at, NEW_TAG, OLD_TAG, 'identity: combined image reports the storage v2 protocol tag')
    (OUT/'main-os.bin').write_bytes(raw)
    (OUT/'worker.bin').write_bytes(W2)
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (OUT/name).write_bytes((ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/runtime-candidate'/name).read_bytes())
    receipt = dict(ok=True, schema='dn2-storage-merge-v3-delta-2', main_sha256=SHA(bytes(raw)),
                   base_main_sha256=N_MAIN, base_image=str(N_SYX), bytes=len(raw),
                   copies=[{'source': '0x4030b980', 'destination': '0x46800000', 'bytes': 94096},
                           {'source': '0x40322910', 'destination': '0x47a36000', 'bytes': 6576},
                           {'source': '0x403242c0', 'destination': '0x47a3a000', 'bytes': 47104},
                           {'source': '0x4032fac0', 'destination': '0x47a38000', 'bytes': 2560},
                           {'source': '0x403304c0', 'destination': '0x47a52000', 'bytes': 8104 + len(M3B_CHAIN)}],
                   m3b=dict(receipt=M3B_RECEIPT, chain_sha256=SHA(M3B_CHAIN),
                            drawer_control_va='0x47a53ae2', drawer_value_source='0x47a53aee',
                            drawer_text_va='0x47a53b3c', drawer_skip_va='0x47a53ba6',
                            transport='halved: display name = names[raw >> 1], matching the DSP slot'),
                   sample_sha256=SHA(BANK3), sample_full_le32_sum=hex(sum(struct.unpack('<11776I', BANK3)) & 0xffffffff),
                   worker_sha256=SHA(W2), worker_bytes=len(W2), worker_offset_hex=hex(WORKER_OFF),
                   bank_offset_hex=hex(BANK_OFF), tag='os1fs-live-v2', path='/sample_bank_3slot_20261008_v1.osb',
                   dsp_section='unchanged native-bounds DSP (9d5bc113...; contains all 108 bank-loader-v1 blocks)',
                   edits=edits, patch_count=len(edits),
                   scope='Offline delta build only; no device access.')
    (OUT/'build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({k: receipt[k] for k in ('ok', 'main_sha256', 'bytes', 'patch_count', 'sample_full_le32_sum')}, indent=2))


if __name__ == '__main__':
    main()
