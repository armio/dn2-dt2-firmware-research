#!/usr/bin/env python3
"""Bind the ManualSliceEditor selector's skipped jump-table arm to DN2 config."""
from pathlib import Path
import argparse, json, struct
import build_dt2_directory_model as L
B = L.B
SHA = 'e47a8e635af03195f0a0e4a7440f5920afd1b47a0d0639c07067fd62bd47ff62'
OLD, NEW, OPERAND = 0x44d2e61c, 0x44507e08, 0x4001b620
TABLE = 0x4001b60e
ARMS = (0x4001b61e, 0x4001b67e, 0x4001b71a, 0x4001b792,
        0x4001b966, 0x4001baae, 0x4001bb52)


def native_evidence():
    donor, native = B.M.S.DONOR.read_bytes(), B.M.RECIPIENT.read_bytes()
    # The same startup invocation installs the exact byte-identical generator.
    assert donor[0x401d0cc2-B.BASE:0x401d0ce0-B.BASE] == bytes.fromhex(
        '203c401113542f400030203c401114fc2f40002c2f02487944d2e61c4e93')
    assert native[0x401b9b58-B.BASE:0x401b9b76-B.BASE] == bytes.fromhex(
        '203c40112cc82f400030203c40112e702f40002c2f02487944507e084e93')
    assert donor[0x40111354-B.BASE:0x40111380-B.BASE] == native[0x40112cc8-B.BASE:0x40112cf4-B.BASE]
    assert donor[OPERAND-2-B.BASE:OPERAND+4-B.BASE] == b'\x48\x79'+B.BE(OLD)
    offsets = struct.unpack_from('>8H', donor, TABLE-B.BASE)
    assert sorted(set(TABLE+x for x in offsets)) == list(ARMS)
    assert native[0x40113456-B.BASE:0x4011345a-B.BASE] == bytes.fromhex('4c472802')
    return dict(donor_startup='0x401d0cc2', native_startup='0x401b9b58',
        donor_generator='0x40111354', native_generator='0x40112cc8',
        generator_byte_identical=True, generator_bytes=44,
        normal_divisor_offset=8, normal_divisor=6,
        fault_instruction='0x40113456: DIVS.L D7,D2',
        jump_table=hex(TABLE), distinct_arms=[hex(x) for x in ARMS])


def build(folder, out):
    raw = bytearray((folder/'main-os.bin').read_bytes())
    assert B.T.SHA(raw) == SHA
    doc = json.loads((folder/'build-receipt.json').read_text())
    assert doc['main_sha256'] == SHA
    evidence = native_evidence()
    copy = doc['runtime_copy']; base, src = int(copy['destination'],16), int(copy['source'],16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    span = next(s for s in doc['manual_slice_editor']['spans'] if s['name']=='manual_slice_editor')
    delta = int(span['runtime'],16)-int(span['donor'],16)
    at = OPERAND+delta; offset = at-base
    assert payload[offset-2:offset+4] == b'\x48\x79'+B.BE(OLD)
    payload[offset:offset+4] = B.BE(NEW)
    raw[src-B.BASE:src-B.BASE+len(payload)] = payload
    edit = dict(donor=hex(OPERAND), runtime=hex(at), target=hex(OLD), binding=hex(NEW),
                kind='explicit jump-table arm absolute operand')
    doc['manual_slice_editor']['edits'].append(edit)
    doc['slice_encoder_fix'] = dict(base=str((folder/'main-os.bin').resolve()),
        base_sha256=SHA, edits=[edit], native_evidence=evidence,
        cause='Linear disassembly consumed the first encoder switch-arm PEA as jump-table data; donor encoder config was left unbound.',
        limits=['One address binding only; hardware slice editing remains unverified.'])
    doc.update(main_sha256=B.T.SHA(raw), runtime_sha256=B.T.SHA(payload), flash_ready=False)
    out.mkdir(parents=True,exist_ok=False)
    (out/'main-os.bin').write_bytes(raw); (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], edits=[edit]),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('folder',type=Path)
    p.add_argument('--out',type=Path,required=True); a=p.parse_args(); build(a.folder,a.out)
