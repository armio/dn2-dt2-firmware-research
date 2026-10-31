#!/usr/bin/env python3
"""Integrate the donor controls and parameter accessors into an offline MAIN.

No Machine is exposed and no SysEx is emitted. New companion IDs temporarily
reuse ONESHOT's corresponding control widgets; the native SourcePageView
composition remains a separate requirement before behavioral parity.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import build_dt2_sampler_controls as controls

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.patch import paramtable as P
BASE=0x40000400
SHA=lambda b:hashlib.sha256(b).hexdigest()
BIN=ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v2/toolchain/build'
BASELINE=ROOT/'output/dn2-research/oneshot-drive-v3-m3b-rev3-stackfix-20261009/main-os.bin'
BASELINE_SHA='205673af2a58674bb239195d4d40a5084d22d626aab59ca11547a31a0d7b0c64'


def run(args):
    p=subprocess.run(list(map(str,args)),capture_output=True,text=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return p.stdout


def build(out):
    out.mkdir(parents=True,exist_ok=False)
    original=BASELINE.read_bytes()
    assert SHA(original)==BASELINE_SHA
    donor=(ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin').read_bytes()
    inv=json.loads((ROOT/'output/dn2-research/oneshot-native-machine-inventory-20261008/inventory.json').read_text())
    # Preserve the complete fallback record as well as all 320 records.
    # paramtable.TABLE is eight bytes BEFORE entry 1's page-id word.
    start=(len(original)+3)&~3
    record0=P.TABLE-P.RECORD+8
    old_records=original[record0-BASE:record0-BASE+321*60]
    assert len(old_records)==321*60
    new_table=BASE+start+52
    new_records=BASE+start+len(old_records)
    blob,receipt=controls.compile_controls(donor,original,inv,new_records,321)
    image=bytearray(original+bytes(start-len(original))+old_records+blob)
    patches=P.relocate(image,BASE,table_va=new_table,added=receipt['record_count'])
    aliases=[]
    for m in receipt['machines']:
        for r in m['records']:
            # Hidden SLOT/BANK use the generic integer row only as an accessor
            # placeholder. Their browser behavior requires the native view.
            aliases.append({25:1,26:2,27:3,28:4,29:3,30:3,31:5,32:11,33:12,34:13}[r['slot']])
    assert len(aliases)==receipt['record_count']
    hook_va=BASE+len(image)
    source=f'''.text
.global sampler_companion
sampler_companion:
 move.l 4(%sp),%d0
 cmpi.l #321,%d0
 bcs.s stock
 cmpi.l #{321+len(aliases)},%d0
 bcc.s stock
 subi.l #321,%d0
 lea aliases,%a0
 move.l (%a0,%d0.l*4),%d0
 move.l %d0,%d1
 lsl.l #6,%d1
 lsl.l #2,%d0
 add.l %d1,%d0
 addi.l #0x4243325c,%d0
 rts
stock:
 move.l 4(%sp),%d0
 cmpi.l #321,%d0
 jmp 0x400c2422
.balign 4
aliases:
 .long {','.join(map(str,aliases))}
'''
    (out/'companion.S').write_text(source)
    run([BIN/'gas/as-new','-mcpu=5475',out/'companion.S','-o',out/'companion.o'])
    run([BIN/'ld/ld-new',f'-Ttext={hook_va:#x}','-e','sampler_companion',out/'companion.o','-o',out/'companion.elf'])
    run([BIN/'binutils/objcopy','-O','binary','-j','.text',out/'companion.elf',out/'companion.bin'])
    (out/'companion.asm').write_text(run([BIN/'binutils/objdump','-d',out/'companion.elf']))
    old=bytes.fromhex('202f00040c8000000141')
    off=0x400c2418-BASE
    assert image[off:off+10]==old
    image[off:off+10]=b'\x4e\xf9'+struct.pack('>I',hook_va)+b'\x4e\x71'*2
    image.extend((out/'companion.bin').read_bytes())
    # The original table remains intact. Every relocated old record, including
    # fallback entry 0 and the last record's formatter/suffix, is byte-identical.
    assert image[start:start+len(old_records)]==old_records
    assert image[P.TABLE-BASE:P.TABLE-BASE+320*60+8]==original[P.TABLE-BASE:P.TABLE-BASE+320*60+8]
    # Do not extend the stock per-machine slot-map initializer or overwrite
    # the original runtime companion table. New Machine maps will be explicit.
    assert image[0x400dc7f0-BASE:0x400dc7f6-BASE]==original[0x400dc7f0-BASE:0x400dc7f6-BASE]
    (out/'main-os.bin').write_bytes(image)
    (out/'controls.bin').write_bytes(blob)
    (out/'controls.json').write_text(json.dumps(receipt,indent=2)+'\n')
    report={'baseline_sha256':BASELINE_SHA,'main_sha256':SHA(image),'bytes':len(image),
            'new_table_va':hex(new_table),'record0_va':hex(BASE+start),
            'new_record0_va':hex(new_records),'first_new_entry':321,'last_new_entry':320+len(aliases),
            'companion_hook_va':hex(hook_va),'companion_aliases':aliases,
            'patches':[vars(p) for p in patches], 'stock_and_oneshot_records_exact':True,
            'machine_menu_changed':False,'dsp_changed':False,'flash_ready':False,
            'limitations':['No new Machine registered or DSP dispatched yet',
             'Companion widgets temporarily match ONESHOT slot positions; native Machine views still required',
             'New table uses appended MAIN storage; full startup integration not yet tested']}
    (out/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('main_sha256','bytes','new_table_va','flash_ready')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
