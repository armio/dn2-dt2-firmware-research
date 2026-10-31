#!/usr/bin/env python3
"""Build an isolated fail-stop media boundary for the storage-only graft.

No device I/O, container generation, filesystem formatting or mounting.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.patch.coldfire import Asm
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_040

INPUT = ROOT/'firmware/ghidra/storage-proof/combined-vfs-lru-candidate'
SOURCE = INPUT/'candidate/main-os.bin'
OUT = ROOT/'firmware/ghidra/storage-proof/io-guard-candidate'
SOURCE_SHA = 'c4f4dcc9a03dca1f0f28185fa7c7b7eca384e941fe6b72043cd690abf344ea57'
BASE, GRAFT_BASE, APPEND = 0x40000400, 0x46800000, 0x30B580
CAVE, CAPACITY, READ_ENTRY, WRITE_ENTRY = 0x402DFBD8, 452, 0x402DFBD8, 0x402DFC28
OLD_CHECKER, LATCH = 0x468004A0, 0x47A19C90
READ, WRITE, TRANSMIT = 0x4012C59A, 0x4012C780, 0x400053D4
WRITE_START, WRITE_END, MAX_COUNT = 0x005D8000, 0x02DF0180, 0x14000
MAGIC = b'DN2IO001'
MANUAL = 'https://www.nxp.com/docs/en/reference-manual/CFPRM.pdf'

def sha(b): return hashlib.sha256(b).hexdigest()
def be(n): return (n & 0xFFFFFFFF).to_bytes(4, 'big')
def offset(va):
    return APPEND+va-GRAFT_BASE if va >= GRAFT_BASE else va-BASE

def build_code():
    a = Asm()
    def prologue(op):
        a.hex('4fefffe848d7047c')  # 24B; D2-D6/A2 at fixed stack EA.
        for disp, dn in ((28,2),(32,3),(36,4)): a.move_l_sp(disp,dn)
        a.hex(f'7a{op:02x}')
    def call_and_return(target):
        a.hex('2f042f032f02'); a.jsr(target); a.hex('4fef000c')
        a.tst_d(0); a.bne('failure')
        a.hex('4cd7047c4fef00184e75')
    a.label('read'); prologue(1); call_and_return(READ)
    assert len(a.b) <= WRITE_ENTRY-CAVE
    while len(a.b)<WRITE_ENTRY-CAVE: a.nop()
    a.label('write'); prologue(2)
    a.tst_d(3); a.beq('bounds')
    a.cmpi(MAX_COUNT,3); a.bhi('bounds')
    a.move_l_dd(3,6); a.andi(511,6); a.bne('bounds')
    a.cmpi(WRITE_START,2); a.bcs('bounds')
    a.move_l_dd(3,6)
    a.hex('e08ee28e')  # LSR.L #8,D6; LSR.L #1,D6: bytes -> sectors.
    a.add_dd(2,6); a.bcs('bounds')
    a.cmpi(WRITE_END,6); a.bhi('bounds')
    call_and_return(WRITE)
    a.label('bounds'); a.hex('70ff7a03'); a.bra('failure')
    a.label('failure')
    a.hex(f'45f9{LATCH:08x}')
    a.hex('248525420004254300082540000c')  # op/LBA/count/nativeD0.
    # Transport ABI is (count, pointer); two immediate copies form one24B frame.
    magic_va = CAVE + len(a.b) + 40
    a.hex(f'41f9{magic_va:08x}2f0848780008'); a.jsr(TRANSMIT); a.hex('4fef0008')
    a.hex('2f0a48780010'); a.jsr(TRANSMIT); a.hex('4fef0008')
    a.label('trap'); a.hex('4afc')
    a.label('magic'); a.bytes(MAGIC)
    code=a.link()
    # Derive literal pointer independently; catches reporter layout changes.
    assert magic_va == CAVE+a._lab['magic'], (hex(magic_va),a._lab)
    assert len(code) <= CAPACITY
    return code, {k:CAVE+v for k,v in a._lab.items()}

def native_isa_rows(code, labels):
    # Reuse the frozen v2 MOVE addressing-combination gate without editing it.
    p=ROOT/'scripts/build_dn2_drive_status_v2_patch.py'
    spec=importlib.util.spec_from_file_location('frozen_status_isa',p)
    b=importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
    cs=Cs(CS_ARCH_M68K,CS_MODE_BIG_ENDIAN|CS_MODE_M68K_040)
    instructions=list(cs.disasm(code[:labels['magic']-CAVE],CAVE))
    assert sum(i.size for i in instructions)==labels['magic']-CAVE
    rows=[]
    for i in instructions:
        w=int.from_bytes(i.bytes[:2],'big')
        if w==0x4E71: rule='NOP;CFPRM Rev3 4-63'
        elif w==0x4AFC: rule='ILLEGAL;CFPRM Rev3 4-39'
        elif w & 0xF1F8 == 0xD080: rule='ADD.L Dn,Dn;CFPRM Rev3 4-2..4-3'
        elif w & 0xF1F8 == 0xE088: rule='LSR.L immediate,Dn;CFPRM Rev3 4-44..4-45'
        else:
            row=b.validate_native_isa([i])[0]; rule=row['manual_rule']
        assert i.size in (2,4,6)
        rows.append({'address':f'0x{i.address:08X}','bytes':bytes(i.bytes).hex(),
                     'instruction':f'{i.mnemonic} {i.op_str}','manual_rule':rule})
    return rows

def make_patch(source):
    assert sha(source)==SOURCE_SHA
    result=bytearray(source); edits=[]
    def patch(va,old,new,purpose):
        off=offset(va); assert source[off:off+len(old)]==old,(hex(va),old.hex())
        assert len(old)==len(new)
        result[off:off+len(new)]=new
        edits.append({'address':f'0x{va:08X}','file_offset':off,'old_hex':old.hex(),
                      'new_hex':new.hex(),'purpose':purpose})
    code,labels=build_code(); isa=native_isa_rows(code,labels)
    assert source[offset(CAVE):offset(CAVE)+CAPACITY]==bytes(CAPACITY)
    patch(CAVE,bytes(len(code)),code,'READ/WRITE guards and first-failure receipt')
    old_checker=bytes.fromhex('23ca47a19c90245f4eb94012c7804a8067042f004afc2f0a247947a19c904e75')
    patch(OLD_CHECKER,old_checker,bytes.fromhex('4ef9')+be(WRITE_ENTRY)+b'\x4e\x71'*13,
          'Replace old checker entry; every logged/direct callback uses new guard')
    closure=(INPUT/'inputs/dt2_closure.log').read_text()
    fnmap={int(a,16):int(b,16) for a,b in re.findall(r'^\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)',(INPUT/'candidate/fn_new_map.txt').read_text(),re.M)}
    ranges={int(a,16):int(b,16) for a,b in re.findall(r'\bFN ([0-9a-f]+) ([0-9a-f]+)',closure)}
    refs={}
    for a,t,ins in re.findall(r'\bREF ([0-9a-f]+) (4012(?:deda|e0c0|ddf2)) [^;\n]+; ([^\n]+)',closure):
        a,t=int(a,16),int(t,16)
        owner=next((f for f in fnmap if f<=a<ranges[f]),None)
        if owner is None: continue
        va=fnmap[owner]+a-owner
        refs[a]={'source_site':f'0x{a:08X}','owner':f'0x{owner:08X}',
                 'graft_site':f'0x{va:08X}','native_target':f'0x{t:08X}','instruction':ins}
    for a,row in sorted(refs.items()):
        va=int(row['graft_site'],16);target=int(row['native_target'],16)
        off=offset(va);old=source[off:off+6];w=int.from_bytes(old[:2],'big')
        row['before_hex']=old.hex()
        if target==0x4012DDF2:
            assert old==bytes.fromhex('70004e714e71');row['policy']='ERASE already suppressed'
        elif w in (0x4E92,0x4E93,0x4E94):
            row['policy']='computed call through patched LEA target'
        elif target==0x4012DEDA:
            assert old[2:]==be(READ)
            patch(va,old,old[:2]+be(READ_ENTRY),'Guard every closure READ operand, including LEA')
            row['policy']='READ guard'
        elif old[2:]==be(WRITE):
            assert w & 0xF1FF == 0x41F9  # LEA absolute-long An.
            patch(va,old,old[:2]+be(WRITE_ENTRY),'Guard indirect WRITE pointer missed by old checker')
            row['policy']='WRITE guard (indirect LEA)'
        else:
            assert old[:2]==b'\x4e\xb9' and int.from_bytes(old[2:],'big') in (OLD_CHECKER,0x468003D8)
            row['policy']='WRITE guard through replaced checker entry / logger callback'
    assert sum(r['policy']=='READ guard' for r in refs.values())==10
    assert sum(r['policy']=='WRITE guard (indirect LEA)' for r in refs.values())==4
    assert sum(r['policy']=='ERASE already suppressed' for r in refs.values())==3
    # Independently scan the entire graft: only injected guard code may contain
    # real READ/WRITE entry addresses, and it lives in MAIN, outside this range.
    graft=bytes(result[APPEND:])
    for target in (READ,WRITE,0x4012C4B2): assert be(target) not in graft,hex(target)
    return bytes(result),code,labels,edits,list(refs.values()),isa

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output-dir',type=Path,default=OUT)
    args=ap.parse_args();args.output_dir.mkdir(parents=True,exist_ok=True)
    source=SOURCE.read_bytes();candidate,code,labels,edits,coverage,isa=make_patch(source)
    report={'source_main_sha256':sha(source),'candidate_main_sha256':sha(candidate),
        'source_main':str(SOURCE.relative_to(ROOT)),'builder_sha256':sha(Path(__file__).read_bytes()),
        'read_entry':f'0x{READ_ENTRY:08X}','write_entry':f'0x{WRITE_ENTRY:08X}',
        'labels':{k:f'0x{v:08X}' for k,v in labels.items()},'code_bytes':len(code),
        'code_capacity':CAPACITY,'latch':f'0x{LATCH:08X}',
        'write_policy':{'start_lba_inclusive':WRITE_START,'end_lba_exclusive':WRITE_END,
                        'max_byte_count':MAX_COUNT,'alignment_bytes':512,
                        'unsigned_overflow_rejected':True},
        'failure_protocol':{'magic':MAGIC.decode(),'bytes':24,'big_endian_fields':['op','lba','byte_count','raw_D0'],
          'op_codes':{'1':'READ native failure','2':'WRITE native failure','3':'WRITE policy rejection'},
          'rejected_native_result':0xFFFFFFFF,'action_after_receipt':'ILLEGAL; never returns to caller'},
        'patches':edits,'closure_io_coverage':coverage,
        'scope':'Storage-only raw MAIN; no V7 overlay, container, device or hardware claim.'}
    (args.output_dir/'main-os.bin').write_bytes(candidate)
    (args.output_dir/'guard-code.bin').write_bytes(code)
    (args.output_dir/'patch-report.json').write_text(json.dumps(report,indent=2)+'\n')
    (args.output_dir/'isa-validation.json').write_text(json.dumps({'candidate_main_sha256':sha(candidate),
        'all_passed':True,'manual_url':MANUAL,'reviewed_instruction_count':len(isa),'instructions':isa},indent=2)+'\n')
    (args.output_dir/'guard-code.asm').write_text('\n'.join(f"{r['address']} {r['bytes']:14s} {r['instruction']}" for r in isa)+'\n')
    shutil.copy2(Path(__file__),args.output_dir/'build_dn2_drive_io_guard.py')
    print(json.dumps({'output_dir':str(args.output_dir),'candidate_main_sha256':sha(candidate),
                      'code_bytes':len(code),'read_entry':hex(READ_ENTRY),'write_entry':hex(WRITE_ENTRY)}))

if __name__=='__main__':main()
