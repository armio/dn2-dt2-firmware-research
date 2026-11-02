#!/usr/bin/env python3
"""Offline native R003–R008 outer depack, tail restore and early startup check.

Executes actual OS 1.11 instructions. No hardware, flash writes, MMIO fixtures,
instruction substitutions or production changes. Requires ColdFire Unicorn.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_MEM_WRITE
from unicorn import m68k_const as M

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.firmware.load import load

BASE, STOP, SP = 0x40000400, 0x4901f000, 0x49010000
STOCK_SHA = '2af43e65e3d8390b41c9f66222620f8cce027d73ed87db00c80b440f628472e0'
PARENT_SHA = 'c76eee3632de5fa63bf1bb367d9a2973807dfba992091848a9e8b67ad8988199'
REGS = [getattr(M, f'UC_M68K_REG_{r}{i}') for r,n in [('D',8),('A',7)] for i in range(n)]
BE = lambda n: struct.pack('>I', n)
SHA = lambda b: hashlib.sha256(b).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def check(candidate, folder, build_id='R003'):
    need(build_id in ('R003', 'R004', 'R005', 'R006', 'R007', 'R008'), 'unsupported build identifier')
    raw = candidate.read_bytes()
    stock_raw = (ROOT/'firmware/Digitone_II_OS1.11.syx').read_bytes()
    need(SHA(stock_raw)==STOCK_SHA, 'unsupported stock image')
    stock, fw = load(stock_raw), load(raw)
    staged = (folder/'main-os.bin').read_bytes()
    expanded = (folder/'expanded/main-os.bin').read_bytes()
    runtime = (folder/'runtime.bin').read_bytes()
    doc = json.loads((folder/'build-receipt.json').read_text())
    need(doc['build'] == build_id, 'build identifier mismatch')
    cfg = doc['boot_tail']
    parent = (ROOT/'output/dn2-research/recorder-reopen-r002-20261031/main/main-os.bin').read_bytes()
    need(SHA(parent)==PARENT_SHA==cfg['parent_main_sha256'], 'wrong R002 baseline')
    need(not any(parent[0x4028da70-BASE:0x4028da70-BASE+136]), 'wrapper cave not unused in R002')
    native_slice=slice(0x40136540-BASE,0x401366a4-BASE)
    need(staged[native_slice]==parent[native_slice]==stock.container.find(3).unpack()[native_slice],
         'native MAIN depacker differs from stock/R002')
    need(fw.container.find(3).unpack()==staged, 'candidate MAIN differs from intended staged image')
    need(SHA(staged)==doc['main_sha256'], 'staged hash mismatch')
    need(SHA(expanded)==cfg['expanded_main_sha256'], 'expanded hash mismatch')
    need(SHA(runtime)==doc['runtime_sha256'], 'runtime hash mismatch')
    for sid in (2,4):
        need(fw.container.find(sid).stored==stock.container.find(sid).stored, f'protected section{sid} changed')
    get = lambda k: int(cfg[k],16)
    cut, scratch, entry, original = map(get, ['cutoff','scratch','entry','original_entry'])
    need((cut,scratch,entry,original,get('depacker')) ==
         (0x402faf54,0x47a58000,0x4028da70,0x400004e8,0x40136540), 'unsupported entry layout')
    need(int.from_bytes(staged[:4],'big')==entry, 'entry pointer mismatch')
    need(cfg['stored_bytes']<=len(runtime)==cfg['scratch_bytes'], 'scratch exceeds existing runtime ownership')
    # Legacy projection is exact R002; R006 separately proves its pinned R005 observer scope.
    if build_id == 'R006':
        from build_dn2_recovery_tail import expand_verified
        from build_dn2_recovery_r006 import verify_projection
        need(expand_verified(staged,doc) == expanded, 'R006 staged projection differs')
        expected = bytearray(verify_projection(expanded,doc))
    else:
        expected = bytearray(parent)
        marker = int(doc['runtime_copy']['source'],16)-BASE+0x47aa5a0c-scratch
        need(expected[marker:marker+4]==b'R002', 'parent marker mismatch')
        expected[marker:marker+4]=build_id.encode('ascii')
        expected[:4]=BE(entry)
    expected[entry-BASE:entry-BASE+cfg['wrapper_bytes']]=staged[entry-BASE:entry-BASE+cfg['wrapper_bytes']]
    need(bytes(expected)==expanded, 'expanded projection contains unrelated changes')
    need(staged[:cut-BASE]==expanded[:cut-BASE], 'prefix unexpectedly differs')
    need(SHA(staged[cut-BASE:])==cfg['stored_sha256'], 'inner stored hash mismatch')
    need(SHA(expanded[cut-BASE:])==cfg['tail_sha256'], 'inner output hash mismatch')
    results=[]
    for stage in (0x40200000,0x40400000):
        u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN)
        u.ctl_set_cpu_model(M.UC_CPU_M68K_CFV4E)
        for address,size in ((0x40000000,0x8000000),(0x49000000,0x20000),(0x80000000,0x20000)):
            u.mem_map(address,size)
        # Conditional path executes section4; ordinary path executes bootstrap.
        if stage==0x40200000:
            u.mem_write(0x80000400,stock.container.find(4).stored)
            depack=0x80005728
        else:
            bootstrap=stock.container.find(2).unpack()
            u.mem_write(0x80000400,bootstrap[4:])
            depack=0x80000432
        stored=fw.container.find(3).stored
        u.mem_write(stage,stored)
        u.reg_write(M.UC_M68K_REG_SR,0x2700)
        def invoke(pc, *args, end=STOP, limit=150_000_000):
            u.reg_write(M.UC_M68K_REG_A7,SP)
            u.mem_write(SP,BE(STOP)+b''.join(BE(a) for a in args))
            u.emu_start(pc,end,count=limit)
            need(u.reg_read(M.UC_M68K_REG_PC)==end, f'incomplete native run at {u.reg_read(M.UC_M68K_REG_PC):08x}')
        overlaps=[]
        def overlap_hook(uc,access,address,size,value,data):
            cursor=uc.reg_read(M.UC_M68K_REG_A0)
            if address+size>cursor and address<stage+8+int.from_bytes(stored[:4],'big'):
                overlaps.append((hex(address),hex(cursor)))
                uc.emu_stop()
        hook=u.hook_add(UC_HOOK_MEM_WRITE,overlap_hook,begin=stage+8,end=stage+len(stored)-1)
        invoke(depack,stage,BASE)
        u.hook_del(hook)
        need(not overlaps,'outer expansion overwrote unread source')
        need(u.reg_read(M.UC_M68K_REG_D0)==len(staged),'outer output length differs')
        need(bytes(u.mem_read(BASE,len(staged)))==staged,'native outer expansion differs')
        guarded=[]
        allowed=[]
        def guard(uc,access,address,size,value,data):
            if not any(lo<=address and address+size<=hi for lo,hi in allowed):
                guarded.append((hex(address),size,hex(uc.reg_read(M.UC_M68K_REG_PC))))
                uc.emu_stop()
        hook=u.hook_add(UC_HOOK_MEM_WRITE,guard)
        allowed[:]=[(SP-256,SP),(cut,BASE+len(expanded)),(scratch,scratch+cfg['stored_bytes'])]
        initial={reg:0x11220000+index*0x101 for index,reg in enumerate(REGS)}
        for reg,value in initial.items(): u.reg_write(reg,value)
        flags=0x02468135
        invoke(entry,flags,end=original)
        need(not guarded, f'wrapper write outside owned ranges: {guarded}')
        need(u.reg_read(M.UC_M68K_REG_A7)==SP,'wrapper stack changed')
        need(bytes(u.mem_read(SP,8))==BE(STOP)+BE(flags),'wrapper altered caller return/boot flags')
        need(all(u.reg_read(reg)==value for reg,value in initial.items()),'wrapper register clobber')
        need(u.reg_read(M.UC_M68K_REG_SR)&0xffe0==0x2700,'wrapper changed SR control bits')
        need(bytes(u.mem_read(BASE,len(expanded)))==expanded,'native restored MAIN differs')
        need(bytes(u.mem_read(scratch,cfg['stored_bytes']))==staged[cut-BASE:],'scratch copy differs')
        # Original entry consumes the preserved boot argument before MMIO and
        # sets its own condition codes; incoming CCR is not an entry contract.
        allowed[:]=[(0x40287520,0x40287524)]
        u.emu_start(original,0x400004f2,count=8)
        need(u.reg_read(M.UC_M68K_REG_PC)==0x400004f2,'original flag handoff incomplete')
        need(bytes(u.mem_read(0x40287520,4))==BE(flags),'original entry lost boot flags')
        row=dict(stage=hex(stage),native_outer_depacker=hex(depack),outer_exact=True,
            unread_source_preserved=True,expanded_exact=True,registers_15_preserved=True,
            stack_and_boot_flags_preserved=True,sr_control_bits_preserved=True,
            original_entry_boot_flags_consumed=True,wrapper_writes_guarded=True)
        # Same actual SRAM data initializer, called before patched BSS copier.
        allowed[:]=[(SP-256,SP),(0x80000000,0x80010000)]
        invoke(0x4000045c)
        need(not guarded,f'data_init write outside SRAM/stack: {guarded}')
        sram=bytes(u.mem_read(0x80000000,0x10000))
        expected_sram=expanded[0x402fc000-BASE:0x4030b980-BASE]+bytes(0x680)
        need(sram==expected_sram,'native SRAM initialization differs')
        # Existing copiers must run before BSS destroys their source bytes.
        copies=[*doc['copies'],doc['runtime_copy']]
        allowed[:]=[(SP-256,SP),(0x47a39000,0x47a39900),(0x47a56000,0x47a57000)]
        allowed.extend((int(c['destination'],16),int(c['destination'],16)+c['bytes']) for c in copies)
        invoke(0x400004b2,end=0x46800026)
        need(not guarded,f'existing bootstrap write outside declared copies: {guarded}')
        need(u.reg_read(M.UC_M68K_REG_A7)==SP,'existing copy chain stack imbalance')
        for c in copies:
            source,dest,n=int(c['source'],16),int(c['destination'],16),c['bytes']
            need(bytes(u.mem_read(dest,n))==expanded[source-BASE:source-BASE+n],'native copied image differs')
        u.hook_del(hook)
        # Native unchanged BSS loop: execute in relocated code, avoid per-byte
        # Python hooks over 100 MiB. Verify complete clear and code/data survivors.
        prefix=bytes(u.mem_read(BASE,0x402fc000-BASE))
        u.emu_start(0x46800026,STOP,count=50_000_000)
        need(u.reg_read(M.UC_M68K_REG_PC)==STOP,'BSS helper did not return')
        need(u.reg_read(M.UC_M68K_REG_A7)==SP+4,'BSS return stack imbalance')
        need(not any(u.mem_read(0x402fc000,0x466b74d0-0x402fc000)),'native BSS clear incomplete')
        need(bytes(u.mem_read(BASE,len(prefix)))==prefix,'BSS modified preserved MAIN prefix')
        need(bytes(u.mem_read(0x80000000,0x10000))==sram,'BSS modified SRAM data')
        for c in copies:
            source,dest,n=int(c['source'],16),int(c['destination'],16),c['bytes']
            need(bytes(u.mem_read(dest,n))==expanded[source-BASE:source-BASE+n],'BSS modified copied image')
        row.update(native_sram_initializer_exact=True,existing_copies_guarded=True,
            copied_regions=len(copies),runtime_exact=True,bss_returned=True,bss_clear_exact=True)
        results.append(row)
    return dict(ok=True,candidate_sha256=SHA(raw),main_sha256=SHA(staged),
        expanded_main_sha256=SHA(expanded),runtime_sha256=SHA(runtime),cases=results,
        limitations=['Native depackers and early startup helpers only; no physical NOR, cache-coherency or hardware boot validation.',
            'BSS helper runs without per-store hooks; full clear, copied regions and preserved prefix/SRAM checked afterward.',
            'Original MAIN entry hardware setup is not executed; startup helpers called directly in original order.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--main',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--build',choices=('R003','R004','R005','R006','R007','R008'),default='R003')
    a=p.parse_args()
    inputs=[a.candidate,*a.main.rglob('*'),Path(__file__),
        ROOT/'firmware/Digitone_II_OS1.11.syx',
        ROOT/'output/dn2-research/recorder-reopen-r002-20261031/main/main-os.bin']
    need(not any(f.is_file() and (a.out.resolve()==f.resolve() or
         (a.out.exists() and a.out.samefile(f))) for f in inputs),'output aliases an input')
    result=check(a.candidate,a.main,a.build)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
