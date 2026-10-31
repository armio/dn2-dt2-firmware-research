#!/usr/bin/env python3
"""Isolated tiny native file diagnostic. Raw MAIN only; no pack/device operations."""
from pathlib import Path
import ast, hashlib, importlib.util, json, re, struct
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_040

JOB=Path(__file__).resolve().parents[1]
IN,OUT=JOB/'inputs',JOB/'candidate'
BASE,GB,APP=0x40000400,0x46800000,0x30B580
OLD_G,ANNEX_OFF,EXT=0x16F90,0x322510,0x47A36000
EXT_LIMIT=EXT+0x2000
OPEN,ROLL1,ROLL2,FILE=0x47A1A000,0x47A25000,0x47A2D000,0x47A35000
NEW_DATA_END=FILE+0x200
STATE_BASE,STATE_END,STAGE,IO=0x46816F8C,0x47A19CA0,0x47A19CA0,0x47A19C90
MOUNTED,DISPATCH=0x46B9608C,EXT+0x1000
PRINTF,HELPER2,COMPARE=0x400054B4,0x4012C340,0x4017E8A8
HOOK,CONTINUE,LOOP=0x400CE1C2,0x400CE1C8,0x400CD4E0
READ_GUARD,WRITE_GUARD=0x402DFBD8,0x402DFC28
SHA=lambda b:hashlib.sha256(b).hexdigest()
BE=lambda n:struct.pack('>I',n&0xffffffff)

def mapping(path):
    return {int(x[0],16):int(x[1],16) for x in (l.split() for l in path.read_text().splitlines()) if x}

def encoder():
    s=importlib.util.spec_from_file_location('tiny_file_coldfire',IN/'coldfire.py')
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m.Asm

def native_validator():
    p=IN/'native-isa-validator.py';tree=ast.parse(p.read_text())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_native_isa')
    ns={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),ns)
    return ns['validate_native_isa']

def main():
    OUT.mkdir(exist_ok=True)
    prior=(IN/'composed-03-main-os.bin').read_bytes();raw=bytearray(prior)
    assert SHA(prior)=='76a2875362a21e9d4dd8c6fb7ffaf60c8e495ba942b9adbe3fe8109edb0af3ee'
    assert len(prior)==ANNEX_OFF and len(prior)-APP==OLD_G
    dt2=(IN/'dt2-main-os.bin').read_bytes();stock=(IN/'dn2-stock-main-os.bin').read_bytes()
    assert SHA(dt2)=='57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'
    fn=mapping(IN/'prior-fn-map.txt');oldfn=dict(fn)
    ram=mapping(IN/'prior-ram-map.txt');oldram=dict(ram)
    assert len(fn)==67 and len(ram)==119
    comp=json.loads((IN/'closure-comparison.json').read_text())
    selected={int(r['native'],16):r['bytes'] for r in comp['native_fs_functions_absent_current_map']}
    selected[0x4015BA22]=90
    oldsizes={int(d,16):int(e,16)-int(s,16) for d,s,e in re.findall(
        r'GRAFT FUN_([0-9a-f]{8}) @0x([0-9a-f]{8})\.\.0x([0-9a-f]{8})',(IN/'prior-graft-report.txt').read_text())}
    instructions={}
    for name in ['prior-native-closure.log','tiny-file-closure.log']:
        for a,n in re.findall(r'INST ([0-9a-f]+) ([0-9a-f]+)',(IN/name).read_text()):
            a,n=int(a,16),int(n,16)
            if a in instructions:assert instructions[a]==n
            instructions[a]=n
    inv=json.loads((IN/'native-api-inventory.json').read_text())
    for row in inv['functions']:
        for i in row['instructions']:
            at=int(i['address'],16);n=i['length']
            if at in instructions:assert instructions[at]==n
            instructions[at]=n
    shared={int(r['native'],16):int(r['dn2'],16) for r in comp['existing_verified_retargets']}
    # All new I/O routes use the already proven live fail-stop wrappers.
    shared.update({0x4012DEDA:READ_GUARD,0x4012E0C0:WRITE_GUARD,0x40189E88:0x4017E73C})
    assert dt2[0x40189E88-BASE:0x40189FF4-BASE]==stock[0x4017E73C-BASE:0x4017E73C-BASE+364]
    ram[0x46F4DED0]=OPEN
    ram[0x46F4DED4]=OPEN+4
    ram[0x40951D90]=ROLL1
    ram[0x406758C0]=ROLL2
    new_spans=[(0x46F4DED0,0xB000,OPEN),(0x40951D90,0x8000,ROLL1),(0x406758C0,0x8000,ROLL2)]
    oldspans=[(int(r['donor'],16),int(r['length'],16),int(r['mapped'][0],16))
              for r in json.loads((IN/'prior-bulk-map-audit.json').read_text())['reservations']]
    cur=EXT+0x100
    for d,n in sorted(selected.items()):
        while cur%4!=d%4:cur+=1
        fn[d]=cur;cur+=n
    native_end=cur;tramp_base=(cur+3)&~3
    trampolines={}
    def trampoline(target):
        if target not in trampolines:trampolines[target]=tramp_base+6*len(trampolines)
        return trampolines[target]
    def mapped(t):
        for d,n,a in new_spans:
            if d<=t<d+n:return a+t-d
        if t in ram:return ram[t]
        if t in shared:return shared[t]
        for d,a in fn.items():
            n=selected.get(d,oldsizes.get(d))
            if d<=t<d+n:return a+t-d
        for d,n,a in oldspans:
            if d<=t<d+n:return a+t-d
        return None
    relocation=[];native_rows=[];pieces={}
    for d,n in sorted(selected.items()):
        b=bytearray(dt2[d-BASE:d-BASE+n])
        ats=sorted(a for a in instructions if d<=a<d+n)
        assert sum(instructions[a] for a in ats)==n,(hex(d),n,sum(instructions[a] for a in ats))
        assert ats[0]==d
        for at in ats:
            ilen=instructions[at];off=at-d;src=dt2[at-BASE:at-BASE+ilen];op=int.from_bytes(src[:2],'big')
            # Full immediate/absolute operand scan: includes ADDI/ADDA-style literal addresses.
            for pos in range(2,ilen-3,2):
                v=int.from_bytes(src[pos:pos+4],'big');new=mapped(v)
                if new is not None:
                    b[off+pos:off+pos+4]=BE(new)
                    relocation.append({'native_site':hex(at),'site':hex(fn[d]+off),'operand_offset':pos,'before':hex(v),'after':hex(new),'kind':'absolute-or-immediate'})
                elif BASE<=v<0x48000000:
                    raise AssertionError(('unmapped native address operand',hex(at),hex(v),src.hex()))
            disp_size=None
            if op&0xF000==0x6000 and ilen in (2,4) and op&0xff!=0xff:
                disp_size=1 if ilen==2 else 2
                disp=int.from_bytes(src[1:2] if disp_size==1 else src[2:4],'big',signed=True)
            elif ilen==4 and op&0x3f==0x3a:
                disp_size=2;disp=int.from_bytes(src[2:4],'big',signed=True)
            if disp_size:
                target=at+2+disp
                if not d<=target<d+n:
                    dest=mapped(target);assert dest is not None,('unmapped PC operand',hex(at),hex(target))
                    delta=dest-(fn[d]+off+2)
                    if not -(1<<(8*disp_size-1))<=delta<(1<<(8*disp_size-1)):
                        # Only control transfers can use an executable JMP thunk.
                        assert op&0xF000==0x6000 or op in (0x4EBA,0x4EFA),(hex(at),hex(op),'far PC data operand')
                        assert disp_size==2,('far byte branch',hex(at))
                        dest=trampoline(dest);delta=dest-(fn[d]+off+2)
                    assert -32768<=delta<=32767
                    p=off+1 if disp_size==1 else off+2
                    b[p:p+disp_size]=delta.to_bytes(disp_size,'big',signed=True)
                    relocation.append({'native_site':hex(at),'site':hex(fn[d]+off),'before':hex(target),'after':hex(dest),'kind':'pc-relative-control'})
            native_rows.append({'donor':hex(d),'native_site':hex(at),'site':hex(fn[d]+off),'length':ilen,'source':src.hex(),'emitted':bytes(b[off:off+ilen]).hex()})
        pieces[d]=bytes(b)
    assert tramp_base+6*len(trampolines)<=DISPATCH
    Asm=encoder();a=Asm()
    def adjust(n):a.hex('4fef'+(n&0xffff).to_bytes(2,'big').hex())
    def store(address,value):a.move_l_imm(value,0).move_l_d_abs(0,address)
    def fstore(off,value):store(FILE+off,value)
    def fload(off,d=0):a.move_l_abs_d(FILE+off,d)
    def tst(d=0):a.hex(f'{0x4a80+d:04x}')
    def bsr(label):a._br('61',label)
    def clr_loop(start,size,label):
        assert size%4==0
        a.move_l_imm(size//4,1).movea_imm(start,0).label(label).hex('42985381').bne(label)
    def pea(address):a.hex('4879'+BE(address).hex())
    def native_call(stage,donor,args):
        fstore(4,stage);bsr('file_report')
        for kind,value in reversed(args):
            if kind=='ptr':pea(value)
            elif kind=='imm':a.move_l_imm(value,0).push('d0')
            elif kind=='abs':a.hex('2f39'+BE(value).hex())
            else:raise AssertionError(kind)
        a.jsr(fn[donor]);adjust(len(args)*4);a.move_l_d_abs(0,FILE+12)
    def require_zero():tst();a.bne('native_failure')
    def cmp_imm(n):a.hex('0c80'+BE(n).hex())
    a.label('entry');adjust(-48);a.hex('48d77cfc')
    names=['FSINIT','FSMOUNT','FSSTATUS','FILEWRITE','FILEREAD','FILESTATUS']
    for name in names:
        a.label('compare_'+name);pea(0);a.push('d2').hex('4e94');adjust(8);tst();a.beq(name)
    a.label('unmatched');a.hex('4cd77cfc');adjust(48);pea(0x4021ACB1);a.jmp(CONTINUE)
    a.label('FSSTATUS');bsr('fs_report');a.bra('done')
    a.label('FSINIT');a.move_l_abs_d(STAGE+4,0);tst();a.bne('FSINIT_reject')
    store(STAGE,0x100);store(STAGE+8,0);bsr('fs_report')
    clr_loop(STATE_BASE,STATE_END-STATE_BASE,'clear_old')
    clr_loop(OPEN,NEW_DATA_END-OPEN,'clear_new')
    a.jsr(fn[0x4015A43A]);store(STAGE+4,1);store(STAGE+8,0);store(STAGE,0x101);bsr('fs_report');a.bra('done')
    a.label('FSINIT_reject');store(STAGE,0x1ff);store(STAGE+8,0xfffffffe);bsr('fs_report');a.bra('done')
    a.label('FSMOUNT');a.move_l_abs_d(STAGE+4,0);tst();a.beq('FSMOUNT_reject')
    store(STAGE,0x300);store(STAGE+8,0);bsr('fs_report')
    a.move_l_imm(1,0).push('d0').jsr(fn[0x4015A450]);adjust(4);a.move_l_d_abs(0,STAGE+8)
    store(STAGE,0x301);bsr('fs_report');a.bra('done')
    a.label('FSMOUNT_reject');store(STAGE,0x3ff);store(STAGE+8,0xfffffffe);bsr('fs_report');a.bra('done')
    a.label('FILESTATUS');fstore(0,0);bsr('file_report');a.bra('done')
    a.label('FILEWRITE');a.moveq(1,7);a.bra('file_start')
    a.label('FILEREAD');a.moveq(2,7)
    a.label('file_start')
    # Preserve attempt across operations, reset everything else to fresh handles/buffers.
    fload(16,6);clr_loop(FILE,0x200,'clear_file');a.move_l_d_abs(6,FILE+16).move_l_d_abs(7,FILE)
    for off in (48,52,56,60,96,100,104,108,112):fstore(off,0xa5a5a5a5)
    a.move_l_abs_d(STAGE+4,0);cmp_imm(1);a.bne('gate_failure')
    a.move_l_abs_d(MOUNTED,0);cmp_imm(1);a.bne('gate_failure')
    a.move_l_dd(7,0);cmp_imm(1);a.bne('read_verify')
    fload(16);tst();a.bne('gate_failure');fstore(16,1)
    native_call(0x100,0x40159F50,[('ptr',0),('ptr',FILE+68),('ptr',FILE+72),('imm',0),('imm',0)])
    a.move_l_d_abs(0,FILE+64).hex('0280'+BE(0x19).hex());cmp_imm(0x19);a.bne('exists_failure')
    native_call(0x101,0x40158626,[('ptr',0),('ptr',0),('ptr',FILE+80)])
    require_zero();a.move_l_abs_d(FILE+80,0).move_l_d_abs(0,FILE+20)
    native_call(0x102,0x4015838E,[('ptr',0),('imm',16),('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+28);cmp_imm(16);a.bne('native_failure')
    a.move_l_abs_d(FILE+84,0).move_l_d_abs(0,FILE+36);cmp_imm(16);a.bne('native_failure')
    native_call(0x103,0x401585E4,[('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+44);require_zero()
    a.label('read_verify');a.movea_imm(FILE+80,0).hex('4298'*4)
    native_call(0x200,0x40158626,[('ptr',0),('ptr',0),('ptr',FILE+80)])
    require_zero();a.move_l_abs_d(FILE+80,0).move_l_d_abs(0,FILE+20)
    native_call(0x201,0x4015BA22,[('abs',FILE+80)])
    a.move_l_d_abs(0,FILE+24);cmp_imm(16);a.bne('native_failure')
    native_call(0x202,0x4015832E,[('ptr',FILE+96),('imm',16),('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+32);cmp_imm(16);a.bne('native_failure')
    a.move_l_abs_d(FILE+84,0).move_l_d_abs(0,FILE+36);cmp_imm(16);a.bne('payload_failure')
    payload=bytes.fromhex(json.loads((JOB/'protocol.json').read_text())['payload_hex'])
    for off in range(0,16,4):
        a.move_l_abs_d(FILE+96+off,0);cmp_imm(int.from_bytes(payload[off:off+4],'big'));a.bne('payload_failure')
    for off in range(0,16,4):a.move_l_abs_d(FILE+96+off,0).move_l_d_abs(0,FILE+48+off)
    native_call(0x203,0x4015832E,[('ptr',FILE+112),('imm',1),('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+40);tst();a.bne('payload_failure')
    a.move_l_abs_d(FILE+84,0).move_l_d_abs(0,FILE+36);cmp_imm(16);a.bne('payload_failure')
    a.move_l_abs_d(FILE+112,0);cmp_imm(0xa5a5a5a5);a.bne('payload_failure')
    native_call(0x204,0x401585E4,[('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+44);require_zero()
    fstore(4,0x206);fstore(8,0);bsr('file_report');a.bra('done')
    for name,error in [('gate_failure',0xfffffffe),('native_failure',0xfffffffd),('exists_failure',0xfffffffc),('payload_failure',0xfffffffb)]:
        a.label(name);fstore(8,error);a.bra('file_failure')
    a.label('file_failure');a.move_l_abs_d(FILE+92,0);tst();a.beq('failure_report')
    # Report failing API first; then preserve its phase across explicit cleanup close.
    bsr('file_report');fload(4);a.move_l_d_abs(0,FILE+116)
    native_call(0x205,0x401585E4,[('ptr',FILE+80)])
    a.move_l_d_abs(0,FILE+44);a.move_l_abs_d(FILE+116,0).move_l_d_abs(0,FILE+4)
    a.label('failure_report');bsr('file_report');a.bra('done')
    a.label('done');a.hex('4cd77cfc');adjust(48);a.jmp(LOOP)
    a.label('fs_report');a.move_l_abs_d(STAGE+4,0);tst();a.beq('fs_uninitialized')
    a.move_l_abs_d(MOUNTED,0);a.bra('fs_mounted')
    a.label('fs_uninitialized');a.move_l_imm(0xffffffff,0)
    a.label('fs_mounted');a.move_l_d_abs(0,STAGE+12)
    for p in [IO+12,IO+8,IO+4,IO,STAGE+12,STAGE+8,STAGE+4,STAGE]:a.hex('2f39'+BE(p).hex())
    a.label('fs_format_ptr');pea(0);a.jsr(PRINTF);adjust(36);a.rts()
    a.label('file_report');a.move_l_abs_d(STAGE+4,0);tst();a.beq('file_uninitialized')
    a.move_l_abs_d(MOUNTED,0);a.bra('file_mounted')
    a.label('file_uninitialized');a.move_l_imm(0xffffffff,0)
    a.label('file_mounted');a.move_l_d_abs(0,STAGE+12)
    public=[FILE,FILE+4,FILE+8,FILE+12,STAGE+4,STAGE+12]+[FILE+x for x in range(16,64,4)]
    assert len(public)==18
    for p in reversed(public):a.hex('2f39'+BE(p).hex())
    a.label('file_format_ptr');pea(0);a.jsr(PRINTF);adjust(76);a.rts()
    code=bytearray(a.link());code_len=len(code)
    texts={n:('#'+n+'\0').encode() for n in names}
    texts.update(path=b'/proof_20261008_v1.bin\0',mode_w=b'w\0',mode_r=b'r\0',payload=payload,
                 fs_report=b'DN2FS001 stage=%08x init=%08x result=%08x mounted=%08x io=%08x lba=%08x bytes=%08x rc=%08x\n\0',
                 file_report=json.loads((JOB/'protocol.json').read_text())['format'].encode()+b'\0')
    text_addr={}
    for name,b in texts.items():
        if len(code)%4:code+=bytes(4-len(code)%4)
        text_addr[name]=DISPATCH+len(code);code+=b
    for name in names:
        pos=a._lab['compare_'+name]+2;code[pos:pos+4]=BE(text_addr[name])
    for name in ['fs','file']:
        pos=a._lab[name+'_format_ptr']+2;code[pos:pos+4]=BE(text_addr[name+'_report'])
    # Resolve only intentionally empty PEA operands within each specific call span.
    for stage,donor,ptrs in [(0x100,0x40159F50,['path']),(0x101,0x40158626,['mode_w','path']),
                            (0x102,0x4015838E,['payload']),(0x200,0x40158626,['mode_r','path'])]:
        # Native calls are emitted once each except OPEN; find the unique preceding stage store.
        marker=bytes.fromhex('203c')+BE(stage)+bytes.fromhex('23c0')+BE(FILE+4)
        at=bytes(code[:code_len]).find(marker);assert at>=0
        call=bytes(code[:code_len]).find(bytes.fromhex('4eb9')+BE(fn[donor]),at)
        region=bytes(code[at:call]);zeros=[m.start()+at+2 for m in re.finditer(bytes.fromhex('487900000000'),region)]
        assert len(zeros)==len(ptrs),(hex(stage),zeros,ptrs)
        for pos,name in zip(zeros,ptrs):code[pos:pos+4]=BE(text_addr[name])
    if len(code)%16:code+=bytes(16-len(code)%16)
    total=DISPATCH+len(code)-EXT
    assert EXT+total<=EXT_LIMIT,(len(code),hex(EXT+total),hex(EXT_LIMIT))
    ext=bytearray(total)
    for d,b in pieces.items():ext[fn[d]-EXT:fn[d]-EXT+len(b)]=b
    for dest,at in trampolines.items():ext[at-EXT:at-EXT+6]=bytes.fromhex('4ef9')+BE(dest)
    ext[DISPATCH-EXT:DISPATCH-EXT+len(code)]=code
    # Image-entry copier runs before any BSS clear. Its final transfer is to RAM.
    copy=Asm().push('a1').hex('2f0a')
    for size,src,dst in [(OLD_G,BASE+APP,GB),(total,BASE+ANNEX_OFF,EXT)]:
        copy.move_l_imm(size//4,1).hex('45f9'+BE(src).hex()).hex('43f9'+BE(dst).hex())
        label='copy_old' if dst==GB else 'copy_extension'
        copy.label(label).hex('229a41e9000453812248').bne(label)
    copy.hex('245f225f').jmp(GB+0x26)
    copier=copy.link();assert len(copier)<=0x100
    ext[:len(copier)]=copier
    patches=[]
    def patch(va,b,reason,expected=None):
        off=APP+va-GB if GB<=va<GB+OLD_G else va-BASE
        old=bytes(raw[off:off+len(b)])
        if expected is not None:assert old==expected,(hex(va),old.hex(),expected.hex())
        raw[off:off+len(b)]=b
        patches.append({'address':hex(va),'file_offset':hex(off),'old':old.hex(),'new':b.hex(),'reason':reason})
    patch(GB,bytes.fromhex('4ef9')+BE(BASE+ANNEX_OFF),'separate image copier entry; preserve old copy length',prior[APP:APP+6])
    # Original 56B boot slot clears only metadata, then invokes stock helper2 once.
    boot=Asm().move_l_imm(12,1).movea_imm(IO,0).label('clear_fs_boot').hex('42985381').bne('clear_fs_boot')
    boot.move_l_imm(0x200//4,1).movea_imm(FILE,0).label('clear_file_boot').hex('42985381').bne('clear_file_boot').jsr(HELPER2).rts()
    boot=boot.link();assert len(boot)<=56
    patch(GB+0x5c,boot+bytes.fromhex('4e71')*((56-len(boot))//2),'boot metadata only + stock helper2 once; no native filesystem call')
    patch(GB+0x94,bytes.fromhex('4ef9')+BE(DISPATCH)+bytes.fromhex('4e71')*((0x4a0-0x94-6)//2),'replace old dispatcher; no FORMAT command text or caller')
    # Only two old homes change: the old copy entry and the busy/open-bitmap scan.
    busy=oldfn[0x4015BCE8]
    assert prior[APP+busy-GB:APP+busy-GB+12]==bytes.fromhex('41f946bb2abcb1fc46bb688c')
    patch(busy+2,BE(OPEN),'full open bitmap base',BE(oldram[0x46F4DED0]))
    patch(busy+8,BE(OPEN+0xB000),'full open bitmap exclusive end; allocation bitmap stays put',BE(oldram[0x46F58ED0]))
    raw+=ext
    # Strict generated-helper ISA gate; native copied bodies preserve source ISA.
    cs=Cs(CS_ARCH_M68K,CS_MODE_BIG_ENDIAN|CS_MODE_M68K_040);check=native_validator();isa=[]
    for at,b in [(BASE+ANNEX_OFF,copier),(EXT,copier),(GB+0x5c,boot),(DISPATCH,bytes(code[:code_len]))]:
        ins=list(cs.disasm(b,at));assert sum(i.size for i in ins)==len(b),(hex(at),len(b))
        for i in ins:
            if int.from_bytes(i.bytes[:2],'big')==0x4e94:
                isa.append({'address':hex(i.address),'bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str,'manual_rule':'JSR (An), CFPRM Rev.3'})
            else:isa+=check([i])
    assert all(fn[d]==a for d,a in oldfn.items())
    assert {d:a for d,a in ram.items() if d not in (0x46F4DED0,0x46F4DED4,0x40951D90,0x406758C0)}=={d:a for d,a in oldram.items() if d not in (0x46F4DED0,0x46F4DED4)}
    # Exhaustive intended code delta accounting is represented directly by patch rows.
    expected=bytearray(prior)
    for p in patches:
        off=int(p['file_offset'],16);b=bytes.fromhex(p['new']);expected[off:off+len(b)]=b
    expected+=ext;assert expected==raw
    for name,table in [('fn_new_map.txt',fn),('ram_map.txt',ram)]:
        (OUT/name).write_text(''.join(f'{d:#x} {a:#x}\n' for d,a in sorted(table.items())))
    (OUT/'main-os.bin').write_bytes(raw);(OUT/'extension.bin').write_bytes(ext)
    receipt={'ok':True,'input_sha256':SHA(prior),'output_sha256':SHA(raw),'bytes':len(raw),
      'extension':{'source_file_offset':hex(ANNEX_OFF),'source_image_address':hex(BASE+ANNEX_OFF),'destination':hex(EXT),'copy_bytes':total,'exclusive_end':hex(EXT+total),'code_budget_end':hex(EXT_LIMIT),'copier_bytes':len(copier),'copier_hex':copier.hex(),'old_copy_bytes':OLD_G,'old_copy_dwords':OLD_G//4,'clear_transfer':hex(GB+0x26)},
      'ranges':{'native_state':[hex(STATE_BASE),hex(STATE_END)],'private_fs':[hex(STAGE),hex(STAGE+32)],'new_clear':[hex(OPEN),hex(NEW_DATA_END)],'open_bitmap':[hex(OPEN),hex(OPEN+0xB000)],'rollback_allocation':[hex(ROLL1),hex(ROLL1+0x8000)],'rollback_hash':[hex(ROLL2),hex(ROLL2+0x8000)],'file_private':[hex(FILE),hex(FILE+0x200)]},
      'file_state':hex(FILE),'file_offsets':{'op':0,'stage':4,'result':8,'native_rc':12,'attempt':16,'id':20,'size':24,'wrote':28,'read':32,'offset':36,'eof':40,'closed':44,'p0':48,'p1':52,'p2':56,'p3':60,'resolver_flags':64,'resolver_id':68,'resolver_tail':72,'handle':80,'read_buffer':96,'eof_buffer':112,'failed_stage':116},
      'old_homes_preserved':67,'new_homes':{hex(d):hex(fn[d]) for d in selected},'old_ram_changes':{hex(d):{'old':hex(oldram[d]),'new':hex(ram[d])} for d in oldram if oldram[d]!=ram[d]},
      'new_ram':{hex(d):hex(ram[d]) for d in ram if d not in oldram},'patches':patches,
      'native_relocation':relocation,'native_instruction_rows':native_rows,'trampolines':{hex(at):hex(dest) for dest,at in trampolines.items()},
      'dispatcher':hex(DISPATCH),'dispatcher_code_bytes':code_len,'dispatcher_with_text_bytes':len(code),
      'labels':{n:hex(DISPATCH+x) for n,x in a._lab.items()},'text_addresses':{n:hex(x) for n,x in text_addr.items()},
      'boot_bytes':boot.hex(),'generated_isa_rows':isa,'protocol_path':str((JOB/'protocol.json').resolve()),
      'scope':'Offline raw candidate only. Native file integration, placement and physical persistence require independent gates. No packing/device operations. Stock non-MAIN sections required.'}
    (OUT/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    (OUT/'generated-disassembly.txt').write_text('\n'.join(r['address']+' '+r['bytes']+' '+r['instruction'] for r in isa)+'\n')
    print(json.dumps({k:receipt[k] for k in ['ok','output_sha256','bytes','extension','old_homes_preserved','old_ram_changes','new_ram','dispatcher_code_bytes']},indent=2))

if __name__=='__main__':main()
