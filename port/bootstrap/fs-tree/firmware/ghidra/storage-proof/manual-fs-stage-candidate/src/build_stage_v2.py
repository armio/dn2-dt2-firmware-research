#!/usr/bin/env python3
"""Isolated postprocessor of pinned combined raw MAIN. No device/export/SYX."""
from pathlib import Path
import ast, hashlib, importlib.util, json, re, shutil
from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_040

JOB = Path(__file__).resolve().parents[1]
IN, OUT = JOB/'inputs', JOB/'revision02'
OUT.mkdir(exist_ok=True)
BASE, GB, APP = 0x40000400, 0x46800000, 0x30B580
BOOT, CODE, CODE_END, GUARD = GB+92, GB+0x94, GB+0x4A0, GB+0x612
STATE_BASE, STATE_END, STAGE, SCRATCH = 0x46816F8C, 0x47A19CA0, 0x47A19CA0, 0x47A19C90
MOUNTED = 0x46B9608C
HOOK, CONTINUE, LOOP = 0x400CE1C2, 0x400CE1C8, 0x400CD4E0
PRINTF, HELPER2, COMPARE = 0x400054B4, 0x4012C340, 0x4017E8A8
READ_CAVE_START, READ_CAVE_END = 0x402DFA1C, 0x402DFBD6
SHA = lambda b: hashlib.sha256(b).hexdigest()
BE = lambda x: (x & 0xFFFFFFFF).to_bytes(4,'big')

def load_encoder():
    s=importlib.util.spec_from_file_location('isolated_coldfire', IN/'coldfire.py')
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m.Asm

def mapping(path):
    return {int(x[0],16):int(x[1],16) for x in (l.split() for l in path.read_text().splitlines()) if x}

def validator():
    tree=ast.parse((IN/'native-isa-validator.py').read_text())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_native_isa')
    ns={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(IN/'native-isa-validator.py'),'exec'),ns)
    return ns['validate_native_isa']

def main():
    raw=bytearray((IN/'combined-main-os.bin').read_bytes()); stock=(IN/'stock-dn2-main.bin').read_bytes()
    assert SHA(raw)=='c4f4dcc9a03dca1f0f28185fa7c7b7eca384e941fe6b72043cd690abf344ea57'
    fn=mapping(IN/'combined-fn-map.txt');ram=mapping(IN/'combined-ram-map.txt');assert ram[0x44F2BD68]==MOUNTED
    assert len(fn)==67 and len(ram)==119
    patches=[]
    def offset(va):return APP+va-GB if va>=GB else va-BASE
    def get(va,n):return bytes(raw[offset(va):offset(va)+n])
    def patch(va,b,why,expected=None):
        old=get(va,len(b))
        if expected is not None:assert old==expected,(hex(va),old.hex(),expected.hex())
        patches.append({'address':hex(va),'size':len(b),'old':old.hex(),'new':b.hex(),'reason':why})
        raw[offset(va):offset(va)+len(b)]=b
    cs=Cs(CS_ARCH_M68K,CS_MODE_BIG_ENDIAN|CS_MODE_M68K_040)
    # The ten original logger stubs carry their exact original callee in PEA.
    tails={}
    for at in [GB+x for x in (0x360,0x388,0x3B0,0x3D8,0x400,0x428,0x450,0x478,0x600,0x638)]:
        assert get(at,2)==bytes.fromhex('4879')
        tails[at]=int.from_bytes(get(at+2,4),'big')
    closure={}
    for line in (IN/'dt2-closure.log').read_text().splitlines():
        m=re.search(r'(?:FUN_)?([0-9a-fA-F]{8}).*?@?0x?([0-9a-fA-F]{8})\.\.0x?([0-9a-fA-F]{8})',line)
        if m:closure[int(m[1],16)]=int(m[3],16)-int(m[2],16)
    # Closure log uses ENTRY records; take exact sizes from the copied builder report if needed.
    report=(IN/'combined-graft-report.txt').read_text()
    for d,s,e in re.findall(r'GRAFT FUN_([0-9a-f]{8}) @0x([0-9a-f]{8})\.\.0x([0-9a-f]{8})',report):
        closure[int(d,16)]=int(e,16)-int(s,16)
    assert all(d in closure for d in fn)
    retired=[]
    for donor,at in fn.items():
        # Ghidra's native instruction boundaries remain authoritative even where
        # Motorola Capstone stops on a supported ColdFire-only instruction.
        native_instructions=[(int(x,16),int(n,16)) for x,n in re.findall(r'INST ([0-9a-f]+) ([0-9a-f]+)',(IN/'dt2-closure.log').read_text())]
        for native,length in native_instructions:
            if not donor<=native<donor+closure[donor]:continue
            address=at+native-donor;b=get(address,6);op=int.from_bytes(b[:2],'big')
            if length==6 and (op in (0x4EB9,0x4EF9,0x4879) or (op & 0xF1FF)==0x41F9):
                target=int.from_bytes(b[2:6],'big')
                if target in tails:
                    patch(address+2,BE(tails[target]),'retire exact legacy logger thunk at native Ghidra instruction boundary',BE(target))
                    retired.append({'site':hex(address),'native_site':hex(native),'old_target':hex(target),'native_target':hex(tails[target])})
    # Three caller checkpoints have displaced non-call bytes or a different logger layout.
    patch(fn[0x4015816C]+0x26,bytes.fromhex('2404206e0010'),'restore native context return checkpoint',bytes.fromhex('4ef9')+BE(GB+0x56A))
    patch(fn[0x40157D28]+0x70,bytes.fromhex('4fef00102001'),'restore native divide return checkpoint',bytes.fromhex('4ef9')+BE(GB+0x74A))
    patch(fn[0x40157D28]+0x8E,BE(fn[0x4015591A]),'restore native sample release instead of legacy G5D',BE(GB+0x512))
    # Core diagnostic mode explicitly skips DT2 factory import even for format's internal init(0).
    patch(fn[0x4015A124]+0x26,bytes.fromhex('4e71'),'core filesystem diagnostic: bypass factory-import BEQ',bytes.fromhex('670a'))
    # Restore both old console slots, retiring FORMAT/WRTEST. Then hook only the old REBOOT PEA.
    patch(HOOK,stock[HOOK-BASE:0x400CE284-BASE],'restore stock REBOOT/Maintenance slots; remove legacy format/write routes')
    Asm=load_encoder()
    # Boot initializes only 48 B private metadata; native helper2 runs exactly once.
    boot=Asm().hex('207c'+BE(SCRATCH).hex()).hex('4298'*12).jsr(HELPER2).rts().link()
    assert len(boot)<=56
    patch(BOOT,boot+bytes.fromhex('4e71')*((56-len(boot))//2),'boot metadata only + original helper2; no flags/clear/mount/format')
    a=Asm(); code_ranges=[]
    def ea_imm(va):a.hex('207c'+BE(va).hex())
    def stage_store(off,value):a.move_l_imm(value,0).hex('23c0'+BE(STAGE+off).hex())
    def stage_load(off,d=0):a.move_l_abs_d(STAGE+off,d)
    def call_label(name):a._br('61',name)
    def tst(d=0):a.hex(f'{0x4A80+d:04x}')
    def adjust(n):a.hex('4fef'+(n&0xFFFF).to_bytes(2,'big').hex())
    a.label('entry');adjust(-48);a.hex('48d77cfc')
    for op,name in [(1,'FSINIT'),(2,'FSFORMAT'),(3,'FSMOUNT'),(4,'FSSTATUS')]:
        # Explicit address patched after link because text follows the code.
        a.label('compare_'+name);a.hex('4879'+'00000000').push('d2').hex('4e94');adjust(8);tst();a.beq(name)
    a.label('unmatched');a.hex('4cd77cfc');adjust(48);a.hex('4879'+BE(0x4021ACB1).hex()).jmp(CONTINUE)
    a.label('FSSTATUS');call_label('report');a.bra('done')
    for op,name,native,arg in [(1,'FSINIT',fn[0x4015A43A],None),(2,'FSFORMAT',fn[0x4015A164],0),(3,'FSMOUNT',fn[0x4015A450],1)]:
        a.label(name);stage_load(4);tst()
        if op==1:a.bne(name+'_reject')
        else:a.beq(name+'_reject')
        if op==2:
            stage_load(16);tst();a.bne(name+'_reject');stage_store(16,1)
        stage_store(0,op<<8);stage_store(8,0);call_label('report')
        if op==1:
            a.move_l_imm((STATE_END-STATE_BASE)//4,0);ea_imm(STATE_BASE)
            a.label('manual_clear');a.hex('42985380');a.bne('manual_clear');a.jsr(native);stage_store(4,1);a.hex('4280')
        else:
            a.move_l_imm(arg,0).push('d0').jsr(native);adjust(4)
        a.hex('23c0'+BE(STAGE+8).hex());stage_store(0,(op<<8)|1);call_label('report');a.bra('done')
        a.label(name+'_reject');stage_store(0,(op<<8)|0xFF);stage_store(8,0xFFFFFFFE);call_label('report');a.bra('done')
    a.label('done');a.hex('4cd77cfc');adjust(48);a.jmp(LOOP)
    a.label('report');stage_load(4);tst();a.beq('uninitialized');a.move_l_abs_d(MOUNTED,0);a.bra('mounted_ready')
    a.label('uninitialized');a.move_l_imm(0xFFFFFFFF,0)
    a.label('mounted_ready');a.hex('23c0'+BE(STAGE+12).hex())
    for address in [SCRATCH+12,SCRATCH+8,SCRATCH+4,SCRATCH,STAGE+12,STAGE+8,STAGE+4,STAGE]:a.hex('2f39'+BE(address).hex())
    a.label('format_push');a.hex('4879'+'00000000').jsr(PRINTF);adjust(36);a.rts()
    code=a.link();code_len=len(code)
    texts={name:('#'+name+'\0').encode() for name in ['FSINIT','FSFORMAT','FSMOUNT','FSSTATUS']}
    texts['report']=b'DN2FS001 stage=%08x init=%08x result=%08x mounted=%08x io=%08x lba=%08x bytes=%08x rc=%08x\n\0'
    text_va={};data=bytearray(code)
    for name,b in texts.items():text_va[name]=CODE+len(data);data+=b
    if len(data)%2:data+=b'\0'
    for name in ['FSINIT','FSFORMAT','FSMOUNT','FSSTATUS']:
        pos=a._lab['compare_'+name]+2;data[pos:pos+4]=BE(text_va[name])
    pos=a._lab['format_push']+2;data[pos:pos+4]=BE(text_va['report'])
    assert CODE+len(data)<=CODE_END,(len(data),CODE_END-CODE)
    patch(CODE,bytes(data)+bytes.fromhex('4e71')*((CODE_END-CODE-len(data))//2),'manual stage dispatcher in retired diagnostic code/string reservation')
    patch(HOOK,bytes.fromhex('4ef9')+BE(CODE),'manual stage dispatch hook',stock[HOOK-BASE:HOOK-BASE+6])
    # Remaining retired diagnostic code is unreachable; preserve checker + exact guard.
    patch(CODE_END+6,bytes.fromhex('4e71')*((GUARD-CODE_END-6)//2),'retire remaining logger code while preserving checker entry and guard')
    patch(GUARD+22,bytes.fromhex('4e71')*((GB+0x7A0-GUARD-22)//2),'retire remaining logger/G7/FD code after exact guard')
    assert get(GUARD,22)==bytes.fromhex('b3c866042268000c246800102668000c4ef946801308')
    assert get(CODE_END,2)==bytes.fromhex('23ca') # IO agent will replace old checker entry with JMP WRITE.
    assert get(READ_CAVE_START,READ_CAVE_END-READ_CAVE_START)==bytes(442)
    assert get(0x400CE0F6,8)==bytes.fromhex('41ea00097e1c97cb')
    assert get(0x4021ACA8,9)==b'#MMCDUMP\0'
    # Compose only the pinned guard's cave, checker entry and exact native operands.
    stage_only_raw=bytes(raw);stage_only_patches=list(patches)
    io=json.loads((IN/'io-patch-report.json').read_text())
    assert io['source_main_sha256']=='c4f4dcc9a03dca1f0f28185fa7c7b7eca384e941fe6b72043cd690abf344ea57'
    io_applied=[]
    for row in io['patches']:
        address=int(row['address'],16);old=bytes.fromhex(row['old_hex']);new=bytes.fromhex(row['new_hex'])
        if address==CODE_END:old,new=old[:6],new[:6]
        else:assert address==0x402DFBD8 or address>=GB+0x7A0
        patch(address,new,'pinned fail-stop guard: '+row['purpose'],old)
        io_applied.append({'address':hex(address),'bytes':len(new)})
    # Every new instruction is gate-checked; extend only two already documented native forms.
    check=validator();rows=[]
    for start,b in [(BOOT,boot),(CODE,bytes(data[:code_len]))]:
        ins=list(cs.disasm(b,start));assert sum(i.size for i in ins)==len(b)
        for i in ins:
            w=int.from_bytes(i.bytes[:2],'big')
            if w==0x4E94:
                rows.append({'address':hex(i.address),'bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str,'manual_rule':'JSR (An), CFPRM Rev.3 4-43..4-44'})
            else:rows+=check([i])
    for name in ['combined-fn-map.txt','combined-ram-map.txt']:
        shutil.copyfile(IN/name,OUT/('fn_new_map.txt' if 'fn-' in name else 'ram_map.txt'))
    (OUT/'main-os.bin').write_bytes(raw)
    labels={k:hex(CODE+v) for k,v in a._lab.items()}
    receipt={'ok':True,'input_sha256':SHA((IN/'combined-main-os.bin').read_bytes()),'output_sha256':SHA(raw),'image_bytes':len(raw),'patches':patches,'retired_logger_calls':retired,'code_start':hex(CODE),'code_bytes':code_len,'code_and_text_bytes':len(data),'code_capacity':CODE_END-CODE,'labels':labels,'text_addresses':{k:hex(v) for k,v in text_va.items()},'stage_state':{'start':hex(STAGE),'end':hex(STAGE+32),'offsets':{'stage':0,'init':4,'result':8,'mounted_snapshot':12,'format_started':16}},'manual_clear':{'start':hex(STATE_BASE),'end':hex(STATE_END),'bytes':STATE_END-STATE_BASE},'io_scratch':hex(SCRATCH),'mounted':hex(MOUNTED),'retained_guard':{'start':hex(GUARD),'bytes':get(GUARD,22).hex()},'reserved_root_rdprobe':{'start':hex(READ_CAVE_START),'end':hex(READ_CAVE_END)},'function_homes_unchanged':67,'ram_mappings_unchanged':119,'native_forms':rows,'io_guard_composition':{'patches':io_applied,'read_entry':io['read_entry'],'write_entry':io['write_entry'],'native_isa_receipt':str(IN/'io-isa-validation.json'),'execution_receipt':str(IN/'io-emulation.json')},'scope':'Offline stage + fail-stop IO raw candidate. Root owns independent final composition/review. No SYX/export/device operation; full format/mount/media completion unproved.'}
    (OUT/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    stage_receipt=dict(receipt);stage_receipt.update(output_sha256=SHA(stage_only_raw),patches=stage_only_patches,io_guard_composition=None)
    (OUT/'stage-only-main-os.bin').write_bytes(stage_only_raw)
    (OUT/'stage-only-build-receipt.json').write_text(json.dumps(stage_receipt,indent=2)+'\n')
    (OUT/'stage-disassembly.txt').write_text('\n'.join(f'{r["address"]} {r["bytes"]:12} {r["instruction"]}' for r in rows)+'\n')
    print(json.dumps({k:receipt[k] for k in ['ok','output_sha256','code_bytes','code_and_text_bytes','code_capacity']},indent=2))

if __name__=='__main__':main()
