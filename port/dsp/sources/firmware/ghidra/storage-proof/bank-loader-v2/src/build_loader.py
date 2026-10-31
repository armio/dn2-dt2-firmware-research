"""Offline, additive SHARC bank transaction on the frozen V7 section7 only."""
from pathlib import Path
import hashlib, json, os, re, struct, sys, tempfile

ROOT = Path(__file__).resolve().parents[5]
V7 = ROOT / 'firmware/ghidra/oneshot-proof/v7-source'
OUT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(V7/'src'), str(V7/'scripts')]
os.environ['SELAS'] = str(ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release/selas')
os.environ['SELMAP'] = str(ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selmap/target/release/selmap')
import sharc_waverider_m3 as A
from dnfw.image import bootstream, sharc_object

BASE = V7/'out/os1handoff-v7/section_7.bin'
BASE_SHA = 'b5b568a86d93041a0110a8df83cf17ad5a586d9b93c40882da40fb622a01bcb9'
CODE_DM, CODE_CAP = 0x2DD600, 0x1000
CODE_SW = CODE_DM//2
STATE, TABLE = 0x2DE600, 0x2DE680
BANK, BANK_BYTES, MAGIC = 0x310800, 47104, 0x3142534F
ENTRIES = ((0x31182C, 2708, 48000), (0x314D54, 2723, 48000), (0x31829C, 3145, 48000))
DIR_WORDS = (MAGIC, len(ENTRIES)) + tuple(w for e in ENTRIES for w in e)
# Zero-checked spans derived from the three-slot bank geometry (directory pad +
# guards and PCM padding merged; PCM and the diagnostic tail stay unchecked).
GUARD_SPANS = ((0x2C, 0x102C), (0x2554, 0x4554), (0x5A9A, 0x7A9C), (0x932E, 0xA330))
SEQ0 = 0x4F420001

def h(b): return hashlib.sha256(b).hexdigest()

def source():
    lines = ['// New bounded command4 transaction; V7 adapter/donor and stock cases0..3 unchanged.',
             '// State: phase,next_offset,sum,expected_sum,last_seq,last_dest,last_count,last_checksum;',
             '// pending request count,dest,sequence,checksum at +32..44.', '.SECTION/PM seg_pmco;']
    def label(n): lines.extend([f'.GLOBAL bl_{n}.;', f'bl_{n}.:'])
    def emit(*s): lines.extend('      '+x+';' for x in s)
    def branch(cond,n): emit(f'{cond}JUMP 0x000000') ; lines[-1] += ' // -> bl_'+n+'.'
    def jump(n): branch('',n)
    label('entry')
    emit('R13 = 4','R8 = I3','I0 = R8','R2 = DM(0, I0)','R11 = LSHIFT R2 BY -16',f'DM({STATE+32:#x}) = R11',
         'R8 = R8 + R13','I0 = R8','R12 = DM(0, I0)',f'DM({STATE+36:#x}) = R12',
         'R8 = R8 + R13','I0 = R8','R10 = DM(0, I0)',f'DM({STATE+40:#x}) = R10',
         'R8 = R8 + R13','I0 = R8','R2 = DM(0, I0)',f'DM({STATE+44:#x}) = R2','R8 = R8 + R13')
    emit('R0 = 640','COMPU(R11, R0)'); branch('IF GT ','refuse')
    emit(f'R0 = {SEQ0:#x}','COMPU(R10, R0)'); branch('IF LT ','refuse')
    emit(f'R0 = {SEQ0+20:#x}','COMPU(R10, R0)'); branch('IF GT ','refuse')
    emit('R10 = R10 - R10','R11 = PASS R11'); branch('IF EQ ','summed')
    label('sum_loop')
    emit('I0 = R8','R2 = DM(0, I0)','R10 = R10 + R2',
         # Zero guards are verified before any bank write. R12 is bank-relative cursor.
         # v2: three-slot spans; PCM and the diagnostic tail are summed unchecked.
         'R0 = 0x2c','COMPU(R12, R0)'); branch('IF LT ','not_guard')
    emit('R0 = 0x102c','COMPU(R12, R0)'); branch('IF LT ','guard')
    emit('R0 = 0x2554','COMPU(R12, R0)'); branch('IF LT ','not_guard')
    emit('R0 = 0x4554','COMPU(R12, R0)'); branch('IF LT ','guard')
    emit('R0 = 0x5a9a','COMPU(R12, R0)'); branch('IF LT ','not_guard')
    emit('R0 = 0x7a9c','COMPU(R12, R0)'); branch('IF LT ','guard')
    emit('R0 = 0x932e','COMPU(R12, R0)'); branch('IF LT ','not_guard')
    emit('R0 = 0xa330','COMPU(R12, R0)'); branch('IF LT ','guard')
    jump('not_guard')
    label('guard'); emit('R2 = PASS R2'); branch('IF NE ','refuse')
    label('not_guard'); emit('R8 = R8 + R13','R12 = R12 + R13','R0 = 1','R11 = R11 - R0'); branch('IF NE ','sum_loop')
    emit(f'R2 = DM({STATE+44:#x})','COMP(R10, R2)'); branch('IF NE ','refuse')
    label('summed')
    # Accepted-repeat receipt is idempotent: no writes and no idle requirement.
    emit(f'R2 = DM({STATE+40:#x})',f'R0 = DM({STATE+16:#x})','COMP(R2, R0)'); branch('IF NE ','new_seq')
    for pending,accepted in ((36,20),(32,24),(44,28)):
        emit(f'R2 = DM({STATE+pending:#x})',f'R0 = DM({STATE+accepted:#x})','COMP(R2, R0)'); branch('IF NE ','refuse')
    jump('ack')
    label('new_seq')
    emit(f'R2 = DM({STATE+40:#x})',f'R0 = DM({STATE+16:#x})','R11 = 1','R0 = R0 + R11','COMP(R2, R0)'); branch('IF EQ ','idle')
    emit(f'R0 = {SEQ0:#x}','COMP(R2, R0)'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE:#x})','R0 = PASS R0'); branch('IF NE ','refuse')
    label('idle')
    # Native copied-frame raw on/off and copies at34..41, aligned reads only.
    emit('R2 = DM(0x25c4ac)','R0 = 0xffff0000','R2 = R2 AND R0'); branch('IF NE ','refuse')
    emit('R2 = DM(0x25c4b0)','R2 = PASS R2'); branch('IF NE ','refuse')
    emit('R2 = DM(0x25c4b4)','R0 = 0xffff','R2 = R2 AND R0'); branch('IF NE ','refuse')
    emit('R8 = 0x30e1b8','R11 = 16','R13 = 0x1d8')
    label('idle_loop'); emit('I0 = R8','R2 = DM(0, I0)','R0 = 255','R2 = R2 AND R0'); branch('IF NE ','refuse')
    emit('R8 = R8 + R13','R0 = 1','R11 = R11 - R0'); branch('IF NE ','idle_loop')
    emit(f'R12 = DM({STATE+36:#x})','R0 = 0xffffffff','COMP(R12, R0)'); branch('IF EQ ','begin')
    emit('R0 = 0xfffffffc','COMP(R12, R0)'); branch('IF EQ ','commit')
    # Only contiguous bounded chunks while RECEIVING; range tests precede writes.
    emit(f'R0 = DM({STATE:#x})','R2 = 1','COMP(R0, R2)'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+4:#x})','COMP(R12, R0)'); branch('IF NE ','refuse')
    emit(f'R11 = DM({STATE+32:#x})','R11 = PASS R11'); branch('IF EQ ','refuse')
    emit('R0 = 3','R2 = R12 AND R0'); branch('IF NE ','refuse')
    emit('R2 = LSHIFT R11 BY 2','R2 = R12 + R2',f'R0 = {BANK_BYTES}','COMPU(R2, R0)'); branch('IF GT ','refuse')
    emit(f'DM({STATE+48:#x}) = R2','R13 = 16','R8 = I3','R8 = R8 + R13','R12 = PASS R12'); branch('IF NE ','copy_start')
    # First chunk must contain the complete exact three-entry directory.
    emit('R0 = 11','COMPU(R11, R0)'); branch('IF LT ','refuse')
    for n,w in enumerate(DIR_WORDS):
        emit('I0 = R8','R2 = DM(0, I0)',f'R0 = {w:#x}','COMP(R2, R0)'); branch('IF NE ','refuse')
        if n<len(DIR_WORDS)-1: emit('R13 = 4','R8 = R8 + R13')
    emit('R13 = 16','R8 = I3','R8 = R8 + R13')
    label('copy_start'); emit(f'R0 = {BANK:#x}','R12 = R12 + R0','R13 = 4')
    label('copy_loop'); emit('I0 = R8','R2 = DM(0, I0)',f'R0 = {BANK:#x}','COMP(R12, R0)'); branch('IF EQ ','skip_magic')
    emit('I0 = R12','DM(0, I0) = R2')
    label('skip_magic'); emit('R8 = R8 + R13','R12 = R12 + R13','R0 = 1','R11 = R11 - R0'); branch('IF NE ','copy_loop')
    emit(f'R2 = DM({STATE+44:#x})',f'R0 = DM({STATE+8:#x})','R10 = R10 - R10','R10 = R0 + R2',f'DM({STATE+8:#x}) = R10',
         f'R2 = DM({STATE+48:#x})',f'DM({STATE+4:#x}) = R2'); jump('accept')
    label('begin'); emit(f'R0 = DM({STATE:#x})','R0 = PASS R0'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+32:#x})','R0 = PASS R0'); branch('IF NE ','refuse')
    emit('R0 = 0',f'DM({BANK:#x}) = R0',f'DM({STATE+4:#x}) = R0',f'DM({STATE+8:#x}) = R0',
         f'R2 = DM({STATE+44:#x})',f'DM({STATE+12:#x}) = R2','R0 = 1',f'DM({STATE:#x}) = R0'); jump('accept')
    label('commit'); emit(f'R0 = DM({STATE:#x})','R2 = 1','COMP(R0, R2)'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+32:#x})','R0 = PASS R0'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+4:#x})',f'R2 = {BANK_BYTES}','COMP(R0, R2)'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+8:#x})',f'R2 = DM({STATE+12:#x})','COMP(R0, R2)'); branch('IF NE ','refuse')
    emit(f'R0 = DM({STATE+44:#x})','COMP(R0, R2)'); branch('IF NE ','refuse')
    emit(f'R0 = {MAGIC:#x}',f'DM({BANK:#x}) = R0','R0 = 2',f'DM({STATE:#x}) = R0')
    label('accept')
    for src,dst in ((40,16),(36,20),(32,24),(44,28)):
        emit(f'R2 = DM({STATE+src:#x})',f'DM({STATE+dst:#x}) = R2')
    label('ack'); emit(f'R2 = DM({STATE+40:#x})','R10 = LSHIFT R2 BY 16','R2 = LSHIFT R2 BY -16','R10 = R10 OR R2'); jump('reply')
    label('refuse'); emit(f'R2 = DM({STATE+40:#x})','R10 = LSHIFT R2 BY 16','R2 = LSHIFT R2 BY -16','R10 = R10 OR R2','R2 = 0x8000','R10 = R10 XOR R2')
    label('reply'); emit(f'DM({STATE+52:#x}) = R10','R0 = 1',f'DM({STATE+72:#x}) = R0','DM(0x2c49e8) = R10','DM(0x2c59e8) = R10', 'R0 = 8','R11 = 8','R12 = 2','R13 = 4','I3 = 0x25c48c','JUMP 0x1c9f0f')
    # V7 owns word6 as diagnostic telemetry at TWO sites. Preserve that exact
    # behavior until OWNER becomes1 on the first loader reply, including a
    # refused BEGIN at phase0. Thereafter word6 belongs to the sticky ACK.
    # Each six-byte first store is a guarded jump here; the second stock store
    # is bypassed and both original destinations are written exactly once.
    for suffix,resume in [('persistent',0x185E54),('helper',0x186100)]:
        label('word6_'+suffix)
        emit(f'DM({STATE+56:#x}) = R0',f'DM({STATE+60:#x}) = R1',
             f'DM({STATE+64:#x}) = ASTATX',f'DM({STATE+68:#x}) = ASTATY',
             f'R1 = DM({STATE+72:#x})','R1 = PASS R1')
        branch('IF EQ ','word6_write_'+suffix)
        emit(f'R0 = DM({STATE+52:#x})')
        label('word6_write_'+suffix)
        emit('DM(0x2c49e8) = R0','DM(0x2c59e8) = R0',
             f'R0 = DM({STATE+56:#x})',f'R1 = DM({STATE+60:#x})',
             f'ASTATY = DM({STATE+68:#x})',f'ASTATX = DM({STATE+64:#x})',f'JUMP {resume:#x}')
    return '\n'.join(lines)+'\n'

def assemble(text, work):
    src=work/'loader.asm'; src.write_text(text)
    raw, offsets=A._selas(src,work)
    syms=sharc_object.symbols((work/'loader.doj').read_bytes())
    labels={k: CODE_SW+v for k,v in syms.items() if k.startswith('bl_')}
    # Pinned selas ASTAT aliases73/74 are wrong on real SHARC+; correct only
    # these exact Type14a absolute transfers to native UREG76/77 as frozenV7.
    ins=[l.split('//',1)[0].strip() for l in text.splitlines()]
    ins=[l for l in ins if l.endswith(';') and not l.startswith('.')]
    assert len(ins)==len(offsets)
    fixed=bytearray(raw)
    for i,l in enumerate(ins):
        if 'ASTAT' not in l:continue
        match=re.fullmatch(r'DM\((0x[0-9a-f]+)\) = (ASTAT[XY]);',l);store=match is not None
        if store:addr,name=int(match[1],16),match[2]
        else:
            match=re.fullmatch(r'(ASTAT[XY]) = DM\((0x[0-9a-f]+)\);',l);assert match,l
            name,addr=match[1],int(match[2],16)
        at=offsets[i];wrong=0x73 if name=='ASTATX' else 0x74;right=wrong+3
        expected=bytes([0x11 if store else 0x10,wrong])+addr.to_bytes(4,'big')
        assert raw[at:at+6]==expected,(l,raw[at:at+6].hex())
        fixed[at+1]=right
    return bytes(fixed),offsets,labels

def main():
    base=BASE.read_bytes(); assert h(base)==BASE_SHA
    text=source()
    with tempfile.TemporaryDirectory(dir=OUT/'attempts') as t:
        work=Path(t);_,_,labels=assemble(text,work)
        text=re.sub(r'JUMP 0x000000; // -> (bl_\w+\.)',lambda m:f'JUMP {labels[m[1]]:#x}; // -> {m[1]}',text)
        be,offs,labels2=assemble(text,work); assert labels==labels2
    code=sharc_object.load_bytes(be); assert len(code)<=CODE_CAP-64
    stream=bytearray(base)
    table=struct.pack('<8I',0x1C9DC2,0x1C9E76,0x1C9EDA,0x1C9F0F,CODE_SW,0x1C9DC2,0x1C9DC2,0x1C9DC2)
    extra=b''
    for address,size in ((CODE_DM,CODE_CAP),(STATE,128),(TABLE,32)):
        for at,data in bootstream.load_regions(base):
            assert not (at<0x28000000+address+size and 0x28000000+address<at+len(data))
    extra+=bootstream.block(0x28000000+CODE_DM,code+bytes(CODE_CAP-len(code)))
    extra+=bootstream.block(0x28000000+STATE,flags=bootstream.FLAG_FILL,count=128)
    extra+=bootstream.block(0x28000000+TABLE,table)
    patches=[]
    for sw,before,after in ((0x1C9D9F,bytes.fromhex('140f2600688a'),bytes.fromhex('140f2d0080e6')),
                            (0x1C9DAA,bytes.fromhex('3e02007812fe'),bytes.fromhex('3e02007812fd'))):
        addr=0x28000000+2*sw;assert bootstream.read_span(base,addr,len(before))==before
        bootstream.write_span(stream,addr,after);patches.append({'sw':hex(sw),'from':before.hex(),'to':after.hex()})
    for sw,label in ((0x185E4E,'bl_word6_persistent.'),(0x1860FA,'bl_word6_helper.')):
        before=sharc_object.load_bytes(bytes.fromhex('1100002c49e8'))
        addr=0x28000000+2*sw;assert bootstream.read_span(base,addr,6)==before
        # Reuse the pinned assembler for a single ordinary absolute JUMP.
        with tempfile.TemporaryDirectory(dir=OUT/'attempts') as t:
            p=Path(t)/'hook.asm';p.write_text('.SECTION/PM seg_pmco;\n JUMP '+hex(labels[label])+';\n')
            be_hook,_=A._selas(p,Path(t));after=sharc_object.load_bytes(be_hook)
        assert len(after)==6
        bootstream.write_span(stream,addr,after);patches.append({'sw':hex(sw),'from':before.hex(),'to':after.hex(),'word6_ownership_shim':label})
    candidate=bootstream.insert_before_final(bytes(stream),extra)
    (OUT/'src/loader.asm').write_text(text)
    (OUT/'section_7.bin').write_bytes(candidate)
    (OUT/'loader-code.bin').write_bytes(code)
    report={'schema':'dn2-oneshot-bank-loader-v2','base_section7_sha256':h(base),'candidate_section7_sha256':h(candidate),
        'base_section7':str(BASE.resolve()),'candidate_bytes':len(candidate),'code_dm':hex(CODE_DM),'code_sw':hex(CODE_SW),
        'code_bytes':len(code),'code_sha256':h(code),'state_dm':hex(STATE),'command_table_dm':hex(TABLE),
        'instruction_offsets':offs,'labels':{k:hex(v) for k,v in labels.items()},'object_parcels_be':be.hex(),
        'source_sha256':h(text.encode()),'builder_sha256':h(Path(__file__).read_bytes()),'native_patches':patches,
        'bank_span':[BANK,BANK+BANK_BYTES],'entries':ENTRIES,'guard_spans':[[a,b] for a,b in GUARD_SPANS],'sequence_first':SEQ0,'frames':21,
        'protocol':{'command':4,'words':['count_words<<16|4','bank_relative_offset_or_control','sequence','payload_word_sum_or_full_bank_sum'],
                    'begin':0xffffffff,'commit':0xfffffffc,'max_payload_bytes':2560,'ack_dm':['0x2c49e8','0x2c59e8'],
                    'refusal_bit':0x80000000,'ack_half_swap':True,'publish':'OSB1 magic is final commit store',
                    'retry_required':'producer must cap per-frame timeout and explicit-refusal retries and total frames',
                    'word6_ownership':'owner0 beforefirstloaderreply preservesV7telemetry;owner1 afteranyloaderreply(includingrefusal) stickyloaderACK overrideswireword6 only; privateV7diagnostic state is unchanged',
                    'owner_state_dm':hex(STATE+72),
                    'ack_state_dm':hex(STATE+52),'diagnostic_version':'V7 renderer/handoff with bank-loader-v1 word6 ownership extension'},
        'limits':['Host emulation only; physical acknowledgement, timing and playback still required.',
                  'One boot permits one transaction; abort leaves bank unpublished until reboot. Checksum is additive, not cryptographic.']}
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('candidate_section7_sha256','code_bytes','frames')}))

if __name__=='__main__': main()
