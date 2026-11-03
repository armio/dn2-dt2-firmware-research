#!/usr/bin/env python3
"""R010: retain complete paired USB exports until guarded DMA publication."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct

import build_dt2_usb_guard_reasons as R

P = R.P
C, B, A, O, T = P.C, P.B, P.A, P.O, P.T
BASE = C.ROOT/'output/dn2-research/usb-guard-r008-20261102/dsp/section_7.bin'
# Exact R008/R009 DSP; MAIN changes are packaged separately.
BASE_SHA = '7613f501bcf71c8e8a8d99a1976a549baf8f8b2df7dc30a8a88baa2dc08da7ff'
CODE, PHYSICAL, CODE_END = 0xbe9000, 0x200d2000, 0x200d3c00
STATE, STATE_END = 0x200db000, 0x200db800
SLOT_BASE, SLOT_BYTES, CAPACITY = 0x200b0000, 0x1400, 3
SLOTS = tuple(SLOT_BASE+i*SLOT_BYTES for i in range(4))
SLOT_END = SLOT_BASE+4*SLOT_BYTES
SPI_OFFSET = 0x800
META = STATE+0x600
REGS = ('I0','MODE1','R0','R1','R2','R3','I1','L0','L1','M0','ASTATX','ASTATY')
SAVES = {n:{r:STATE+off+4*i for i,r in enumerate(REGS)}
         for n,off in (('before',0),('early',0x80),('after',0x100),('publication',0x180))}
FIELDS = {n:STATE+0x200+4*i for i,n in enumerate((
    'write_cursor','read_cursor','produced','enqueued','committed','overflow',
    'rejected','empty','cycle_published','producer_valid','original_tdm','original_spi',
    'write_stage','head_stage','head_sequence','publication_phase','last_sequence',
    'last_tdm','last_spi','seen_tdm','seen_spi','freshness_deferred','bad_pointer',
    'bad_depth','started','last_elapsed','max_elapsed','crossed','cross_flags',
    'return_kind','attempts','max_depth','last_reason','last_depth'))}
G = {n:STATE+0x380+4*i for i,n in enumerate(('tdm_target','spi_target'))}
F = {f'{phase}_{bus}_{field}':STATE+0x400+4*i for i,(phase,bus,field) in enumerate(
    (phase,bus,field) for phase in ('before','after') for bus in ('tdm','spi')
    for field in ('start','current','count','start_again'))}
HOOKS = (('before',0x1c265b,6,0x1c265e),('after',0x1c26ef,6,0x1c26f2),
         ('early',0x1c9f15,10,0x1c9f1a),('publication',0xbf264c,6,0xbf2676))
label, jump, load, store = P.label, P.jump, P.load, P.store


def inc(name):
    return P.inc(FIELDS[name])


def save(name):
    p = SAVES[name]
    return (store(p['I0'],'I0')+label(name+'_mode')+'      I0 = 0x12345678;\n'+
            store(p['MODE1'],'I0')+'      BIT CLR MODE1 0x202000;\n      NOP;\n      NOP;\n'+
            ''.join(store(p[r],r) for r in REGS[2:]))


def restore(name):
    p = SAVES[name]
    return ''.join(load(p[r],r) for r in (*REGS[2:],'MODE1','I0'))


def clock(name, address):
    return label(name+'_clock')+'      I0 = 0x12345678;\n'+store(address,'I0')


def slot_pointer(cursor, destination):
    return (load(FIELDS[cursor])+'      R1 = 3;\n      R0 = R0 AND R1;\n'
            '      R1 = LSHIFT R0 BY 12;\n      R0 = LSHIFT R0 BY 10;\n'
            f'      R0 = R0 + R1;\n      R1 = {SLOT_BASE:#x};\n      R0 = R0 + R1;\n'+
            store(FIELDS[destination]))


def meta_pointer(cursor):
    return (load(FIELDS[cursor])+'      R1 = 3;\n      R0 = R0 AND R1;\n'
            f'      R0 = LSHIFT R0 BY 4;\n      R1 = {META:#x};\n      R0 = R0 + R1;\n'
            '      I0 = R0;\n      L0 = 0;\n      NOP;\n')


def snapshot(phase, bus):
    dma = P.BUS[bus][0]
    return ''.join(label(f'{phase}_{bus}_{field}')+load(dma+offset)+store(F[f'{phase}_{bus}_{field}'])
                   for field,offset in (('start',4),('current',0x2c),('count',0x34),('start_again',4)))


def validate(phase, bus, bad):
    # Reuse every R008 ownership predicate and numerical bound verbatim.
    old_g, old_f = P.G, P.F
    try:
        P.G, P.F = G, F
        s = P.validate(phase,bus,bad)
    finally:
        P.G, P.F = old_g, old_f
    ids = [n for n,(p,b,_) in R.REASONS.items() if p==phase and b==bus and n>2]
    hits = list(re.finditer(r'(?m)^.*JUMP 0x0; // -> '+re.escape(bad)+r'\.\n',s))
    assert len(hits)==len(ids)
    for h,n in reversed(list(zip(hits,ids))):
        s=s[:h.start()]+h.group().replace('// -> '+bad+'.','// -> reason_'+str(n)+'.')+s[h.end():]
    return s


def observe_consumption(bus):
    """Require a positive-count transfer after publication, not an old drained state."""
    prefix='seen_'+bus
    s=load(FIELDS['last_'+bus])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump(prefix+'_done','IF EQ')
    s+='      R1 = 0x28000000;\n      R2 = R0 + R1;\n'+load(F['before_'+bus+'_start'])
    s+='      COMP(R0, R2);\n'+jump(prefix+'_done','IF NE')+load(F['before_'+bus+'_start_again'],'R1')
    s+='      COMP(R0, R1);\n'+jump(prefix+'_done','IF NE')
    _,_,_,size,_,maximum=P.BUS[bus]
    s+=load(F['before_'+bus+'_count'])+f'      R1 = {maximum};\n      COMPU(R0, R1);\n'+jump(prefix+'_done','IF GT')
    s+='      R1 = 0;\n      COMP(R0, R1);\n'+jump(prefix+'_done','IF EQ')
    s+=load(F['before_'+bus+'_current'])+'      COMPU(R0, R2);\n'+jump(prefix+'_done','IF LT')
    s+=f'      R1 = {size};\n      R2 = R2 + R1;\n      COMPU(R0, R2);\n'+jump(prefix+'_done','IF GE')
    return s+label(prefix+'_yes')+'      R0 = 1;\n'+store(FIELDS['seen_'+bus])+label(prefix+'_done')


def source():
    s='.SECTION/PM seg_pmco;\n'+label('before_entry')+save('before')
    s+=store(FIELDS['original_tdm'],'I3')+store(FIELDS['original_spi'],'I13')
    s+='      R0 = 0;\n'+store(FIELDS['producer_valid'])+store(FIELDS['write_stage'])
    for bus,reg in (('tdm','I3'),('spi','I13')):
        pages=P.BUS[bus][1]
        s+=f'      R0 = {reg};\n      R1 = {pages[0]:#x};\n      COMP(R0, R1);\n'+jump('producer_'+bus+'_valid','IF EQ')
        s+=f'      R1 = {pages[1]:#x};\n      COMP(R0, R1);\n'+jump('producer_bad_pointer','IF NE')+label('producer_'+bus+'_valid')
    s+=load(FIELDS['write_cursor'])+load(FIELDS['read_cursor'],'R1')+'      R0 = R0 - R1;\n      R1 = 3;\n      COMPU(R0, R1);\n'+jump('producer_bad_depth','IF GT')
    s+=slot_pointer('write_cursor','write_stage')+'      I3 = R0;\n      R1 = 0x800;\n      R0 = R0 + R1;\n      I13 = R0;\n      R0 = 1;\n'+store(FIELDS['producer_valid'])+jump('before_restore')
    s+=label('producer_bad_pointer')+inc('bad_pointer')+jump('producer_sink')+label('producer_bad_depth')+inc('bad_depth')
    s+=label('producer_sink')+f'      I3 = {P.SINK:#x};\n      I13 = {P.SINK:#x};\n'
    s+=label('before_restore')+restore('before')+label('before_replay')+'      I0 = 0x12345678;\n      JUMP 0x1c265e;\n'

    s+=label('early_entry')+save('early')+'      R0 = 0;\n'+store(FIELDS['cycle_published'])+store(FIELDS['return_kind'])+jump('attempt_entry')

    s+=label('after_entry')+save('after')+'      R0 = 1;\n'+store(FIELDS['return_kind'])+inc('produced')
    s+=load(FIELDS['producer_valid'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('attempt_entry','IF EQ')
    s+=load(FIELDS['write_cursor'])+load(FIELDS['read_cursor'],'R1')+'      R2 = R0 - R1;\n      R1 = 3;\n      COMPU(R2, R1);\n'+jump('producer_full','IF GE')
    s+=meta_pointer('write_cursor')
    for offset,bus in ((0,'tdm'),(1,'spi')):
        s+=load(FIELDS['original_'+bus])+f'      R1 = {P.BUS[bus][2]:#x};\n      R0 = R0 XOR R1;\n      DM({offset}, I0) = R0;\n'
    s+=load(FIELDS['produced'])+'      DM(2, I0) = R0;\n      R0 = 0;\n      DM(3, I0) = R0;\n'+inc('enqueued')
    s+=label('enqueue_commit')+inc('write_cursor')+jump('attempt_entry')+label('producer_full')+inc('overflow')

    s+=label('attempt_entry')+inc('attempts')+load(FIELDS['cycle_published'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('attempt_restore','IF NE')
    s+=load(FIELDS['write_cursor'])+load(FIELDS['read_cursor'],'R1')+'      R2 = R0 - R1;\n'+store(FIELDS['last_depth'],'R2')
    s+='      R1 = 0;\n      COMP(R2, R1);\n'+jump('attempt_empty','IF EQ')+'      R1 = 3;\n      COMPU(R2, R1);\n'+jump('attempt_bad_depth','IF GT')
    s+=load(FIELDS['max_depth'])+'      COMPU(R2, R0);\n'+jump('depth_done','IF LE')+store(FIELDS['max_depth'],'R2')+label('depth_done')
    s+=slot_pointer('read_cursor','head_stage')+meta_pointer('read_cursor')
    for off,name in ((0,'tdm_target'),(1,'spi_target')):
        s+=f'      R0 = DM({off}, I0);\n'+store(G[name])
        pages=P.BUS[name.split('_')[0]][1]
        s+=f'      R1 = {pages[0]:#x};\n      COMP(R0, R1);\n'+jump('head_'+name+'_valid','IF EQ')
        s+=f'      R1 = {pages[1]:#x};\n      COMP(R0, R1);\n'+jump('attempt_bad_pointer','IF NE')+label('head_'+name+'_valid')
    s+='      R0 = DM(2, I0);\n'+store(FIELDS['head_sequence'])+clock('attempt',FIELDS['started'])
    s+='      R0 = 0;\n'+store(FIELDS['last_reason'])+store(FIELDS['cross_flags'])
    for bus in P.BUS:s+=snapshot('before',bus)+observe_consumption(bus)
    for bus in P.BUS:s+=validate('before',bus,'attempt_reject')
    for bus in P.BUS:
        s+=load(G[bus+'_target'])+load(FIELDS['last_'+bus],'R1')+'      COMP(R0, R1);\n'+jump('fresh_'+bus,'IF NE')
        s+=load(FIELDS['seen_'+bus])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('attempt_not_consumed','IF EQ')+label('fresh_'+bus)
    s+='      R0 = 1;\n'+store(FIELDS['cycle_published'])
    for bus in P.BUS:s+=load(G[bus+'_target'])+store(FIELDS['last_'+bus])+'      R0 = 0;\n'+store(FIELDS['seen_'+bus])
    s+='      L0 = 0;\n      L1 = 0;\n      M0 = 1;\n'
    s+=load(FIELDS['head_stage'],'I0')+load(G['tdm_target'],'I1')+'      R2 = 32;\n'+label('copy_tdm')
    s+=('      R0 = DM(I0, M0);\n      DM(I1, M0) = R0;\n')*14
    s+='      R1 = 8;\n      R0 = I0;\n      R0 = R0 + R1;\n      I0 = R0;\n      R0 = I1;\n      R0 = R0 + R1;\n      I1 = R0;\n      R2 = R2 - 1;\n'+jump('copy_tdm','IF NE')
    s+=load(FIELDS['head_stage'])+'      R1 = 0x81c;\n      R0 = R0 + R1;\n      I0 = R0;\n'+load(G['spi_target'])+'      R1 = 28;\n      R0 = R0 + R1;\n      I1 = R0;\n      R2 = 21;\n'+label('copy_spi')
    s+=('      R0 = DM(I0, M0);\n      DM(I1, M0) = R0;\n')*32
    s+='      R2 = R2 - 1;\n'+jump('copy_spi','IF NE')+clock('finish',FIELDS['last_elapsed'])
    s+=load(FIELDS['last_elapsed'])+load(FIELDS['started'],'R1')+'      R0 = R0 - R1;\n'+store(FIELDS['last_elapsed'])+load(FIELDS['max_elapsed'],'R1')+'      COMPU(R0, R1);\n'+jump('max_done','IF LE')+store(FIELDS['max_elapsed'])+label('max_done')
    s+=f'      R1 = {P.MAX_ELAPSED};\n      COMPU(R0, R1);\n'+jump('elapsed_ok','IF LT')+'      R0 = 4;\n'+store(FIELDS['cross_flags'])+label('elapsed_ok')
    for bus,bit in (('tdm',1),('spi',2)):
        s+=snapshot('after',bus)+validate('after',bus,bus+'_cross')+jump(bus+'_checked')
        s+=label(bus+'_cross')+load(FIELDS['cross_flags'])+f'      R1 = {bit};\n      R0 = R0 OR R1;\n'+store(FIELDS['cross_flags'])+label(bus+'_checked')
    s+=load(FIELDS['cross_flags'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('attempt_crossed','IF NE')
    s+=load(FIELDS['head_sequence'])+store(FIELDS['last_sequence'])+inc('committed')+label('dequeue_commit')+inc('read_cursor')+jump('attempt_restore')
    for name,counter in (('empty','empty'),('bad_depth','bad_depth'),('bad_pointer','bad_pointer'),('reject','rejected'),('not_consumed','freshness_deferred'),('crossed','crossed')):
        s+=label('attempt_'+name)+inc(counter)+jump('attempt_restore')
    s+=label('attempt_restore')+load(FIELDS['return_kind'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('after_restore','IF NE')
    s+=restore('early')+label('early_replay')+'      I0 = 0x12345678;\n      I0 = 0x12345678;\n      JUMP 0x1c9f1a;\n'
    s+=label('after_restore')+load(FIELDS['original_spi'],'I13')+load(FIELDS['original_spi'])+'      R1 = 112;\n      R0 = R0 + R1;\n      I4 = R0;\n'+restore('after')+label('after_replay')+'      I0 = 0x12345678;\n      JUMP 0x1c26f2;\n'
    for n,(phase,bus,_) in R.REASONS.items():
        if n<=2:continue
        s+=label('reason_'+str(n))+f'      R0 = {n};\n'+store(FIELDS['last_reason'])+jump('attempt_reject' if phase=='before' else bus+'_cross')

    # Existing phase-15 scalar publisher envelope; native reply words retained.
    s+=label('publication_entry')+save('publication')+load(FIELDS['publication_phase'])
    pairs=(('produced','committed'),('last_depth','max_depth'),('rejected','overflow'),
           ('crossed','last_elapsed'),('last_sequence','freshness_deferred'),('last_reason','bad_depth'))
    for i in range(len(pairs)-1):s+=f'      R1 = {i};\n      COMP(R0, R1);\n'+jump('publication_'+str(i),'IF EQ')
    s+=jump('publication_'+str(len(pairs)-1))
    for i,(a,b) in enumerate(pairs):
        s+=label('publication_'+str(i))+f'      R0 = {(i+1)%len(pairs)};\n'+store(FIELDS['publication_phase'])
        s+=P.P.Q.P.D.P.publish(FIELDS[a],12)+P.P.Q.P.D.P.publish(FIELDS[b],16)
        s+=restore('publication')+f'      I0 = {((0xdc22+i)<<16)|0x4f53:#x};\n      JUMP 0xbf2676;\n'
    return s


def memory_audit(raw):
    E = P.P.E
    loaded = C.B.load_regions(raw)
    def read_at(address, size):
        return next(data[address-start:address-start+size] for start,data in loaded
                    if start<=address and address+size<=start+len(data))
    regions=((SLOT_BASE,SLOT_END),(PHYSICAL,CODE_END),(STATE,STATE_END))
    for lo,hi in regions:
        assert not any(b.target<hi and lo<b.target+b.count for b in C.B.walk(raw).blocks),(hex(lo),hex(hi))
        assert not any(E.literals(raw,lo,hi)),('physical literal',hex(lo))
    assert E.literals(raw,0xbd8000,0xbda800)==([0x2838d612],[0x200ada80])
    # Pin whole containing instructions: these raw alias coincidences are
    # instruction fields, not pointers into the proposed staging storage.
    aliases = [dict(hit='0x2838d612', instruction='0x2838d60e',
                    bytes='be6e1316bd00', meaning='F0 = F11 * F13; DM(I7 + 2) = R12'),
               dict(hit='0x200ada80', instruction='0x200ada80',
                    bytes='c09fbd00426d', meaning='DM(I7, M7) = 0xbd6d42; continuation outside staging')]
    for item in aliases:
        assert read_at(int(item['instruction'],16),6)==bytes.fromhex(item['bytes']), item
    assert not any(E.literals(raw,CODE,0xbe9e00))
    assert not any(E.literals(raw,0xbed800,0xbedc00))
    return dict(regions=[[hex(a),hex(b)] for a,b in regions],loaded_overlap=False,
                physical_literal_hits=0,code_state_alias_hits=0,
                classified_stage_alias_hits=aliases,
                cache='CPU-only L2 staging under stock cache policy; DMA still reads existing L1 pages.',
                limit='Loaded/reference closure does not prove arbitrary computed writers absent.')


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    doc=json.loads(BASE.with_name('build-receipt.json').read_text())
    audit=memory_audit(raw)
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    m=B.decode_view(k,raw)
    originals={name:m.read_sw(pc,size) for name,pc,size,_ in HOOKS}
    assert m.read_sw(0x1c9f12,6)==C.S.to_bytes(0x063e00bf2a80)
    assert k.st.decode_at(m,None,0x1c9f15).length_bytes==4
    assert k.st.decode_at(m,None,0x1c9f17).length_bytes==6
    out.mkdir(parents=True,exist_ok=False)
    asm=out/'usb-retained.asm';s=source();asm.write_text(s)
    obj,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'usb-retained.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);obj,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(obj));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])}
    fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
        if v>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
    for name in SAVES:
        at=2*(labels[name+'_mode.']-CODE);assert widths[at]==6
        code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
    for name in ('attempt','finish'):
        at=2*(labels[name+'_clock.']-CODE);assert widths[at]==6
        code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['EMUCLK']))
    for name,word in (('before',0x1596ffffff82),('after',0x142200002000)):
        at=2*(labels[name+'_replay.']-CODE);assert widths[at]==6
        code[at:at+6]=C.S.to_bytes(word)
    # Two placeholders occupy twelve bytes; native displaced pair occupies ten.
    at=2*(labels['early_replay.']-CODE)
    assert widths[at]==widths[at+6]==6
    code[at:at+12]=originals['early']+bytes.fromhex('0100')
    offsets=sorted((set(offsets)-{at+6})|{at+4,at+10})
    assert PHYSICAL+len(code)<=CODE_END,(len(code),CODE_END-PHYSICAL)
    image=bytearray(raw);hooks=[]
    for name,pc,size,resume in HOOKS:
        physical=C.S.code_address(pc,window='l2' if pc>=0xb80000 else 'l1')
        patch=C.S.to_bytes(0x063e00000000|labels[name+'_entry.'])+bytes.fromhex('0100')*((size-6)//2)
        C.B.write_span(image,physical,patch)
        hooks.append(dict(name=name,site=hex(pc),physical=hex(physical),entry=hex(labels[name+'_entry.']),resume=hex(resume),before=originals[name].hex(),after=patch.hex()))
    blocks=[(PHYSICAL,bytes(code)),(STATE,bytes(STATE_END-STATE)),(SLOT_BASE,bytes(SLOT_END-SLOT_BASE))]
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    w=C.B.walk(result);first,last=w.blocks[7],w.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['usb_retained']=dict(base_sha256=BASE_SHA,code=hex(CODE),code_physical=hex(PHYSICAL),code_bytes=len(code),instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},hooks=hooks,
        state=hex(STATE),state_bytes=STATE_END-STATE,fields={n:hex(v) for n,v in FIELDS.items()},guard_targets={n:hex(v) for n,v in G.items()},guard_snapshots={n:hex(v) for n,v in F.items()},
        scratch={n:{r:hex(a) for r,a in p.items()} for n,p in SAVES.items()},slots=[hex(a) for a in SLOTS],slot_bytes=SLOT_BYTES,spi_offset=SPI_OFFSET,metadata=hex(META),metadata_bytes_per_slot=16,capacity=CAPACITY,
        encoding_fixes=fixes,memory_audit=audit,
        guard='Exact R008 canonical/START-CURRENT-COUNT-START predicates and bounds; COUNT1 remains owned. Post-copy checks and 100000-cycle elapsed ceiling retained.',
        queue='Single normal-task owner; producer writes fourth private slot and commits cursor last. FIFO consumes only oldest pair after joint checks and copy. Rejection retains it; full queue drops new block explicitly, never overwrites queued blocks.',
        attempts='After native headphone codec commit and after complete native USB export; at most one copy per render. Same target cannot be rewritten until DMA was observed consuming that bus page since its prior copy.',
        copies=dict(tdm_words=448,tdm_stride_bytes=64,tdm_frames=32,spi_words=672,spi_offset=28,native_prefix_trailer_untouched=True),
        publication=dict(phase=15,tags={hex(0x4f53dc22+i):list(pair) for i,pair in enumerate((('produced','committed'),('last_depth','max_depth'),('rejected','overflow'),('crossed','last_elapsed'),('last_sequence','freshness_deferred'),('last_reason','bad_depth')))}),
        unchanged=['Native USB sample conversion/channel arithmetic','Headphone codec commit before new early work','Native SPI/DMA descriptor configuration and completion callbacks','Control-frame parsing, ordering, note and release events','CF collection and USB packet writer'],
        limits=['Hardware timing/USB continuity remain unverified.','Finite capacity cannot absorb unbounded DMA unavailability; overflow is counted.','Post-check observes but cannot undo a DMA crossing during copy; admission is not a hardware lock.','Additional USB block latency depends on queue depth and available DMA windows.','R008 journal publisher is replaced by R010 retention counters; old observer data/code remain inert.'])
    doc['usb_guard_reasons']['superseded_by']='usb_retained; R008 executable observer remains loaded but hooks are replaced'
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(sha256=C.SHA(result),code_bytes=len(code),slots=[hex(a) for a in SLOTS]),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True)
    build(ap.parse_args().out)
