#!/usr/bin/env python3
"""R008: classify exact R007 USB guard decisions; no publication-policy change."""
from pathlib import Path
import argparse
import json
import re

import build_dt2_usb_guarded_publication as P

C,B,A,O,T=P.C,P.B,P.A,P.O,P.T
BASE=C.ROOT/'output/dn2-research/usb-guard-r007-20261101/dsp/section_7.bin'
BASE_SHA='681a0800b66fb046407b6cf8730cf66de7f1a7640ba7bb78cc9e4e15dab0103b'
CODE,PHYSICAL,CODE_END,STATE,END=P.CODE,P.PHYSICAL,P.CODE_END,P.STATE,P.END
MAGIC=0x55475238
label,jump,load,store,inc=P.label,P.jump,P.load,P.store,P.inc
D={n:STATE+0x150+4*i for i,n in enumerate((
    'reason','reason_count','bus','kind','post_reason','post_reason_count','post_bus',
    'tdm_after_clock','spi_after_clock','event_clock','window','window_valid',
    'next_kind','snapshot_kind','snapshot_sequence','chunk','hold','cycle',
    'pub_i4','pub_l4','pub_l0','journal_i4','journal_l4','journal_l0','field_value','pub_r3'))}
COUNTERS=STATE+0x200
REJECT,POST,SNAP,ZERO=(STATE+x for x in (0x2a0,0x310,0x380,0x3f0))
EVENT_FIELDS=('snapshot_sequence event_sequence reason reason_count original_i3 original_i13 '
              'tdm_target spi_target before_start before_current before_count before_start_again '
              'after_start after_current after_count after_start_again active_callback event_callback '
              'started finished after_snapshot_clock event_clock accepted rejected crossed cross_flags '
              'valid_mask checksum').split()
COUNTER_FIELDS=['snapshot_sequence','callback','accepted','rejected','crossed','max_elapsed','first_reason_id']+[f'reason_{i}' for i in range(20)]+['checksum']
BEFORE_REASONS=('start_bracket','unknown_start','other_count_below_floor','other_count_above_max',
                'other_current_below_start','other_current_at_or_past_end','target_count_not_zero','target_current_not_end')
AFTER_REASONS=BEFORE_REASONS[:6]+('same_start_count_reload',)+BEFORE_REASONS[6:]+('newly_drained_start','newly_drained_count')
REASONS={1:('before','tdm','noncanonical_destination'),2:('before','spi','noncanonical_destination')}
for phase,bus,start,names in (('before','tdm',3,BEFORE_REASONS),('before','spi',11,BEFORE_REASONS),
                            ('after','tdm',19,AFTER_REASONS),('after','spi',30,AFTER_REASONS)):
    REASONS.update({start+i:(phase,bus,n) for i,n in enumerate(names)})
assert len(REASONS)==40 and max(D.values())+4<=COUNTERS and ZERO+48<=END


def snapshot(phase,bus):
    s=_snapshot(phase,bus)
    if phase=='after':s+=P.clock(bus+'_sample',D[bus+'_after_clock'])
    return s


def validate(phase,bus,bad):
    s=_validate(phase,bus,bad)
    ids=[n for n,(p,b,_) in REASONS.items() if p==phase and b==bus and n>2]
    matches=list(re.finditer(r'(?m)^.*JUMP 0x0; // -> '+re.escape(bad)+r'\.\n',s))
    assert len(matches)==len(ids),(phase,bus,len(matches),ids)
    for match,n in reversed(list(zip(matches,ids))):
        s=s[:match.start()]+match.group().replace('// -> '+bad+'.','// -> reason_'+str(n)+'.')+s[match.end():]
    return s


def journal():
    """Failure-only bounded copy, sharing the native task's scalar envelope."""
    s=label('journal_entry')+store(D['journal_i4'],'I4')+store(D['journal_l4'],'L4')+store(D['journal_l0'],'L0')
    s+=P.clock('event',D['event_clock'])+'      L0 = 0;\n      L4 = 0;\n      NOP;\n'
    s+=load(D['kind'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('journal_post','IF NE')
    s+=f'      I0 = {REJECT:#x};\n      R0 = I3;\n      DM(4, I0) = R0;\n'+load(P.G['rejected'])+'      DM(1, I0) = R0;\n'+jump('journal_common')
    s+=label('journal_post')+f'      I0 = {POST:#x};\n'+load(P.G['tdm_target'])+'      R1 = 0x1800;\n      R0 = R0 XOR R1;\n      DM(4, I0) = R0;\n'+load(P.G['crossed'])+'      DM(1, I0) = R0;\n'
    s+=label('journal_common')
    fields={2:D['reason'],3:D['reason_count'],5:P.G['original_i13'],6:P.G['tdm_target'],7:P.G['spi_target'],
            16:P.P.ACTIVE_CALLBACK,17:P.P.CALLBACK,18:P.G['started'],19:P.G['finished'],21:D['event_clock'],
            22:P.G['accepted'],23:P.G['rejected'],24:P.G['crossed'],25:P.G['cross_flags']}
    for field,address in fields.items():s+=load(address)+f'      DM({field}, I0) = R0;\n'
    s+=load(D['bus'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('journal_no_bus','IF EQ')
    s+='      R1 = 1;\n      COMP(R0, R1);\n'+jump('journal_spi','IF NE')
    s+=f'      I4 = {P.F["before_tdm_start"]:#x};\n'+load(D['tdm_after_clock'])+jump('journal_tuple')
    s+=label('journal_spi')+f'      I4 = {P.F["before_spi_start"]:#x};\n'+load(D['spi_after_clock'])+jump('journal_tuple')
    s+=label('journal_no_bus')+f'      I4 = {ZERO:#x};\n      R0 = 0;\n'
    s+=label('journal_tuple')+'      DM(20, I0) = R0;\n'
    for i in range(4):s+=f'      R0 = DM({i}, I4);\n      DM({8+i}, I0) = R0;\n      R0 = DM({8+i}, I4);\n      DM({12+i}, I0) = R0;\n'
    # Targets/tuple/timing validity is explicit; a rejected early branch leaves
    # later parent snapshot cells stale. Never represent those as current reads.
    s+=load(D['kind'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('journal_post_mask','IF NE')
    s+=load(D['reason'])+'      R1 = 1;\n      COMP(R0, R1);\n'+jump('journal_canonical_tdm','IF EQ')
    s+='      R1 = 2;\n      COMP(R0, R1);\n'+jump('journal_canonical_spi','IF EQ')
    s+='      R0 = 0x0f;\n'+jump('journal_mask')
    s+=label('journal_canonical_tdm')+'      R0 = 1;\n'+jump('journal_mask')
    s+=label('journal_canonical_spi')+'      R0 = 3;\n'+jump('journal_mask')
    s+=label('journal_post_mask')+'      R0 = 0x3f;\n'+load(D['bus'],'R1')+'      R2 = 0;\n      COMP(R1, R2);\n'+jump('journal_mask','IF NE')+'      R0 = 0x27;\n'
    s+=label('journal_mask')+'      DM(26, I0) = R0;\n'+load(D['journal_l0'],'L0')+load(D['journal_l4'],'L4')+load(D['journal_i4'],'I4')
    s+=load(D['kind'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('after_restore','IF NE')+jump('reject_sink')
    return s


def publication():
    # Parent BF2350 envelope already saves all arithmetic/status and I0. Only
    # bounded indexed snapshot accesses need these additional pointer saves.
    s=label('publication_entry')+store(D['pub_i4'],'I4')+store(D['pub_l4'],'L4')+store(D['pub_l0'],'L0')+store(D['pub_r3'],'R3')
    s+='      L0 = 0;\n      L4 = 0;\n      NOP;\n'
    hb=P.P.Q.P.D.P.P.HEARTBEAT
    s+=load(hb)+'      R0 = LSHIFT R0 BY -14;\n'+load(D['window'],'R1')+'      COMP(R0, R1);\n'+jump('publication_new_window','IF NE')
    s+=load(D['window_valid'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('publication_ready','IF NE')
    s+=label('publication_new_window')+load(hb)+'      R0 = LSHIFT R0 BY -14;\n'+store(D['window'])+'      R0 = 1;\n'+store(D['window_valid'])
    s+='      R0 = 0;\n'+store(D['chunk'])+store(D['hold'])+store(D['cycle'])
    s+=inc(D['snapshot_sequence'])+load(D['next_kind'])+store(D['snapshot_kind'])+'      R1 = 1;\n      R0 = R0 + R1;\n      R1 = 3;\n      R0 = R0 AND R1;\n'+store(D['next_kind'])
    s+=load(D['snapshot_kind'])+'      R1 = 2;\n      COMPU(R0, R1);\n'+jump('publication_counters','IF GE')
    s+='      R1 = 0;\n      COMP(R0, R1);\n'+jump('publication_post','IF NE')+f'      I4 = {REJECT:#x};\n'+jump('publication_copy')
    s+=label('publication_post')+f'      I4 = {POST:#x};\n'+label('publication_copy')
    s+=f'      I0 = {SNAP:#x};\n      R2 = 27;\n'+label('publication_copy_word')
    s+='      R0 = DM(0, I4);\n      DM(0, I0) = R0;\n      R0 = I4;\n      R1 = 4;\n      R0 = R0 + R1;\n      I4 = R0;\n      R0 = I0;\n      R0 = R0 + R1;\n      I0 = R0;\n      R2 = R2 - 1;\n'+jump('publication_copy_word','IF NE')
    s+=jump('publication_checksum')+label('publication_counters')
    for i,a in enumerate((D['snapshot_sequence'],P.P.CALLBACK,P.G['accepted'],P.G['rejected'],P.G['crossed'],P.G['max_elapsed'])):s+=load(a)+store(SNAP+4*i)
    s+=load(D['snapshot_kind'])+'      R1 = 2;\n      COMP(R0, R1);\n'+jump('publication_counts_b','IF NE')+f'      I4 = {COUNTERS:#x};\n      R0 = 1;\n'+jump('publication_counts_selected')
    s+=label('publication_counts_b')+f'      I4 = {COUNTERS+80:#x};\n      R0 = 21;\n'+label('publication_counts_selected')+store(SNAP+24)
    s+=f'      I0 = {SNAP+28:#x};\n      R2 = 20;\n'+jump('publication_copy_word')
    s+=label('publication_checksum')+load(D['snapshot_sequence'])+store(SNAP)+f'      R0 = {MAGIC:#x};\n'+load(D['snapshot_kind'],'R1')+'      R0 = R0 XOR R1;\n'+f'      I4 = {SNAP:#x};\n      R3 = 27;\n'+label('publication_hash_word')
    s+='      R1 = LSHIFT R0 BY 5;\n      R0 = LSHIFT R0 BY -27;\n      R0 = R0 OR R1;\n      R2 = DM(0, I4);\n      R0 = R0 XOR R2;\n      R2 = I4;\n      R1 = 4;\n      R2 = R2 + R1;\n      I4 = R2;\n      R3 = R3 - 1;\n'+jump('publication_hash_word','IF NE')
    s+=store(SNAP+108)+label('publication_ready')+load(D['chunk'])
    for n in range(3):s+=f'      R1 = {n};\n      COMP(R0, R1);\n'+jump(f'publication_legacy_{n}','IF EQ')
    s+='      R1 = 3;\n      R2 = R0 - R1;\n      R0 = LSHIFT R2 BY 2;\n'+f'      R1 = {SNAP:#x};\n      R0 = R0 + R1;\n      I4 = R0;\n      R0 = DM(0, I4);\n'+store(D['field_value'])
    s+=P.P.Q.P.D.P.publish(D['field_value'],16)+P.P.Q.P.D.P.publish(SNAP,12)
    s+=load(D['chunk'],'R2')+'      R1 = 3;\n      R2 = R2 - R1;\n'+load(D['snapshot_kind'])+'      R0 = LSHIFT R0 BY 8;\n      R0 = R0 OR R2;\n'+load(D['cycle'],'R1')+'      R1 = LSHIFT R1 BY 5;\n      R0 = R0 OR R1;\n      R1 = 0x4f53e800;\n      R0 = R0 OR R1;\n'+P.P.rotate()+'      I0 = R0;\n'+jump('publication_advance')
    for n,(tag,a,b) in enumerate(((0xdc1f,0x200e654c,0x200e6554),(0xdc20,P.G['accepted'],P.G['rejected']),(0xdc21,P.G['crossed'],P.G['max_elapsed']))):
        s+=label(f'publication_legacy_{n}')+P.P.Q.P.D.P.publish(a,12)+P.P.Q.P.D.P.publish(b,16)+f'      I0 = {(tag<<16)|0x4f53:#x};\n'+jump('publication_advance')
    s+=label('publication_advance')+inc(D['hold'])+'      R1 = 15;\n      R0 = R0 AND R1;\n'+store(D['hold'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('publication_restore','IF NE')
    s+=inc(D['chunk'])+'      R1 = 31;\n      COMP(R0, R1);\n'+jump('publication_restore','IF NE')+'      R0 = 0;\n'+store(D['chunk'])
    s+=load(D['cycle'])+'      R1 = 1;\n      R0 = R0 XOR R1;\n'+store(D['cycle'])
    s+=label('publication_restore')+load(D['pub_l0'],'L0')+load(D['pub_l4'],'L4')+load(D['pub_i4'],'I4')+load(D['pub_r3'],'R3')+'      JUMP 0xbf2676;\n'
    return s


def source():
    # Generate the parent's unchanged predicates; substitute only failure
    # destinations, plus timestamp/private observer code outside comparisons.
    original_validate,original_snapshot=P.validate,P.snapshot
    try:
        P.validate=validate;P.snapshot=snapshot
        # Wrappers call the originals through these temporary globals.
        globals()['_validate']=original_validate;globals()['_snapshot']=original_snapshot
        s=P.source()
    finally:P.validate=original_validate;P.snapshot=original_snapshot
    s=s[:s.index(label('publication_entry'))]
    # Canonical failures precede validate(), in the original pointer checks.
    for n in (1,2):s=s.replace('// -> reject.','// -> reason_'+str(n)+'.',1)
    s=s.replace(label('reject')+inc(P.G['rejected']),label('reject')+inc(P.G['rejected'])+'      R0 = 0;\n'+store(D['kind'])+jump('journal_entry')+label('reject_sink'))
    needle=load(P.G['finished'])+load(P.G['started'],'R1')
    s=s.replace(needle,'      R0 = 0;\n'+store(D['post_reason'])+store(D['post_reason_count'])+store(D['post_bus'])+needle)
    s=s.replace(inc(P.G['crossed']),inc(P.G['crossed'])+load(D['post_reason'])+store(D['reason'])+load(D['post_reason_count'])+store(D['reason_count'])+load(D['post_bus'])+store(D['bus'])+'      R0 = 1;\n'+store(D['kind'])+jump('journal_entry'))
    s+=journal()+publication()
    for n,(phase,bus,_) in REASONS.items():
        s+=label('reason_'+str(n))+inc(COUNTERS+4*(n-1))
        if phase=='after':
            s+=store(D['reason_count'])+load(D['post_reason'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('reason_resume_'+str(n),'IF NE')
            s+=load(D['reason_count'])+store(D['post_reason_count'])+f'      R0 = {n};\n'+store(D['post_reason'])+f'      R0 = {1 if bus=="tdm" else 2};\n'+store(D['post_bus'])
            s+=label('reason_resume_'+str(n))+jump(bus+'_cross')
        else:
            s+=store(D['reason_count'])+f'      R0 = {n};\n'+store(D['reason'])+f'      R0 = {0 if n<=2 else (1 if bus=="tdm" else 2)};\n'+store(D['bus'])+jump('reject')
    return s


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    doc=json.loads(BASE.with_name('build-receipt.json').read_text());parent=doc['usb_guarded_publication']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
    out.mkdir(parents=True,exist_ok=False);asm=out/'usb-guard-reasons.asm';s=source();asm.write_text(s)
    obj,offsets=A._selas(asm,out);labels={n:CODE+v for n,v in O.symbols((out/'usb-guard-reasons.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);obj,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(obj));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        value=C.S.to_value(code[off:off+6]);reg=(value>>32)&0x7f
        if value>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((value&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
    for name,reg in [('before_mode','MODE1'),('after_mode','MODE1')]+[(n+'_clock','EMUCLK') for n in ('before','after','tdm_sample','spi_sample','event')]:
        at=2*(labels[name+'.']-CODE);assert widths[at]==6;code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES[reg]))
    for name,_,word,_ in P.HOOKS[:2]:
        at=2*(labels[name+'_replay.']-CODE);assert widths[at]==6;code[at:at+6]=C.S.to_bytes(word)
    assert PHYSICAL+len(code)<=CODE_END,('code reservation',len(code),CODE_END-PHYSICAL)
    image=bytearray(raw);hooks=[]
    for old in parent['hooks']:
        name=old['name'];physical=int(old['physical'],16);before=bytes.fromhex(old['after']);assert m.read_sw(int(old['site'],16),6)==before
        after=C.S.to_bytes(0x063e00000000|labels[name+'_entry.']);C.B.write_span(image,physical,after)
        hooks.append(dict(name=name,site=old['site'],physical=old['physical'],entry=hex(labels[name+'_entry.']),resume=old['resume'],before=before.hex(),after=after.hex()))
    blocks=C.B.walk(bytes(image)).blocks;owner=[b for b in blocks if b.target==PHYSICAL];assert len(owner)==1
    owner=owner[0];assert owner.count==parent['code_bytes']
    result=bytes(image[:owner.offset])+C.B.block(PHYSICAL,bytes(code))+bytes(image[owner.end:])
    w=C.B.walk(result);first,last=w.blocks[7],w.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:];assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['usb_guard_reasons']=dict(base=str(BASE),base_sha256=BASE_SHA,code=hex(CODE),code_physical=hex(PHYSICAL),code_bytes=len(code),instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},hooks=hooks,
        state=hex(STATE),state_bytes=END-STATE,fields={n:hex(v) for n,v in D.items()},reason_counters=hex(COUNTERS),reason_map={str(n):dict(phase=p,bus=b,predicate=r,address=hex(COUNTERS+4*(n-1))) for n,(p,b,r) in REASONS.items()},
        records={'reject':hex(REJECT),'post':hex(POST),'snapshot':hex(SNAP)},record_fields=EVENT_FIELDS,counter_fields=COUNTER_FIELDS,record_bytes=112,encoding_fixes=fixes,
        publication=dict(schema='R008-UGR8-v1',phase=15,marker_base='0x4f53e800',marker_mask='0xfffffcc0',kind_shift=8,kind_mask=3,cycle_shift=5,field_mask=31,fields=28,hold_calls=16,slots_per_cycle=31,legacy_slots=3,kind_order=['reject','post','counterA','counterB'],word3='immutable snapshot sequence',word4='field value',checksum_seed=hex(MAGIC),checksum='seed XOR kind, then ROL32(acc,5) XOR word for words0..26',latch='one immutable snapshot per heartbeat>>14 phase15 window; unique snapshot sequence; no midwindow replacement',read_rule='Require28fields,word0==echoedsequence,validchecksum,no conflicting duplicates. Completebothcyclemasks upgrades to repeated_matching; incomplete remains unavailable.',retained=['DC10..DC1D','DC1F','DC20','DC21','native header words0/2/5/6 and S0 effects'],recorder='unchanged native BF53B0 gate'),
        valid_mask={'1':'original pointers present','2':'TDM target valid','4':'SPI target valid','8':'selected before tuple valid','16':'selected after tuple and sample clock valid','32':'finished clock and cross flags valid'},
        unchanged=['R007 branch predicates and admission decisions','canonical successor target mapping','native audio loops and rejection sink','codec and control ordering','DMA descriptors and configuration','MMIO read set/order'],
        historical_replay={'r006_capture01':{'banks':14,'predicate_rejects':0},'r006_capture02':{'banks':18,'first_tdm_count_below_256':5,'counts':[52,63,80,50,129]},'limit':'Historical R006 per-bus boundaries differ from R007 joint boundaries; does not identify current R007 rejects or postfailures.'},
        limits=['Observation adds bounded execution cost and can change timing.','No policy fix until live branch evidence.','START/current/count snapshots are not atomic ownership fences.','Post-snapshot timestamp exposes delay after export clock; no IRQ lock or precise memory completion claim.','Native SPI work-unit completion gives released-page evidence, but paired staged-publication redesign is deferred.','Counter banks are independently timed phase15 snapshots.','Literal/known-owner closure inherited R007; arbitrary computed writers remain unproven.'])
    for key in ('code','code_physical','code_bytes','instruction_offsets','labels','hooks','encoding_fixes'):
        doc['usb_guarded_publication'].pop(key,None)
    doc['usb_guarded_publication']['superseded_by']='usb_guard_reasons; data layout and policy retained, executable region replaced'
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(ok=True,sha256=C.SHA(result),code_bytes=len(code),instructions=len(offsets)),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
