#!/usr/bin/env python3
"""R007: publish USB audio to guarded native successor pages; exact R005 parent."""
from pathlib import Path
import argparse
import json
import re
import collections

import build_dt2_usb_publication_timing as P
import audit_dn2_dsp_encoding as E

C,B,A,O,T=P.C,P.B,P.A,P.O,P.T
BASE,BASE_SHA=P.BASE,P.BASE_SHA
CODE,PHYSICAL,CODE_END,STATE,END=P.CODE,P.PHYSICAL,P.CODE_END,P.STATE,P.END
SINK,SINK_END=0x200f9000,0x200fa000
MAX_ELAPSED=100000
REGS=('I0','MODE1','R0','R1','R2','ASTATX','ASTATY')
SAVE={r:STATE+4*i for i,r in enumerate(REGS)}
G={n:STATE+0x40+4*i for i,n in enumerate((
    'original_i13','tdm_target','spi_target','armed','accepted','rejected','crossed',
    'started','finished','last_elapsed','max_elapsed','publication_phase','cross_flags'))}
F={f'{phase}_{bus}_{field}':STATE+0x100+4*i for i,(phase,bus,field) in enumerate(
    (phase,bus,field) for phase in ('before','after') for bus in ('tdm','spi')
    for field in ('start','current','count','start_again'))}
BUS={'tdm':(0x31022000,(0x2c08e8,0x2c10e8),0x1800,2048,256,512),
     'spi':(0x3102d200,(0x2c49d0,0x2c59d0),0x1000,2748,512,1374)}
HOOKS=(('before',0x1c265b,0x1596ffffff82,0x1c265e),
       ('after',0x1c26ef,0x142200002000,0x1c26f2),
       ('publication',0xbf264c,0x1000200e5320,0xbf2676))
label,jump,load,store,inc=P.label,P.jump,P.load,P.store,P.inc


def save(name):
    return (store(SAVE['I0'],'I0')+label(name+'_mode')+'      I0 = 0x12345678;\n'+
            store(SAVE['MODE1'],'I0')+'      BIT CLR MODE1 0x202000;\n      NOP;\n      NOP;\n'+
            ''.join(store(SAVE[r],r) for r in REGS[2:]))


def restore():
    return ''.join(load(SAVE[r],r) for r in (*REGS[2:],'MODE1','I0'))


def clock(name,address):
    return label(name+'_clock')+'      I0 = 0x12345678;\n'+store(address,'I0')


def snapshot(phase,bus):
    dma=BUS[bus][0]
    return ''.join(label(f'{phase}_{bus}_{field}')+load(dma+offset)+store(F[f'{phase}_{bus}_{field}'])
                   for field,offset in (('start',4),('current',0x2c),('count',0x34),('start_again',4)))


def validate(phase,bus,bad):
    """Validate scalar snapshot and target lifetime, with explicit drained case."""
    _,pages,mask,size,minimum,maximum=BUS[bus]
    prefix=f'{phase}_{bus}';f=lambda key:F[f'{prefix}_{key}']
    s=load(f('start'))+load(f('start_again'),'R1')+'      COMP(R0, R1);\n'+jump(bad,'IF NE')
    s+=load(G[bus+'_target'],'R2')+'      R1 = 0x28000000;\n      R2 = R2 + R1;\n      COMP(R0, R2);\n'+jump(prefix+'_drained','IF EQ')
    s+=f'      R1 = {mask:#x};\n      R2 = R2 XOR R1;\n      COMP(R0, R2);\n'+jump(bad,'IF NE')
    s+=load(f('count'))+f'      R1 = {minimum if phase=="before" else 1};\n      COMPU(R0, R1);\n'+jump(bad,'IF LT')
    s+=f'      R1 = {maximum};\n      COMPU(R0, R1);\n'+jump(bad,'IF GT')
    s+=load(f('current'))+'      COMPU(R0, R2);\n'+jump(bad,'IF LT')
    s+=f'      R1 = {size};\n      R2 = R2 + R1;\n      COMPU(R0, R2);\n'+jump(bad,'IF GE')
    if phase=='after':
        s+=load(f('start'))+load(F[f'before_{bus}_start'],'R1')+'      COMP(R0, R1);\n'+jump(prefix+'_ok','IF NE')
        s+=load(f('count'))+load(F[f'before_{bus}_count'],'R1')+'      COMPU(R0, R1);\n'+jump(bad,'IF GT')
    s+=jump(prefix+'_ok')+label(prefix+'_drained')
    s+=load(f('count'))+'      R1 = 0;\n      COMP(R0, R1);\n'+jump(bad,'IF NE')
    s+=load(f('current'))+f'      R1 = {size};\n      R2 = R2 + R1;\n      COMP(R0, R2);\n'+jump(bad,'IF NE')
    if phase=='after':
        # Only continued drained ownership is safe; a whole newly-read target
        # completing during this export is a crossing, even if COUNT is zero.
        s+=load(f('start'))+load(F[f'before_{bus}_start'],'R1')+'      COMP(R0, R1);\n'+jump(bad,'IF NE')
        s+=load(F[f'before_{bus}_count'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump(bad,'IF NE')
    return s+label(prefix+'_ok')


def source():
    s='.SECTION/PM seg_pmco;\n'+label('before_entry')+save('before')+clock('before',G['started'])
    s+=store(G['original_i13'],'I13')+'      R0 = 0;\n'+store(G['armed'])+store(G['cross_flags'])
    for bus,reg in (('tdm','I3'),('spi','I13')):
        _,pages,mask,_,_,_=BUS[bus]
        s+=f'      R0 = {reg};\n      R1 = {pages[0]:#x};\n      COMP(R0, R1);\n'+jump(bus+'_canonical','IF EQ')
        s+=f'      R1 = {pages[1]:#x};\n      COMP(R0, R1);\n'+jump('reject','IF NE')+label(bus+'_canonical')
        s+=f'      R1 = {mask:#x};\n      R0 = R0 XOR R1;\n'+store(G[bus+'_target'])
    for bus in BUS:s+=snapshot('before',bus)+validate('before',bus,'reject')
    s+=inc(G['accepted'])+'      R0 = 1;\n'+store(G['armed'])
    s+=load(G['tdm_target'],'I3')+load(G['spi_target'],'I13')+jump('before_restore')
    s+=label('reject')+inc(G['rejected'])+f'      I3 = {SINK:#x};\n      I13 = {SINK:#x};\n'
    s+=label('before_restore')+restore()+label('before_replay')+'      I0 = 0x12345678;\n      JUMP 0x1c265e;\n'

    s+=label('after_entry')+save('after')+clock('after',G['finished'])
    s+=load(G['armed'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('after_restore','IF EQ')
    s+=load(G['finished'])+load(G['started'],'R1')+'      R0 = R0 - R1;\n'+store(G['last_elapsed'])
    s+=load(G['max_elapsed'],'R1')+'      COMPU(R0, R1);\n'+jump('elapsed_max_done','IF LE')+store(G['max_elapsed'])+label('elapsed_max_done')
    s+=f'      R1 = {MAX_ELAPSED};\n      COMPU(R0, R1);\n'+jump('elapsed_ok','IF LT')
    s+='      R0 = 4;\n'+store(G['cross_flags'])+label('elapsed_ok')
    for bus,bit in (('tdm',1),('spi',2)):
        s+=snapshot('after',bus)+validate('after',bus,bus+'_cross')+jump(bus+'_checked')
        s+=label(bus+'_cross')+load(G['cross_flags'])+f'      R1 = {bit};\n      R0 = R0 OR R1;\n'+store(G['cross_flags'])+label(bus+'_checked')
    s+=load(G['cross_flags'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('after_restore','IF EQ')+inc(G['crossed'])
    s+=label('after_restore')+'      R0 = 0;\n'+store(G['armed'])+load(G['original_i13'],'I13')
    # Native packed loop leaves I4 at reply+28+14*6. Preserve that caller-visible
    # value; I5 and I3 are independently restored by the native epilogue.
    s+=load(G['original_i13'])+'      R1 = 112;\n      R0 = R0 + R1;\n      I4 = R0;\n'+restore()
    s+=label('after_replay')+'      I0 = 0x12345678;\n      JUMP 0x1c26f2;\n'

    # Enters inside existing scalar legacy publisher save/restore envelope.
    s+=label('publication_entry')+load(G['publication_phase'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('publication_codec','IF EQ')
    s+='      R1 = 1;\n      COMP(R0, R1);\n'+jump('publication_guard','IF EQ')
    for name,tag,a,b,nextphase in (
        ('cross',0xdc21,G['crossed'],G['max_elapsed'],0),
        ('codec',0xdc1f,0x200e654c,0x200e6554,1),
        ('guard',0xdc20,G['accepted'],G['rejected'],2)):
        s+=label('publication_'+name)+f'      R0 = {nextphase};\n'+store(G['publication_phase'])
        s+=P.Q.P.D.P.publish(a,12)+P.Q.P.D.P.publish(b,16)
        s+=f'      I0 = {(tag<<16)|0x4f53:#x};\n      JUMP 0xbf2676;\n'
    return s


def sink_closure(raw):
    """Classify all raw literal coincidences; never mistake code for pointers."""
    visa,data=P.E.literals(raw,SINK,SINK_END)
    avisa,adata=P.E.literals(raw,0xbfc800,0xbfd000)
    expected_data={0x28389fc0};expected_alias={0x20018ada,0x20018b02,0x20018ba8,0x20018bd0,
        0x2001cba0,0x200d03d8,0x2838771e,0x2838bd5a,0x2838c828,0x2838df7a}
    assert not visa and set(data)==expected_data and set(avisa)==expected_alias and not adata
    # Bound each apparent pointer to an unchanged, classified native instruction.
    native=E.native_corpus(C.ROOT/'firmware/dn2-1.11/section_7_blob.bin')
    donor=E.native_corpus(C.ROOT/'firmware/dt2-1.16/section_7_blob.bin')
    regions=C.B.load_regions(raw);evidence=[]
    for hit in sorted(expected_data|expected_alias):
        donor_hit=hit==0x200d03d8
        target=0x1c39cf+(hit-0x200d0200)//2 if donor_hit else None
        rows=donor[3] if donor_hit else native[3]
        found=[]
        for pc,ins,idx,off in rows:
            at=E.physical(pc)
            if (pc<=target<pc+ins.length_bytes//2) if donor_hit else (at<=hit<at+ins.length_bytes):
                actual=0x200d0200+2*(pc-0x1c39cf) if donor_hit else at
                blob=next(b[actual-a:actual-a+ins.length_bytes] for a,b in regions if a<=actual< a+len(b))
                assert blob==C.S.to_bytes(ins.raw)[-ins.length_bytes:]
                text=E.sharcfn.render_instruction(pc,ins,E.NoMemory(),set(),collections.Counter(),[])[0]
                found.append(dict(hit=hex(hit),pc=hex(pc),form=ins.type_name,instruction=text,unchanged_native_bytes=True))
        assert len(found)==1,(hex(hit),found)
        evidence+=found
    return evidence


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    doc=json.loads(BASE.with_name('build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
    for _,pc,word,_ in HOOKS:assert m.read_sw(pc,6)==C.S.to_bytes(word),(hex(pc),m.read_sw(pc,6).hex())
    assert not any(P.E.literals(raw,PHYSICAL,END)) and not any(P.E.literals(raw,CODE,0xbed800))
    for block in C.B.walk(raw).blocks:
        for lo,hi in ((PHYSICAL,END),(SINK,SINK_END)):
            assert not (block.target<hi and lo<block.target+block.count),(hex(block.target),block.count)
    closure=sink_closure(raw)
    stock=B.decode_view(k,(C.ROOT/'firmware/dn2-1.11/section_7_blob.bin').read_bytes())
    for lo,hi in ((0x1ca373,0x1ca392),(0x1ca46a,0x1ca59f),(0x1ca020,0x1ca05e),(0x1cc1d6,0x1cc26a)):
        assert m.read_sw(lo,2*(hi-lo))==stock.read_sw(lo,2*(hi-lo))
    out.mkdir(parents=True,exist_ok=False);asm=out/'usb-guarded-publication.asm';s=source();asm.write_text(s)
    obj,offsets=A._selas(asm,out);labels={n:CODE+v for n,v in O.symbols((out/'usb-guarded-publication.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);obj,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(obj));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        value=C.S.to_value(code[off:off+6]);reg=(value>>32)&0x7f
        if value>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((value&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
    for name in ('before','after'):
        for suffix,reg in (('mode','MODE1'),('clock','EMUCLK')):
            at=2*(labels[name+'_'+suffix+'.']-CODE);assert widths[at]==6
            code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES[reg]))
    for name,_,word,_ in HOOKS[:2]:
        at=2*(labels[name+'_replay.']-CODE);assert widths[at]==6;code[at:at+6]=C.S.to_bytes(word)
    assert PHYSICAL+len(code)<=CODE_END
    image=bytearray(raw);hooks=[]
    for name,pc,word,resume in HOOKS:
        physical=C.S.code_address(pc,window='l2' if pc>=0xb80000 else 'l1');patch=C.S.to_bytes(0x063e00000000|labels[name+'_entry.'])
        C.B.write_span(image,physical,patch)
        hooks.append(dict(name=name,site=hex(pc),physical=hex(physical),entry=hex(labels[name+'_entry.']),resume=hex(resume),before=C.S.to_bytes(word).hex(),after=patch.hex()))
    blocks=[(PHYSICAL,bytes(code)),(STATE,bytes(END-STATE)),(SINK,bytes(SINK_END-SINK))]
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks));w=C.B.walk(result);first,last=w.blocks[7],w.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:];assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['usb_guarded_publication']=dict(base=str(BASE),base_sha256=BASE_SHA,code=hex(CODE),code_physical=hex(PHYSICAL),code_bytes=len(code),instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},hooks=hooks,state=hex(STATE),state_bytes=END-STATE,sink=hex(SINK),sink_bytes=SINK_END-SINK,fields={n:hex(v) for n,v in G.items()},snapshots={n:hex(v) for n,v in F.items()},save={n:hex(v) for n,v in SAVE.items()},encoding_fixes=fixes,
        publication=dict(phase=15,rotation='DC1F then DC20 then DC21, one tag per phase15 invocation',heartbeat_phase='(heartbeat >> 10) & 15 == 15',tags={'0x4f53dc1f':['codec_zero_commits','codec_discarded_on_skip'],'0x4f53dc20':['guard_accepted','guard_rejected'],'0x4f53dc21':['guard_crossed_or_late','max_accepted_elapsed_cycles']},removed='DC1E static SPORT/DMA configuration only',retained='DC10..DC1D; legacy DC00/DC01 exit may surface; native words0/2/5/6 and S0 side effects unchanged',byte_order='existing DSP halfswap -> canonical CF big-endian32',recorder='existing BF53B0 gate remains; phase15 cannot run with Recorder enabled'),
        admission=dict(tdm_xor='0x1800',spi_xor='0x1000',canonical_only=True,tdm_min_count=256,tdm_max_count=512,spi_min_count=512,spi_max_count=1374,drained='target==stableSTART,COUNT0,CURRENT==START+pagebytes; native circular descriptors alternate to other page',joint=True,reject='both native audio loops target same private sequential sink; no live fallback'),
        postcheck=dict(cross_bits={'1':'TDM ownership/read bracket failure','2':'SPI ownership/read bracket failure','4':'elapsed threshold'},late_threshold_cycles=MAX_ELAPSED,scope='prehook clock after scalar save through posthook clock; includes admission/native exports/IRQ delay; accepted only; postcheck cannot undo writes'),
        ownership=dict(reservation=[hex(PHYSICAL),hex(END)],sink=[hex(SINK),hex(SINK_END)],loaded_fill_overlap=False,code_state_literals=0,sink_raw_pattern_classification=closure,known_owners='R005 wrapper scratch ends200F9000; native DMA arena starts200FA000. Shared sink written sequentially by serialized native exporter only; no reader/ISR access introduced.',limitation='Literal/native-owner closure does not exclude every arbitrary computed writer.'),
        unchanged=['R005 codec conversion/stage/early commit/phase accounting','CF control order and SPI selector/DMA descriptors','Recorder input/reply ownership','all native exporter computation and loop bytes','native S0 header side effects','no R006 observer or launch-stamp dependency'],
        limits=['Admission is not an IRQ lock; arbitrary preemption can exhaust safe window.','Fixed successor-page swap adds one transport slot in observed lockstep; no per-sample generation tags prove absolute TDM/SPI alignment.','Guard rejection repeats prior live pages; counters expose deliberate drops.','No hardware timing/audio assurance from offline fixtures.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(ok=True,sha256=C.SHA(result),code_bytes=len(code),state_bytes=END-STATE,sink_bytes=SINK_END-SINK),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
