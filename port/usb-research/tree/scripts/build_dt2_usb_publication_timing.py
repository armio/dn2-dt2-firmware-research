#!/usr/bin/env python3
"""Observe R005 USB publication boundaries without changing audio/control policy."""
from pathlib import Path
import argparse
import json
import re
import struct

import build_dt2_buffer_phase_accounting as Q
import build_dt2_dsp_scratch_efficiency as E

C, B, A, O, T = Q.C, Q.P.B, Q.P.A, Q.P.O, Q.P.T
BASE = C.ROOT/'output/dn2-research/sample-scratch-r005-20261101/dsp/section_7.bin'
BASE_SHA = '57be61eb71d41dcb164ecedbb32ea7fd92eae493512d737260466865f5a32e0c'
CODE, PHYSICAL, CODE_END = 0xbec800, 0x200d9000, 0x200da800
STATE, END = 0x200da800, 0x200db000
MAGIC = 0x55425436
WIRE = 0x200f8d40
CALLBACK, ACTIVE_CALLBACK = 0x200e2304, 0x200e2318
REGS = ('I0','MODE1','R0','R1','R2','I4','L4','ASTATX','ASTATY')
SAVE = {n:STATE+4*i for i,n in enumerate(REGS)}
PAIR_SAVE = STATE+0x28
G = {n:STATE+0x40+4*i for i,n in enumerate((
    'frame_id','frame_valid','sequence','publish_calls','publish_epoch','armed',
    'last_selected','invalid_identity','pending'))}
WORK, LATEST, SNAP = (STATE+v for v in (0x100,0x180,0x200))
NAMES = ('frame_id sequence active_callback callback_before tdm_destination spi_destination flags '
         'tdm_before_clock tdm_before_start tdm_before_current tdm_before_count tdm_before_start_again '
         'tdm_after_clock tdm_after_start tdm_after_current tdm_after_count tdm_after_start_again '
         'spi_before_clock spi_before_start spi_before_current spi_before_count spi_before_start_again '
         'spi_after_clock spi_after_start spi_after_current spi_after_count spi_after_start_again '
         'callback_after previous_render_cycles overbudget_count busy_callbacks checksum').split()
F = {n:WORK+4*i for i,n in enumerate(NAMES)}
HOOKS = (
    ('identity',0x1c2872,0x063e00bfa880,0xbfa880),
    ('tdm_before',0x1c265b,0x1596ffffff82,0x1c265e),
    ('boundary',0x1c2692,0x1596ffffffaa,0x1c2695),
    ('spi_after',0x1c26ef,0x142200002000,0x1c26f2),
    ('publication',0xbf53b3,0x063e00bf2350,0xbf53b6),
)


def label(n): return f'.GLOBAL {n}.;\n{n}.:\n'
def jump(n, cond=''): return f'      {cond} JUMP 0x0; // -> {n}.\n'
def load(a, r='R0'): return f'      {r} = DM({a:#x});\n'
def store(a, r='R0'): return f'      DM({a:#x}) = {r};\n'
def rotate(r='R0'):
    return f'      R1 = LSHIFT {r} BY 16;\n      {r} = LSHIFT {r} BY -16;\n      {r} = {r} OR R1;\n'
def inc(a): return load(a)+'      R1 = 1;\n      R0 = R0 + R1;\n'+store(a)
def copy(src,dst,count=32):
    return ''.join(load(src+4*i)+store(dst+4*i) for i in range(count))
def save(n):
    return (store(SAVE['I0'],'I0')+label(n+'_mode')+'      I0 = 0x12345678;\n'+
            store(SAVE['MODE1'],'I0')+(store(PAIR_SAVE) if n=='publication' else '')+
            '      BIT CLR MODE1 0x202000;\n      NOP;\n      NOP;\n'+
            ''.join(store(SAVE[r],r) for r in REGS[2:]))
def restore():
    return ''.join(load(SAVE[r],r) for r in (*REGS[2:],'MODE1','I0'))
def clock(n):
    return label(n+'_clock')+'      I0 = 0x12345678;\n'+store(F[n+'_clock'],'I0')
def sample(n,dma):
    return clock(n)+''.join(load(dma+off)+store(F[n+'_'+field]) for field,off in
        (('start',4),('current',0x2c),('count',0x34),('start_again',4)))
def replay(n,resume):
    return restore()+label(n+'_replay')+'      I0 = 0x12345678;\n'+f'      JUMP {resume:#x};\n'


def source():
    s='.SECTION/PM seg_pmco;\n'+label('identity_entry')+save('identity')
    s+='      R0 = 0;\n'+store(G['frame_id'])+store(G['frame_valid'])
    s+='      I4 = DM(-32, I6);\n      L4 = 0;\n      NOP;\n'
    s+='      R0 = I4;\n      R1 = 0x2c29d0;\n      COMP(R0, R1);\n'+jump('identity_page','IF EQ')
    s+='      R1 = 0x2c39d0;\n      COMP(R0, R1);\n'+jump('identity_bad','IF NE')+label('identity_page')
    s+='      R0 = DM(0x2a7, I4);\n'+rotate()+f'      R1 = {MAGIC:#x};\n      COMP(R0, R1);\n'+jump('identity_bad','IF NE')
    s+='      R0 = DM(0x2a8, I4);\n'+rotate()+'      R2 = R0;\n      R0 = DM(0x2a9, I4);\n'+rotate()
    s+='      R1 = -1;\n      R1 = R1 XOR R2;\n      COMP(R0, R1);\n'+jump('identity_bad','IF NE')
    # Read identity again: no torn tag is accepted when RX changes mid-snapshot.
    s+='      R0 = DM(0x2a8, I4);\n'+rotate()+'      COMP(R0, R2);\n'+jump('identity_bad','IF NE')
    s+=store(G['frame_id'],'R2')+'      R0 = 1;\n'+store(G['frame_valid'])+jump('identity_restore')
    s+=label('identity_bad')+inc(G['invalid_identity'])+label('identity_restore')+restore()+'      JUMP 0xbfa880;\n'

    s+=label('tdm_before_entry')+save('tdm_before')
    s+='      R0 = 0;\n'+store(G['armed'])+load(G['frame_valid'])+'      R1 = 1;\n      COMP(R0, R1);\n'+jump('tdm_before_finish','IF NE')
    s+=load(G['frame_id'])+'      R1 = 255;\n      R2 = R0 AND R1;\n      R1 = 0;\n      COMP(R2, R1);\n'+jump('tdm_before_finish','IF NE')
    s+=load(G['last_selected'],'R1')+'      COMP(R0, R1);\n'+jump('tdm_before_finish','IF EQ')
    s+=store(G['last_selected'])+store(F['frame_id'])+'      R0 = 1;\n'+store(G['armed'])
    s+=load(T.FIELDS['completed'])+'      R1 = 1;\n      R0 = R0 + R1;\n'+store(G['sequence'])+store(F['sequence'])
    s+=load(G['frame_valid'])+store(F['flags'])+load(ACTIVE_CALLBACK)+store(F['active_callback'])
    s+=load(CALLBACK)+store(F['callback_before'])+store(F['tdm_destination'],'I3')+store(F['spi_destination'],'I13')
    s+=sample('tdm_before',0x31022000)+label('tdm_before_finish')+replay('tdm_before',0x1c265e)

    s+=label('boundary_entry')+save('boundary')+load(G['armed'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('boundary_finish','IF EQ')
    s+=sample('tdm_after',0x31022000)+sample('spi_before',0x3102d200)+label('boundary_finish')+replay('boundary',0x1c2695)

    s+=label('spi_after_entry')+save('spi_after')+load(G['armed'])+'      R1 = 0;\n      COMP(R0, R1);\n'+jump('spi_after_finish','IF EQ')
    s+=sample('spi_after',0x3102d200)
    s+=load(CALLBACK)+store(F['callback_after'])
    # Observed selected-page equality is a candidate, not an underrun assertion.
    for name,bit in (('tdm',2),('spi',4)):
        s+=load(F[name+'_destination'])+'      R1 = 0x28000000;\n      R2 = R0 + R1;\n'
        s+=load(F[name+'_before_start'])+'      COMP(R0, R2);\n'+jump(name+'_same','IF EQ')
        s+=load(F[name+'_after_start'])+'      COMP(R0, R2);\n'+jump(name+'_other','IF NE')
        s+=label(name+'_same')+load(F['flags'])+f'      R1 = {bit};\n      R0 = R0 OR R1;\n'+store(F['flags'])
        s+=label(name+'_other')
    for name,at in [('previous_render_cycles',T.FIELDS['last']),('overbudget_count',T.FIELDS['overbudget']),
                    ('busy_callbacks',0x200e2338)]:
        s+=load(at)+store(F[name])
    s+=f'      R0 = {MAGIC:#x};\n'
    for i in range(31):
        s+='      R1 = LSHIFT R0 BY 5;\n      R0 = LSHIFT R0 BY -27;\n      R0 = R0 OR R1;\n'
        s+=load(WORK+4*i,'R2')+'      R0 = R0 XOR R2;\n'
    s+=store(F['checksum'])
    s+=copy(WORK,LATEST)
    s+='      R0 = 1;\n'+store(G['pending'])+'      R0 = 0;\n'+store(G['armed'])
    s+=label('spi_after_finish')+replay('spi_after',0x1c26f2)

    # BF53B0's installed Recorder gate protects this hook; recheck the cookie
    # here as well, so direct entry cannot corrupt active Recorder fields.
    s+=label('publication_entry')+save('publication')
    s+=load(WIRE+24)+'      R0 = LSHIFT R0 BY -16;\n      R1 = 0x5243;\n      COMP(R0, R1);\n'+jump('publication_finish','IF EQ')
    # Old BF2350's initial DM(2C59D4)=R0 has an S0 companion at +8
    # when SSE is enabled. Preserve that inherited heartbeat write; +4 is
    # replaced by our final diagnostic marker as in the old publisher.
    s+=load(SAVE['MODE1'])+'      R1 = 0x200000;\n      R0 = R0 AND R1;\n      R1 = 0;\n      COMP(R0, R1);\n'+jump('publication_native_done','IF EQ')
    s+=load(PAIR_SAVE+4)+store(0x2c59d8)+label('publication_native_done')
    s+=load(G['publish_calls'])+'      R1 = 31;\n      R2 = R0 AND R1;\n      R1 = 0;\n      COMP(R2, R1);\n'+jump('publication_existing','IF NE')
    s+=load(G['pending'])+'      COMP(R0, R1);\n'+jump('publication_existing','IF EQ')
    # Replace only at field zero. A complete record remains immutable for
    # each 32-call cycle, repeated until the next selected control ID arrives.
    s+=inc(G['publish_epoch'])+copy(LATEST,SNAP)+'      R0 = 0;\n'+store(G['pending'])
    s+=label('publication_existing')+load(G['publish_calls'])+'      R1 = 31;\n      R2 = R0 AND R1;\n'
    s+='      R0 = LSHIFT R2 BY 2;\n'+f'      R1 = {SNAP:#x};\n      R0 = R0 + R1;\n      I4 = R0;\n      L4 = 0;\n      NOP;\n      R0 = DM(0, I4);\n'+rotate()
    s+='      DM(0x2c49e0) = R0;\n      DM(0x2c59e0) = R0;\n'+load(SNAP)+rotate()
    s+='      DM(0x2c49dc) = R0;\n      DM(0x2c59dc) = R0;\n'+load(G['publish_epoch'])
    s+='      R1 = 63;\n      R0 = R0 AND R1;\n      R0 = LSHIFT R0 BY 5;\n      R0 = R0 OR R2;\n      R1 = 0x4f53e000;\n      R0 = R0 OR R1;\n'+rotate()
    s+='      DM(0x2c49d4) = R0;\n      DM(0x2c59d4) = R0;\n'+inc(G['publish_calls'])
    s+=label('publication_finish')+restore()+'      JUMP 0xbf53b6;\n'
    return s


def build(out):
    raw=BASE.read_bytes()
    if C.SHA(raw)!=BASE_SHA: raise ValueError('requires exact R005 DSP')
    doc=json.loads(BASE.with_name('build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    m=B.decode_view(k,raw)
    for _,pc,word,_ in HOOKS: assert m.read_sw(pc,6)==C.S.to_bytes(word),hex(pc)
    assert m.read_sw(0x1c266c,6)==C.S.to_bytes(0x0c000e800023)
    assert m.read_sw(0xbf53b0,6)==C.S.to_bytes(0x063e00bfa778)
    assert not any(PHYSICAL<a+len(b) and a<END for a,b in C.B.load_regions(raw))
    assert not any(E.literals(raw,PHYSICAL,END))
    assert not any(E.literals(raw,CODE,0xbed800))
    out.mkdir(parents=True,exist_ok=False);asm=out/'usb-publication-timing.asm';s=source();asm.write_text(s)
    obj,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'usb-publication-timing.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);obj,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(obj));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])}
    fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
        if v>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
    for name in ('identity','tdm_before','boundary','spi_after','publication'):
        at=2*(labels[name+'_mode.']-CODE);assert widths[at]==6
        code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
    for name in ('tdm_before','tdm_after','spi_before','spi_after'):
        at=2*(labels[name+'_clock.']-CODE);assert widths[at]==6
        code[at:at+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['EMUCLK']))
    for name,_,word,_ in HOOKS[1:4]:
        at=2*(labels[name+'_replay.']-CODE);assert widths[at]==6;code[at:at+6]=C.S.to_bytes(word)
    assert PHYSICAL+len(code)<=CODE_END,(len(code),hex(PHYSICAL+len(code)))
    image=bytearray(raw);hooks=[]
    for name,pc,word,resume in HOOKS:
        patch=C.S.to_bytes(0x063e00000000|labels[name+'_entry.'])
        physical=C.S.code_address(pc,window='l2' if pc>=0xb80000 else 'l1')
        C.B.write_span(image,physical,patch)
        hooks.append(dict(name=name,site=hex(pc),physical=hex(physical),entry=hex(labels[name+'_entry.']),resume=hex(resume),before=C.S.to_bytes(word).hex(),after=patch.hex()))
    blocks=[(PHYSICAL,bytes(code)),(STATE,bytes(END-STATE))]
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    w=C.B.walk(result);first,last=w.blocks[7],w.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['usb_publication_timing']=dict(base=str(BASE),base_sha256=BASE_SHA,code=hex(CODE),code_physical=hex(PHYSICAL),code_bytes=len(code),instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},hooks=hooks,state=hex(STATE),state_bytes=END-STATE,fields={n:hex(v) for n,v in G.items()},record_fields=NAMES,records={n:hex(v) for n,v in [('working',WORK),('latest',LATEST),('publication_snapshot',SNAP)]},record_bytes=128,save={n:hex(v) for n,v in SAVE.items()},encoding_fixes=fixes,
        identity=dict(direction='CF to DSP only',offset='0xa9c',bytes=12,magic=hex(MAGIC),generation=4,complement=8,byte_order='CF big-endian32, rotate16 after native SPI halfword transport',snapshot='1C2872 before existing Recorder snapshot and conditional native0xA80 copy; validate known RX page, magic, complement, reread ID',no_transfer_growth=True),
        selection=dict(control_id_modulus=256,residue=0,once_per_distinct_id=True,invalid_identity_skips_mmio=True),
        publication=dict(site='0xbf53b3',recorder_gate='0xbf53b0 -> 0xbfa778',reply='0x800053a4',marker_offset=4,identity_offset=12,value_offset=16,marker_base='0x4f53e000',marker_mask='0xfffff800',field_mask=31,epoch_shift=5,epoch_mask=63,calls_per_field=1,fields_per_snapshot=32,calls_per_snapshot=32,snapshot='Latest completed selected controlID, replaced only at field0; repeat immutable32-field cycle until next selected record. Nominal32-block cycle21.33ms, selected controlIDs256apart170.67ms.',read_rule='Group by marker epoch and echoed control launch_id. Require two consistent complete32-field repetitions, word0 equal echoedID, and valid word31 checksum; reject conflicts/incomplete/hash mismatch. Native SPI publication is not atomic; checksum detects corruption but is not cryptographic proof; controlID is not an audio payload generation.',checksum='word31=fold(words0..30):seed0x55425436; each stepROL32(acc,5) XOR word',unchanged_header_words=[0,2,5,6],old_publication='Replace only closed-Recorder final DC10..DC1E publication. Original counters keep accumulating; record exposes render sequence, prior render cycles, overbudget and busy counts. DC12/13/14/17..1E and crossed-completion count no longer guaranteed visible through this final publisher; legacy exit/other diagnostic publishers remain.'),
        ownership=dict(reservation=[hex(PHYSICAL),hex(END)],loaded_fill_overlap=False,prior_visa_literals=0,prior_data_pointers=0,program_alias=[hex(CODE),'0xbed800'],prior_alias_literals=0,known_owners='R005 loaded code below200D1A14; Recorder state begins200DC000; native L2 DMA reservation200FA000..200FE000 excluded; all new data direct absolute addressing except bounded snapshot index.',limitation='Literal/loaded closure does not prove absence of every arbitrary computed writer.'),
        flags={'1':'valid CF identity','2':'TDM selected page equals sampled DMA START before or after','4':'SPI selected page equals sampled DMA START before or after'},
        contract='Read-only bounded DMA/timer observations, rolling selected completed records; no audio, control frame, selector, IRQ mask, DMA configuration, wait, loop body or publication ownership change.',
        limits=['Same-page candidate is not an underrun assertion; inspect CURRENT/count and both START brackets.','Sampling may perturb already tight deadlines; measured clocks include observer/IRQ cost.','Callback IDs and EMUCLK are DSP-local; CF launch ID joins observations but does not synchronize processor clocks.','TDMBEFORE is1C265B, before five native setup instructions and originalDO1C266C.','No per-sample audio generation tags; header identity does not prove entire payload coherent.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),state_bytes=END-STATE,hooks=len(hooks)),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
