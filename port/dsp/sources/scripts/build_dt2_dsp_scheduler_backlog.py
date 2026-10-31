#!/usr/bin/env python3
"""Observe native skipped audio notifications without changing scheduling/audio."""
from pathlib import Path
import argparse
import json
import re

import build_dt2_dsp_timing_publication as P

T, C, B, A, O = P.T, P.C, P.B, P.A, P.O
BASE = C.ROOT/'output/dn2-research/dt2-dsp-timing-publication-20261011/section_7.bin'
BASE_SHA = 'e0c300a41198f0476598258806bff56089ddadd597cd3a796acb5d1d987dcc37'
CODE, STATE = 0xbf0400, 0x200e1200
SITE, RESUME, BEFORE = 0x1c9fee, 0x1c9ff1, 0x023e00320020
PUB_SITE, PUB_RESUME = P.SITE, P.RESUME
SAVE_NAMES = ('i0','mode','r0','r1','r2','asx','asy')
FIELDS = {n: STATE+4*i for i,n in enumerate((*SAVE_NAMES,'wait_returns','backlog_skips','max_notification_count'))}
PUB_FIELDS = {n: STATE+0x40+4*i for i,n in enumerate(SAVE_NAMES)}
STATE_BYTES = 0x5c


def preserve(fields, label):
    s=f'      DM({fields["i0"]:#x}) = I0;\n'+T.label(label)
    s+='      I0 = 0x12345678; // actual MODE1 universal copy\n'
    s+=f'      DM({fields["mode"]:#x}) = I0;\n      BIT CLR MODE1 0x200000;\n      NOP;\n      NOP;\n'
    for r,n in (('R0','r0'),('R1','r1'),('R2','r2'),('ASTATX','asx'),('ASTATY','asy')):
        s+=f'      DM({fields[n]:#x}) = {r};\n'
    return s


def restore(fields):
    s=''
    for r,n in (('R0','r0'),('R1','r1'),('R2','r2'),('ASTATX','asx'),('ASTATY','asy'),('MODE1','mode')):
        s+=f'      {r} = DM({fields[n]:#x});\n'
    s+='      NOP;\n      NOP;\n'+f'      I0 = DM({fields["i0"]:#x});\n'
    return s


def publish(address, offset):
    s=f'''      R0 = DM({address:#x});
      R1 = LSHIFT R0 BY 16;
      R2 = LSHIFT R0 BY -16;
      R1 = R1 OR R2;
      I0 = R1;
'''
    return s+''.join(f'      DM({p+offset:#x}) = I0;\n' for p in T.PAGES)


def source():
    s='.SECTION/PM seg_pmco;\n'+T.label('scheduler_entry.')+preserve(FIELDS,'scheduler_mode.')
    s+=f'''      R1 = DM({FIELDS['wait_returns']:#x});
      R2 = 1;
      R1 = R1 + R2;
      DM({FIELDS['wait_returns']:#x}) = R1;
      R1 = DM({FIELDS['max_notification_count']:#x});
      COMPU(R0, R1);
'''+T.jump('scheduler_max_done.','IF LE')
    s+=f'      DM({FIELDS["max_notification_count"]:#x}) = R0;\n'+T.label('scheduler_max_done.')
    s+='      R1 = 1;\n      COMPU(R0, R1);\n'+T.jump('scheduler_restore.','IF LE')
    s+=f'''      R0 = DM({FIELDS['backlog_skips']:#x});
      R1 = R0 + R1;
      DM({FIELDS['backlog_skips']:#x}) = R1;
'''+T.label('scheduler_restore.')+restore(FIELDS)
    s+=T.label('scheduler_replay.')+'      I0 = 0x12345678; // exact native BTGL replacement\n'
    s+=f'      JUMP {RESUME:#x};\n'
    s+=T.label('publication_entry.')+f'      DM(0x2c59d4) = R0;\n'+preserve(PUB_FIELDS,'publication_mode.')
    s+=f'''      R0 = DM({P.HEARTBEAT:#x});
      R0 = LSHIFT R0 BY -10;
      R1 = 3;
      R0 = R0 AND R1;
      R1 = 1;
      COMP(R0, R1);
'''+T.jump('publication_backlog.','IF GT')+T.jump('publication_counts.','IF EQ')
    s+=publish(T.FIELDS['last'],12)+publish(T.FIELDS['max'],16)
    s+='      I0 = 0xdc104f53;\n'+T.jump('publication_marker.')
    s+=T.label('publication_counts.')+publish(T.FIELDS['completed'],12)+publish(T.FIELDS['overbudget'],16)
    s+='      I0 = 0xdc114f53;\n'+T.jump('publication_marker.')
    s+=T.label('publication_backlog.')+publish(FIELDS['backlog_skips'],12)+publish(FIELDS['max_notification_count'],16)
    s+='      I0 = 0xdc124f53;\n'+T.label('publication_marker.')
    s+=''.join(f'      DM({p+4:#x}) = I0;\n' for p in T.PAGES)
    s+=T.label('publication_restore.')+restore(PUB_FIELDS)+f'      JUMP {PUB_RESUME:#x};\n'
    return s


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    out.mkdir(parents=True,exist_ok=False)
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    m=B.decode_view(k,raw)
    assert m.read_sw(SITE,6)==C.S.to_bytes(BEFORE)
    assert m.read_sw(PUB_SITE,6)==C.S.to_bytes(0x063e00000000|P.CODE)
    # Bind the full native scheduler branch and the relocated observable publisher.
    assert k.st.decode_at(m,None,0x1c9fe7).raw==0x180400b891fa
    assert m.read_sw(RESUME,6)==bytes.fromhex('300700000a00')
    assert m.read_sw(PUB_SITE-6,12)==b''.join(C.S.to_bytes(v) for v in (0x10000030dd58,0x1100002c49d4))
    asm=out/'scheduler-backlog.asm';s=source();asm.write_text(s)
    be,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'scheduler-backlog.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
    code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])}
    fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        value=C.S.to_value(code[off:off+6]);reg=(value>>32)&0x7f
        if value>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((value&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32))
            fixes.append(hex(CODE+off//2))
    for name in ('scheduler_mode.','publication_mode.'):
        off=2*(labels[name]-CODE);assert widths[off]==6
        code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
    off=2*(labels['scheduler_replay.']-CODE);assert widths[off]==6
    code[off:off+6]=C.S.to_bytes(BEFORE)
    physical=C.S.code_address(CODE,window='l2');assert physical==0x200e0800 and physical+len(code)<=0x200e1000
    assert STATE+STATE_BYTES<=0x200e1300
    regions=C.B.load_regions(raw);blocks=[(physical,bytes(code)),(STATE,bytes(STATE_BYTES))]
    for at,data in blocks:
        assert not any(at<a+len(v) and a<at+len(data) for a,v in regions),hex(at)
        regions.append((at,data))
    image=bytearray(raw);hooks=[]
    for pc,name,window in ((SITE,'scheduler_entry.','l1'),(PUB_SITE,'publication_entry.','l2')):
        patch=C.S.to_bytes(0x063e00000000|labels[name]);before=m.read_sw(pc,6)
        C.B.write_span(image,C.S.code_address(pc,window=window),patch)
        hooks.append(dict(site=hex(pc),before=before.hex(),after=patch.hex(),entry=hex(labels[name]),
            resume=hex(RESUME if pc==SITE else PUB_RESUME)))
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['scheduler_backlog']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,hooks=hooks,
        code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),state=hex(STATE),state_bytes=STATE_BYTES,
        labels={n:hex(v) for n,v in labels.items()},instruction_offsets=offsets,
        fields={n:hex(v) for n,v in FIELDS.items()},publication_save_fields={n:hex(v) for n,v in PUB_FIELDS.items()},
        system_register_fixes=fixes,native_replay=hex(BEFORE),
        phase=f'(DM({P.HEARTBEAT:#x}) >> 10) & 3',
        schema={'0x4f53dc10':{'heartbeat_phase':[0],'3':'last_render_cycles','4':'max_render_cycles'},
                '0x4f53dc11':{'heartbeat_phase':[1],'3':'completed_render_calls','4':'above_nominal_budget_calls'},
                '0x4f53dc12':{'heartbeat_phase':[2,3],'3':'backlog_skips','4':'max_notification_count'}},
        byte_order='Canonical CF big-endian32 directly; DSP pre-halfswaps before native MSB-first16 transport.',
        counters='wait_returns increments for every native wait return; backlog_skips increments once when unsigned R0>1; max_notification_count retains the largest R0. Counts wrap modulo2^32. wait_returns retained internally; completed render total remains DC11.',
        untouched_cf_words=[0,2,5,6],measurement_hooks_unchanged=True,
        contract='Observe native wait count before exact displaced BTGL; preserve all register/status/SIMD state. Native notification consumption, conditional branch, audio renderer and allocator stay unchanged.',
        limits=['Backlog skips prove consumed native notifications without a render at that iteration, not automatically an audible DAC underrun.',
                'Zero backlog does not exclude a late start with notification count1.',
                'Publisher runs only when rendering resumes; stalled publication means unavailable diagnostics, not zero backlog.',
                'Observer costs cycles outside render timer; known-live publisher costs cycles inside render timer.',
                'Counters/max retained since boot; startup may contribute; counter deltas wrap modulo2^32.',
                'DC00/DC01 original exit publication remains; DC10/DC11 retain fields and canonical order, but use phases0/1 of four.',
                'Publication remains non-atomic; inspect phase/heartbeat and use a full-pattern bounded capture.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hooks=hooks),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
