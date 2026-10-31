#!/usr/bin/env python3
"""Publish retained T1DM timing at the known-live legacy stage8 publication."""
from pathlib import Path
import argparse
import json
import re

import build_dt2_dsp_block_timing as T

C,B,A,O=T.C,T.B,T.A,T.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-block-timing-20261011/section_7.bin'
BASE_SHA='c9d06edbd07becf8a4ae71077775ec7e0711a49332476b9dc128c9fe428ca11d'
CODE,STATE,SITE,RESUME=0xbf0340,0x200e1180,0xbf53b3,0xbf53b6
BEFORE=0x1100002c59d4
HEARTBEAT=0x30dcd0
FIELDS={n:STATE+4*i for i,n in enumerate(('i0','mode','r0','r1','r2','asx','asy'))}


def source():
    s='.SECTION/PM seg_pmco;\n'+T.label('publication_entry.')
    # This store is replayed first, with the caller's original SIMD behavior.
    s+=f'      DM(0x2c59d4) = R0;\n      DM({FIELDS["i0"]:#x}) = I0;\n'
    s+=T.label('publication_mode.')+'      I0 = 0x12345678; // actual MODE1 universal copy\n'
    s+=f'      DM({FIELDS["mode"]:#x}) = I0;\n      BIT CLR MODE1 0x200000;\n      NOP;\n      NOP;\n'
    for r,f in (('R0','r0'),('R1','r1'),('R2','r2'),('ASTATX','asx'),('ASTATY','asy')):
        s+=f'      DM({FIELDS[f]:#x}) = {r};\n'
    s+=f'''      R0 = DM({HEARTBEAT:#x});
      R0 = LSHIFT R0 BY -10;
      R1 = 1;
      R0 = R0 AND R1;
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('publication_counts.','IF NE')
    s+=T.publish_value('last',12)+T.publish_value('max',16)
    s+='      I0 = 0xdc104f53;\n'+T.jump('publication_marker.')
    s+=T.label('publication_counts.')+T.publish_value('completed',12)+T.publish_value('overbudget',16)
    s+='      I0 = 0xdc114f53;\n'+T.label('publication_marker.')
    s+=''.join(f'      DM({p+4:#x}) = I0;\n' for p in T.PAGES)
    s+=T.label('publication_restore.')
    for r,f in (('R0','r0'),('R1','r1'),('R2','r2'),('ASTATX','asx'),('ASTATY','asy'),('MODE1','mode'),('I0','i0')):
        s+=f'      {r} = DM({FIELDS[f]:#x});\n'
    s+=f'      JUMP {RESUME:#x};\n'
    return s


def build(out):
    raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
    out.mkdir(parents=True,exist_ok=False)
    doc=json.loads((BASE.parent/'build-receipt.json').read_text())
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    m=B.decode_view(k,raw);ins=k.st.decode_at(m,None,SITE)
    assert ins.raw==BEFORE and ins.length_bytes==6
    # Match the full active publisher and its surrounding restores, not inert
    # historical L1 copies retained by the earlier relocation build.
    expected=(0x10000030dd58,0x1100002c49d4,BEFORE,0x10000030dc10,0x10010030dc14,0x063e001c944c)
    assert m.read_sw(SITE-6,36)==b''.join(C.S.to_bytes(v) for v in expected)
    asm=out/'timing-publication.asm';s=source();asm.write_text(s)
    be,offsets=A._selas(asm,out)
    labels={n:CODE+v for n,v in O.symbols((out/'timing-publication.doj').read_bytes()).items()}
    s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
    asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
    code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])}
    assert C.S.to_value(code[:6])==BEFORE
    fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        value=C.S.to_value(code[off:off+6]);reg=(value>>32)&0x7f
        if value>>40 in (0x10,0x11) and reg in (0x70,0x73,0x74):
            code[off:off+6]=C.S.to_bytes((value&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32))
            fixes.append(hex(CODE+off//2))
    off=2*(labels['publication_mode.']-CODE);assert widths[off]==6
    code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
    physical=C.S.code_address(CODE,window='l2');assert physical==0x200e0680 and physical+len(code)<=0x200e1000
    assert STATE+len(FIELDS)*4<=0x200e1200
    regions=C.B.load_regions(raw);blocks=[(physical,bytes(code)),(STATE,bytes(len(FIELDS)*4))]
    for at,data in blocks:
        assert not any(at<a+len(v) and a<at+len(data) for a,v in regions),hex(at)
        regions.append((at,data))
    image=bytearray(raw);patch=C.S.to_bytes(0x063e00000000|CODE)
    C.B.write_span(image,C.S.code_address(SITE,window='l2'),patch)
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    # This new receipt corrects the wire description without rewriting the
    # frozen T1DM receipt or its image.
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['timing_publication']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,
        hook=dict(site=hex(SITE),before=hex(BEFORE),after=patch.hex(),entry=hex(CODE),replay=hex(CODE),resume=hex(RESUME)),
        code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),scratch=hex(STATE),scratch_bytes=len(FIELDS)*4,
        labels={n:hex(a) for n,a in labels.items()},instruction_offsets=offsets,
        fields={n:hex(a) for n,a in FIELDS.items()},system_register_fixes=fixes,
        preserved_clobbers=['I0','R0','R1','R2','MODE1','ASTATX','ASTATY'],
        timing_state={n:hex(T.FIELDS[n]) for n in ('last','max','completed','overbudget')},
        phase=f'(DM({HEARTBEAT:#x}) >> 10) & 1',heartbeat=hex(HEARTBEAT),
        schema={'0x4f53dc10':{'3':'last_render_cycles','4':'max_render_cycles'},
                '0x4f53dc11':{'3':'completed_calls','4':'above_nominal_budget_calls'}},
        cf_byte_order='Read canonical CF big-endian32 marker and payload directly; DSP pre-halfswaps before native MSB-first16 transport.',
        untouched_cf_words=[0,2,5,6],measurement_hooks_unchanged=True,
        contract='Append-only known-live stage8 publication; replay final legacy store first, preserve scalar/DAG/mode/status clobbers, then expose previous completed render-call state. No audio algorithm change.',
        limits=['The cause of missing T1DM timing counters remains unconfirmed; publication does not prove measurement-hook execution.',
                'Phase is controlled by existing heartbeat, independent of completed calls. Zero completed/overbudget is valid.',
                'Observer executes inside the measured native call and adds overhead to subsequent timing.',
                'The original T1DM exit publisher remains unchanged and can also expose DC00/DC01.',
                'Counters/max retained since boot; startup may dominate maximum; counts wrap modulo2^32.',
                'Above666667 nominal1GHz cycles is not proof of DAC underrun.',
                'Publication is non-atomic. Poll both phases at5Hz for at least3seconds.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hook=doc['timing_publication']['hook']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
