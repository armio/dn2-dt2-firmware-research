#!/usr/bin/env python3
"""Instrument the T1DL native render call; do not modify audio algorithms."""
from pathlib import Path
import argparse
import json
import re

import build_dt2_cursor_release_floor_fix as P
import build_dt2_dsp_render_diagnostic as D

C, B, A, O = P.C, P.B, P.A, P.O
BASE = C.ROOT / 'output/dn2-research/dt2-dsp-sampler-start-reset-20261011/section_7.bin'
BASE_SHA = '35d49fc8e71698f2780de86b90bf60594c42da0802f8bf3406ba8da3386639ca'
CODE, STATE = 0xbf0200, 0x200e1100
PAGES = (0x2c49d0, 0x2c59d0)
BUDGET = 666667
FIELDS = {n: STATE + 4*i for i, n in enumerate((
    'save_i0', 'save_mode', 'save_r0', 'save_r1', 'save_r2', 'save_asx', 'save_asy',
    'start', 'end', 'last', 'max', 'completed', 'overbudget', 'armed'))}
HOOKS = ((0x1c9fb9, 0x0f0400268438, 'timing_entry.'),
         (0x1c9fc3, 0x158700000002, 'timing_exit.'))


def label(n):
    return f'.GLOBAL {n}\n{n}:\n'


def jump(n, cond=''):
    return f'      {cond+" " if cond else ""}JUMP 0x0; // -> {n}\n'


def prefix(stamp):
    # DAG universal copies are scalar even with SSE set. Clear SSE before
    # ordinary R-register stores, then restore both status banks and MODE1.
    s = f'      DM({FIELDS["save_i0"]:#x}) = I0;\n'
    s += label(f'{stamp}_clock.') + '      I0 = 0x12345678; // actual EMUCLK universal copy\n'
    s += f'      DM({FIELDS[stamp]:#x}) = I0;\n'
    s += label(f'{stamp}_mode.') + '      I0 = 0x12345678; // actual MODE1 universal copy\n'
    s += f'      DM({FIELDS["save_mode"]:#x}) = I0;\n'
    s += '      BIT CLR MODE1 0x200000;\n      NOP;\n      NOP;\n'
    for reg, field in (('R0', 'save_r0'), ('R1', 'save_r1'), ('R2', 'save_r2'),
                       ('ASTATX', 'save_asx'), ('ASTATY', 'save_asy')):
        s += f'      DM({FIELDS[field]:#x}) = {reg};\n'
    return s


def restore(name, site, original):
    s = label(name)
    for reg, field in (('R0', 'save_r0'), ('R1', 'save_r1'), ('R2', 'save_r2'),
                       ('ASTATX', 'save_asx'), ('ASTATY', 'save_asy'), ('MODE1', 'save_mode')):
        s += f'      {reg} = DM({FIELDS[field]:#x});\n'
    s += f'      I0 = DM({FIELDS["save_i0"]:#x});\n'
    s += label(name.replace('_restore', '_replay'))
    # Six-byte placeholder replaced with the exact displaced native encoding.
    s += f'      I0 = 0x12345678; // native {original:#014x}\n      JUMP {site+3:#x};\n'
    return s


def publish_value(field, offset):
    return f'''      R0 = DM({FIELDS[field]:#x});
      R1 = LSHIFT R0 BY 16;
      R2 = LSHIFT R0 BY -16;
      R1 = R1 OR R2;
      I0 = R1;
''' + ''.join(f'      DM({p+offset:#x}) = I0;\n' for p in PAGES)


def source():
    s = '.SECTION/PM seg_pmco;\n' + label('timing_entry.') + prefix('start')
    s += f'      R0 = 1;\n      DM({FIELDS["armed"]:#x}) = R0;\n'
    s += restore('entry_restore.', HOOKS[0][0], HOOKS[0][1])
    s += label('timing_exit.') + prefix('end')
    s += f'''      R0 = DM({FIELDS['armed']:#x});
      R1 = 0;
      COMP(R0, R1);
''' + jump('exit_restore.', 'IF EQ')
    s += f'''      DM({FIELDS['armed']:#x}) = R1;
      R0 = DM({FIELDS['end']:#x});
      R1 = DM({FIELDS['start']:#x});
      R0 = R0 - R1;
      DM({FIELDS['last']:#x}) = R0;
      R1 = DM({FIELDS['max']:#x});
      COMPU(R0, R1);
''' + jump('max_done.', 'IF LE')
    s += f'      DM({FIELDS["max"]:#x}) = R0;\n' + label('max_done.')
    s += f'''      R1 = {BUDGET};
      COMPU(R0, R1);
''' + jump('budget_done.', 'IF LE')
    s += f'''      R0 = DM({FIELDS['overbudget']:#x});
      R1 = 1;
      R0 = R0 + R1;
      DM({FIELDS['overbudget']:#x}) = R0;
''' + label('budget_done.')
    s += f'''      R0 = DM({FIELDS['completed']:#x});
      R1 = 1;
      R0 = R0 + R1;
      DM({FIELDS['completed']:#x}) = R0;
      R0 = LSHIFT R0 BY -10;
      R0 = R0 AND R1;
      R1 = 0;
      COMP(R0, R1);
''' + jump('publish_counts.', 'IF NE')
    s += publish_value('last', 12) + publish_value('max', 16)
    s += '      I0 = 0xdc004f53;\n' + jump('publish_marker.')
    s += label('publish_counts.') + publish_value('completed', 12) + publish_value('overbudget', 16)
    s += '      I0 = 0xdc014f53;\n' + label('publish_marker.')
    s += ''.join(f'      DM({p+4:#x}) = I0;\n' for p in PAGES)
    s += restore('exit_restore.', HOOKS[1][0], HOOKS[1][1])
    return s


def build(out, replace=False):
    raw = BASE.read_bytes()
    assert C.SHA(raw) == BASE_SHA
    out.mkdir(parents=True, exist_ok=replace)
    (out/'block-timing-diagnostic-check.json').unlink(missing_ok=True)
    doc = json.loads((BASE.parent/'build-receipt.json').read_text())
    asm = out/'block-timing.asm'
    s = source(); asm.write_text(s)
    be, offsets = A._selas(asm, out)
    labels = {n: CODE+v for n,v in O.symbols((out/'block-timing.doj').read_bytes()).items()}
    s = re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))', lambda x:x[1]+hex(labels[x[3]])+x[2], s)
    asm.write_text(s); be, again = A._selas(asm, out); assert again == offsets
    code = bytearray(O.load_bytes(be))
    widths = {a:b-a for a,b in zip(offsets, offsets[1:]+[len(code)])}
    fixes = []
    for off in offsets:
        if off+6 > len(code): continue
        value = C.S.to_value(code[off:off+6]); reg = (value>>32)&0x7f
        if value>>40 in (0x10, 0x11) and reg in (0x70, 0x73, 0x74):
            code[off:off+6] = C.S.to_bytes((value&~(0x7f<<32)) | ({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32))
            fixes.append(hex(CODE+off//2))
    for stamp in ('start', 'end'):
        for suffix, source_reg in (('clock', 0x69), ('mode', 0x72)):
            off = 2*(labels[f'{stamp}_{suffix}.']-CODE)
            assert widths[off] == 6, (stamp, suffix, widths[off])
            assert C.S.to_value(code[off:off+6])>>40 == 0x0f
            code[off:off+6] = C.S.to_bytes(D.ureg_copy(source_reg))
    hooks=[]; image=bytearray(raw)
    k=C.M.Digikit(C.SRC/'toolchains/digikit'); k.ldr.L2_BYTE_LIMIT=0x20100000
    memory=B.decode_view(k,raw)
    for (site, before, entry), replay in zip(HOOKS, ('entry_replay.', 'exit_replay.')):
        ins=k.st.decode_at(memory,None,site); assert ins.raw==before and ins.length_bytes==6
        off=2*(labels[replay]-CODE); assert widths[off] == 6
        code[off:off+6]=C.S.to_bytes(before)
        after=C.S.to_bytes(0x063e00000000|labels[entry])
        C.B.write_span(image,C.S.code_address(site),after)
        hooks.append(dict(site=hex(site),entry=hex(labels[entry]),replay=hex(labels[replay]),
                          resume=hex(site+3),before=hex(before),after=after.hex()))
    physical=C.S.code_address(CODE,window='l2')
    assert physical==0x200e0400 and physical+len(code)<=0x200e1000
    blocks=[(physical,bytes(code)),(STATE,bytes(len(FIELDS)*4))]
    regions=C.B.load_regions(raw)
    for at,data in blocks:
        assert not any(at<a+len(v) and a<at+len(data) for a,v in regions)
        regions.append((at,data))
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
    walk=C.B.walk(result); first,last=walk.blocks[7],walk.blocks[-1]
    assert first.flags==0x50 and last.flags==0x80
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
    doc['block_timing_diagnostic']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,
        hooks=hooks,code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),
        scratch=hex(STATE),scratch_bytes=len(FIELDS)*4,fields={n:hex(a) for n,a in FIELDS.items()},
        labels={n:hex(a) for n,a in labels.items()},instruction_offsets=offsets,
        system_register_fixes=fixes,preserved_clobbers=['I0','R0','R1','R2','MODE1','ASTATX','ASTATY'],
        clock_ureg='0x69',nominal_core_hz=1000000000,nominal_block_frames=32,sample_rate=48000,
        clock_evidence='firmware/ghidra/oneshot-proof/v7-source/docs/sharc-load.md: native boot clock init SW120230,20MHz CLKIN,MSEL100,DF0,CSEL2',
        nominal_budget_cycles=BUDGET,overbudget_comparison='unsigned duration > 666667',
        schema={'0x4f53dc00':{'3':'last_render_cycles','4':'max_render_cycles'},
                '0x4f53dc01':{'3':'completed_calls','4':'above_nominal_budget_calls'}},
        phase='(completed_calls >> 10) & 1',reply_pages=[hex(p) for p in PAGES],
        cf_byte_order='swap16 of each big-endian CF word',untouched_cf_words=[0,2,5,6],
        contract='Measure only the native1C2712 call between1C9FB9 and1C9FC3. Scalarize before saving R-registers, restore all clobbers/status/mode, and replay exact displaced instructions.',
        limits=['Counters/max retained since boot; warmup can dominate max. Compare count deltas before/after activity.',
                'Completed and above-budget counts are uint32 and wrap modulo2^32; host comparisons must account for wrap.',
                'EMUCLK low32 duration is modulo2^32; spans of one full wrap or longer are ambiguous.',
                'Nominal1GHz comes from native boot clock setup. Above budget is not proof of DAC underrun.',
                'Entry observer overhead after clock read is included; exit bookkeeping/publication is excluded.',
                'Reply publication is non-atomic. Payload is written before marker; same-tag samples may still race.',
                'Poll both phases at5Hz for at least3seconds. No hardware timing validation in offline checks.'])
    (out/'section_7.bin').write_bytes(result)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hooks=hooks),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--replace',action='store_true');a=p.parse_args();build(a.out,a.replace)
