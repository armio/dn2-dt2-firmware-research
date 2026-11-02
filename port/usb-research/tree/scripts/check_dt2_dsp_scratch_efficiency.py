#!/usr/bin/env python3
"""Execute current stereo wrappers; compare PCM, histories and registers byte-for-byte."""
from pathlib import Path
import argparse
import json
import math
import struct
import build_dt2_dsp_scratch_efficiency as P
import build_dt2_output_hook as H
import check_dt2_stereo_balance as S
import build_dt2_dsp_dma_l1 as L

C, B, F = P.C, P.B, P.F
T, OR, D, Q = S.T, S.OR, S.D, S.Q
STACK, LEFT, PARAMS, IO = 0x2ffe00, 0x241298, 0x2554b8, 0x257e6c
TABLE, OUT, INL = 0x805dc000, 0x805dd000, 0x805df000
CURRENT = [1,1,5,6,1,10,5,2,10,5,10,10,5,5,10,5]
MIXED = [0,1,2,3,4,5,6,7,8,9,10,0,1,2,3,4]


def check(folder):
    raw = (folder/'section_7.bin').read_bytes()
    doc = json.loads((folder/'build-receipt.json').read_text())
    spec = doc['dsp_scratch_efficiency']
    parent = Path(spec['base'])
    old = parent.read_bytes()
    assert C.SHA(raw) == doc['section7_sha256'] and C.SHA(old) == spec['base_sha256']
    # Reverse only our patches and appended reservation, including the LDR span.
    reverse = bytearray(raw)
    for patch in spec['patches']:
        C.B.write_span(reverse, int(patch['physical'],16), bytes.fromhex(patch['before']))
    before_walk, after_walk = C.B.walk(old), C.B.walk(raw)
    assert len(after_walk.blocks) == len(before_walk.blocks)+1
    added = after_walk.blocks[-2]
    assert (added.target, added.count) == (P.START, P.END-P.START)
    reverse = reverse[:added.offset]+reverse[added.end:]
    first = before_walk.blocks[7]
    reverse[first.offset:first.end] = old[first.offset:first.end]
    assert bytes(reverse) == old
    delivery_path = None
    delivery_cases = 0
    if C.SHA(old) == P.R004_SHA:
        assert spec['original_dsp_sha256'] == P.R004_SHA
        assert 'dsp_delivery_efficiency' not in doc
    else:
        delivery = doc['dsp_delivery_efficiency']
        baseline = (Path(delivery['base'])/'section_7.bin').read_bytes()
        full_reverse = bytearray(reverse)
        for patch in delivery['patches']:
            C.B.write_span(full_reverse, int(patch['physical'],16), bytes.fromhex(patch['before']))
        assert bytes(full_reverse) == baseline and C.SHA(baseline) == P.BASELINE_SHA
        delivery_path = parent.parent/'delivery-efficiency-check.json'
        delivery_check = json.loads(delivery_path.read_text())
        assert delivery_check['ok'] and delivery_check['section7_sha256'] == C.SHA(old)
        delivery_cases = sum(len(delivery_check[key]) for key in
                             ('early_copy_cases','lifecycle_cases','preserved_error_isr'))

    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    import sharc_modify_units
    modify_counts, _ = sharc_modify_units.install()
    memories = [B.decode_view(k, blob) for blob in (old, raw)]
    rows, oldrows = doc['dsp_l1_code_fix']['placements'], doc['dsp_startup_fix']['placements']
    def mv(a):
        return F.mapped(L.mapped(B.mapped(a, oldrows)), rows)
    before = B.decode_view(k, B.BASE.read_bytes())
    widths = {}
    for row in oldrows:
        if row['index'] not in (138,139,159,160,163,164,165):
            continue
        pcs = B.boundaries(k, before, row)+[row['old']+row['bytes']//2]
        for pc, end in zip(pcs, pcs[1:]):
            widths[mv(pc)] = 2*(end-pc)
    def runner(index, pc, regs):
        r = OR.runner_for(k, memories[index], pc, regs=regs)
        for address, width in widths.items():
            r._cache[address] = F.decode_fixed(k, memories[index], address, width)
        return r
    def put(r, address, value, size=4):
        OR._poke(k, r.state, address, value, size)
    def exact(r, address, size):
        return D.exact_bytes(k, r.state, address, size)
    def run(r, stop, limit=50000):
        status, at, steps = T.fx.run(r, limit, Q.EffectsFixups(), stop_at=[stop])
        assert (status, at) == ('stop', stop), (status, hex(at), steps)
        return steps
    def guards(r):
        for old_address, _, size in P.MOVES:
            OR.poke_bytes(k, r.state, old_address, bytes([0xa5])*size)
        for a in (P.START-4, P.END-4):
            put(r, a, 0x6a38c195)
    def assert_guards(r):
        for old_address, _, size in P.MOVES:
            assert exact(r, old_address, size) == bytes([0xa5])*size
        for a in (P.START-4, P.END-4):
            assert exact(r, a, 4) == struct.pack('<I', 0x6a38c195)

    regs = dict(R9=32, I9=LEFT, I6=STACK, I7=STACK-0x180, MODE1=0x01000000)
    runners = [runner(i, 0x1c9b33, regs) for i in range(2)]
    right = mv(H.H.E.P.BUFFERS)
    for r in runners:
        for a, v in [(STACK-96,LEFT+0x137c8),(STACK-116,PARAMS+0x1b4),
                     (STACK-120,IO),(STACK-228,0x1234),(STACK-224,0x5678),(IO+12,TABLE)]:
            put(r,a,v)
    cases = []
    for name, machines, n, event, shift in [
        ('all-six-samplers-trigger',MIXED,32,1,0),
        ('all-six-held-pan-level-ramp',MIXED,32,0,.1),
        ('current-twelve-sampler-assignments',CURRENT,32,1,0),
        ('current-release-tail',CURRENT,32,0,.2),
        ('all-stock', [i%5 for i in range(16)],32,1,0),
        ('zero-frames',CURRENT,0,0,0),
    ]:
        sentinel = struct.pack('<1024f', *(-.125-i/65536 for i in range(1024)))
        for r in runners:
            for voice, machine in enumerate(machines):
                put(r,0x25c520+2*voice,machine,2)
                put(r,LEFT+0x137c8+4*voice,INL+128*voice)
                put(r,TABLE+8*voice,OUT+256*voice)
                put(r,TABLE+8*voice+4,OUT+256*voice+128)
                pan=[.5,0,1,.25,.75,.5][voice%6]
                put(r,PARAMS+voice*0x234+0x230,T.F(pan))
                put(r,PARAMS+voice*0x234+0x22c,T.F(.75-shift))
                put(r,LEFT+0x1390c+voice,event,1)
                put(r,LEFT+0x1351c+44*voice+20,event)
                OR.poke_bytes(k,r.state,INL+128*voice,struct.pack('<32f',*(.002*(voice+1)*math.sin(i*.3) for i in range(32))))
                OR.poke_bytes(k,r.state,right+128*voice,struct.pack('<32f',*(.004*(voice+1)*math.cos(i*.2) for i in range(32))))
            OR.poke_bytes(k,r.state,OUT,sentinel)
        guards(runners[1])
        steps = []
        for index, r in enumerate(runners):
            r = r.fresh_call(0x1c9b33, regs={**regs, 'R9':n})
            saved = {reg:D.register(k,r.state,reg) for reg in H.REGS}
            saved.update(M0=0x1234,M1=0x5678)
            steps.append(run(r,0x1c9b37))
            assert {reg:D.register(k,r.state,reg) for reg in H.REGS} == saved
            runners[index] = r
        assert steps[0] == steps[1]
        for address, size in [(OUT,4096),(H.P.STATE,0x700)]:
            assert exact(runners[0],address,size) == exact(runners[1],address,size)
        actual = exact(runners[1],OUT,4096)
        for voice, machine in enumerate(machines):
            if machine < 5 or machine > 10 or not n:
                assert actual[voice*256:(voice+1)*256] == sentinel[voice*256:(voice+1)*256]
        assert all(math.isfinite(x) for x in struct.unpack('<1024f',actual))
        assert_guards(runners[1])
        cases.append(dict(case=name,instructions=steps[1],pcm_and_histories_exact=True,
            preserved_registers=99,stock_slots_unchanged=True,guards_intact=True))

    # Exercise both retained wrappers directly, including independent channel levels.
    wrappers = []
    for old_pc in (0x177000,0x178000):
        pc = mv(old_pc)
        pair = [runner(i,pc,dict(I6=STACK,I7=STACK-0x180,MODE1=0x01000000)) for i in range(2)]
        for name,n,panl,panr,level,event in [
            ('center',32,.5,.5,1,1),('hard-left',32,0,0,1,1),
            ('hard-right',32,1,1,1,1),('unequal-held-ramp',32,.25,.75,.5,0),
            ('one-frame',1,.5,.5,1,0),('zero',0,.5,.5,1,0),
        ]:
            for r in pair:
                values=[S.LEFT,S.RIGHT,S.OUTL,S.OUTR,n,T.F(panl),T.F(panr),T.F(level),T.F(1),T.F(.25),H.P.STATE+4,event,event]
                for i,value in enumerate(values):put(r,S.CTX+4*i,value)
                for a,values in [(S.LEFT,[.02*math.sin(x*.31)+.01 for x in range(32)]),
                                 (S.RIGHT,[.04*math.cos(x*.23) for x in range(32)])]:
                    OR.poke_bytes(k,r.state,a,struct.pack('<32f',*values))
                OR.poke_bytes(k,r.state,S.OUTL,bytes(128))
                OR.poke_bytes(k,r.state,S.OUTR,bytes(128))
            guards(pair[1])
            steps=[]
            for index,r in enumerate(pair):
                r=r.fresh_call(pc,regs=dict(R4=S.CTX,I6=STACK,I7=STACK-0x180),return_address=S.STOP)
                saved={reg:D.register(k,r.state,reg) for reg in H.P.REGS}
                steps.append(run(r,S.STOP))
                assert {reg:D.register(k,r.state,reg) for reg in H.P.REGS} == saved
                pair[index]=r
            assert steps[0] == steps[1]
            for address,size in [(S.OUTL,128),(S.OUTR,128),(H.P.STATE,0x700)]:
                assert exact(pair[0],address,size) == exact(pair[1],address,size)
            assert_guards(pair[1])
            wrappers.append(dict(entry=hex(pc),case=name,instructions=steps[1],
                pcm_and_histories_exact=True,preserved_registers=64,guards_intact=True))
    report=dict(ok=True,section7_sha256=C.SHA(raw),baseline_sha256=spec['original_dsp_sha256'],
        parent_sha256=C.SHA(old),scratch_reversal_exact=True,
        full_t200_reversal_exact=delivery_path is not None,
        delivery_check=str(delivery_path) if delivery_path else None,
        delivery_cases=delivery_cases,
        output_cases=cases,wrapper_cases=wrappers,patch_count=len(spec['patches']),
        save_bytes_moved=652,new_reservation_bytes=656,modify_corrections=dict(modify_counts),
        limitations=['Compiled instruction emulation uses existing native-operation fixups, fixture post-effect PCM and native scalar entry ABI.',
            'Stock output is represented by sentinels; all stock slots remain byte-identical.',
            'No timing speedup asserted; DDR cache/L2 arbitration and actual DSP load require hardware comparison.'])
    (folder/'dsp-efficiency-check.json').write_text(json.dumps(report,indent=2)+'\n')
    (folder/'release-scope-check.json').write_text(json.dumps(dict(ok=True,section7_sha256=C.SHA(raw),
        baseline_sha256=spec['original_dsp_sha256'],exact_reversal=True,
        scope=('Two observer redirects,' if delivery_path else '')+
              '454 private save-address literals,656 zero-initialized L2 bytes and LDR span only.'),indent=2)+'\n')
    print(json.dumps(dict(ok=True,section7_sha256=C.SHA(raw),output_cases=len(cases),wrapper_cases=len(wrappers))))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    check(parser.parse_args().folder)
