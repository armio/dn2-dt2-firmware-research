#!/usr/bin/env python3
"""Compare effects-only execution with the original native processing chain."""
from pathlib import Path
import argparse,json,struct,math
import build_dn2_right_process as P
import check_dn2_right_engine as I
C,E,T,OR,D=P.C,P.E,I.T,I.OR,I.D
STACK,STOP=0x2ffe00,0x175f00


def active_envelope(k,runner,record):
    # Existing Waverider M3 ADSR fixture: immediate attack, full sustain.
    # Constructor defaults include envelope timing and aren't an immediate
    # audible-note fixture. Keep the native envelope code in the comparison.
    for off,value in {0x20c:0,0x210:0,0x214:0,0x218:0,0x21c:1,0x220:.5,0x224:0}.items():
        OR._poke(k,runner.state,record+off,0 if off==0x20c else T.F(value),4)


class EffectsFixups(T.fx.Fixups):
    """Include the missing PEy immediate-shift operation in offline execution.

    ADI SHARC+ PRM3-39/3-40, SIMD compute example:
    https://www.analog.com/media/en/dsp-documentation/processor-manuals/SC58x-2158x-prm.pdf
    The pinned runner executes6b on PEx only; G1 misses its ShiftImm fields.
    A stale PEy SZ then makes an even-count loop execute its odd tail.
    Reuse the existing two-pass operation, including separate PE status.
    """
    def pre(self,runner,insn):
        if insn.type_name=='6b_shiftimm' and T.fx.simd(runner.state):
            assert T.fx.cond_of(insn.fields)==31
            self.note('SIMD immediate shift companion',runner.state.pc_sw)
            return ('replace',lambda rr:self.two_pass(rr,insn))
        return super().pre(runner,insn)


def boundaries(k,m,r,original,lo,hi,dest,skip=()):
    import sharc_disasm as dis
    fixes=[];pc=lo
    while pc<hi:
        ins=k.st.decode_at(original,None,pc);target=dest+pc-lo
        if not any(start<=pc<end for start,end in skip):
            actual=k.st.decode_at(m,None,target)
            if ins.length_bytes!=actual.length_bytes:
                matches=[x for x in [dis.decode_loaded_at(m,target),*dis._narrow_candidates_from_words(dis._loaded_words(m,target),target*2,64)]
                         if x.kind=='confident' and x.length_bytes==ins.length_bytes and x.type_name==ins.type_name]
                assert len({(x.raw,x.type_name) for x in matches})==1,(hex(target),matches)
                actual=matches[0];fixes.append(hex(target))
            r._cache[target]=actual
        pc+=ins.length_bytes//2
    return fixes


def main(folder):
    raw=(folder/'section_7.bin').read_bytes();doc=json.loads((folder/'build-receipt.json').read_text())
    assert C.SHA(raw)==doc['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    import sharc_modify_units
    counts,sites=sharc_modify_units.install()
    m=k.ldr.LoadedMemory.from_stream(raw);stock=k.ldr.LoadedMemory.from_stream(P.STOCK.read_bytes())
    r=OR.runner_for(k,m,E.INIT,regs={'I6':STACK,'I7':STACK-8})
    r=r.fresh_call(E.INIT,regs={'R4':E.ENGINE,'R8':E.PARAMS,'R12':E.CONFIG,'I6':STACK,'I7':STACK-8},return_address=STOP)
    def put(r,a,v):OR._poke(k,r.state,a,v,4)
    def call(r,pc):
        rr=r.fresh_call(pc,regs={'R4':E.ENGINE,'R8':E.PARAMS,'R12':E.CONFIG+0x40,'I6':STACK,'I7':STACK-8},return_address=STOP)
        put(rr,STACK-4,STOP-1);put(rr,STACK,STACK)
        return rr
    put(r,STACK-4,STOP-1);put(r,STACK,STACK);put(r,STACK+4,T.F(48000))
    fixes=[]
    for _,lo,hi,dest in E.SPANS:fixes+=boundaries(k,m,r,m,lo,hi,dest)
    fx=T.fx.Fixups();status,at,steps=T.fx.run(r,300000,fx,stop_at=[STOP])
    assert (status,at)==('stop',STOP),(status,at,steps)
    init_steps=steps
    put(r,E.CONFIG+0x40,32)
    for voice in range(16):
        put(r,E.PARAMS+voice*0x234+0x1b4,5)
        active_envelope(k,r,E.PARAMS+voice*0x234)
        # Real note inputs: pitch in semitones, normalized velocity, voice
        # trigger and AMP gate. Initialized idle engines correctly stay silent.
        put(r,E.ENGINE+0x1387c+4*voice,T.F(60))
        put(r,E.ENGINE+0x138bc+4*voice,T.F(.75))
        OR._poke(k,r.state,E.ENGINE+0x138fc+voice,1,1)
        OR._poke(k,r.state,E.ENGINE+0x1393c+voice,1,1)
        samples=[0.02*math.sin((x+voice)*math.tau/32) for x in range(32)]
        OR.poke_bytes(k,r.state,E.P.BUFFERS+voice*128,struct.pack('<32f',*samples))
    # Restore the original two instructions at the native sampler hook only
    # in the reference runner. Kind5 has no stock oscillator, leaving fixtures
    # as input to the complete native effects chain.
    reference=call(r,P.LO)
    OR.poke_bytes(k,reference.state,C.S.code_address(0x1c9448),stock.read_sw(0x1c9448,8))
    reference._cache[0x1c9448]=k.st.decode_at(stock,None,0x1c9448)
    reference._cache[0x1c944a]=k.st.decode_at(stock,None,0x1c944a)
    candidate=call(r,P.CODE)
    skip=[(int(x['pc'],16),int(x['pc'],16)+3) for x in doc['patches']]
    fixes+=boundaries(k,m,candidate,stock,P.LO,P.HI,P.CODE,skip)
    results=[]
    for name,rr,end in [('native',reference,0x1c9ad6),('right',candidate,STOP)]:
        fx=EffectsFixups();I.S.models(k,m,fx,None)
        status,at,steps=T.fx.run(rr,400000,fx,stop_at=[end])
        assert (status,at)==('stop',end),(name,status,at,steps)
        first_peak=max(map(abs,struct.unpack('<512f',D.exact_bytes(k,rr.state,E.P.BUFFERS,2048))))
        # Native cleanup latches the note event into1390C. AMP consumes that
        # latched event on the next block; a cold engine's first block is quiet.
        for voice in range(16):
            samples=[0.02*math.sin((x+voice)*math.tau/32) for x in range(32)]
            OR.poke_bytes(k,rr.state,E.P.BUFFERS+voice*128,struct.pack('<32f',*samples))
        rr=call(rr,P.LO if name=='native' else P.CODE)
        status,at,held_steps=T.fx.run(rr,400000,fx,stop_at=[end])
        assert (status,at)==('stop',end),(name,'held',status,at,held_steps)
        if name=='native':reference=rr
        else:candidate=rr
        results.append(dict(name=name,instructions=steps,held_instructions=held_steps,first_peak=first_peak,fixups=dict(fx.counts)))
    actual=D.exact_bytes(k,candidate.state,E.P.BUFFERS,2048)
    expected=D.exact_bytes(k,reference.state,E.P.BUFFERS,2048)
    assert actual==expected,'Audio differs from native effects chain'
    assert all(math.isfinite(x) for x in struct.unpack('<512f',actual))
    peak=max(map(abs,struct.unpack('<512f',actual)))
    assert peak>1e-12,('silent fixture',peak)
    assert D.register(k,candidate.state,'I6')==STACK and D.register(k,candidate.state,'I7')==STACK
    # Filter and AMP state must match native effects, independent of skipped
    # stock oscillator histories at the beginning of the engine object.
    a=D.exact_bytes(k,candidate.state,E.ENGINE+0xd908,0x14220-0xd908)
    b=D.exact_bytes(k,reference.state,E.ENGINE+0xd908,0x14220-0xd908)
    assert a==b,[(hex(0xd908+i),x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y][:30]
    allowed=[(E.ENGINE,E.ENGINE+0x14220),(E.DELAY,E.DELAY+0x80000),
             (E.SCRATCH,E.SCRATCH+0x100),(E.PARAMS,E.PARAMS+0x2340),
             (E.CONFIG,E.CONFIG+0x100),
             (C.S.data_address(E.P.BUFFERS),C.S.data_address(E.P.BUFFERS)+2048),
             (C.S.data_address(0x2ff000),C.S.data_address(0x300000))]
    outside=[a for a in candidate.state.overlay if not any(lo<=a<hi for lo,hi in allowed)]
    assert not outside,[hex(a) for a in sorted(outside)[:30]]
    report=dict(ok=True,section7_sha256=C.SHA(raw),results=results,init_instructions=init_steps,peak=peak,
                donor_boundary_decode_corrections=fixes,modify_corrections=dict(counts),
                audio_sha256=C.SHA(actual),native_audio_and_effects_state_equal=True,
                writes_confined_to_private_regions_and_stack=True,
                limitations=['Input and controls are fixtures.','No startup/block/reset hook or hardware check.'])
    (folder/'right-process-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);main(p.parse_args().folder)
