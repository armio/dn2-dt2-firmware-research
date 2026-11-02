#!/usr/bin/env python3
"""Check independent native voice resets and the effects-only constructor."""
from pathlib import Path
import argparse,json,struct
import build_dn2_right_engine as E
import check_dt2_sampler_dispatch as S
C=E.C;T,OR,D=S.T,S.OR,S.D
STACK,STOP=0x2ffe00,0x174f00


def main(folder):
    blob=(folder/'section_7.bin').read_bytes();doc=json.loads((folder/'build-receipt.json').read_text())
    assert C.SHA(blob)==doc['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    import sharc_modify_units
    modify_counts,modify_sites=sharc_modify_units.install()
    memory=k.ldr.LoadedMemory.from_stream(blob)
    r=OR.runner_for(k,memory,E.RESET,regs={'I6':STACK,'I7':STACK-8})
    def put(a,v):OR._poke(k,r.state,a,v,4)
    def word(a):return k.st._dm_read(r.state,a,4).value
    put(E.ENGINE,T.F(48000));put(E.ENGINE+4,T.F(1/32))
    # Native reset is the behavioral reference, including its universal-
    # register stores in SIMD mode. Do not assume that every audio word is
    # cleared by this routine; render overwrites active audio blocks later.
    ref=r.fresh_call(0x1c8b6d,regs={'R4':E.ENGINE,'R8':0,'I6':STACK,'I7':STACK-8},return_address=STOP)
    OR._poke(k,ref.state,STACK-4,STOP-1,4);OR._poke(k,ref.state,STACK,STACK,4)
    OR.poke_bytes(k,ref.state,0x804acf90,b'\x55'*128)
    rf=T.fx.Fixups();rs,ra,rn=T.fx.run(ref,200000,rf,stop_at=[STOP])
    assert (rs,ra)==('stop',STOP),(rs,ra,rn)
    native_audio=D.exact_bytes(k,ref.state,0x804acf90,128)
    native_state=bytearray(D.exact_bytes(k,ref.state,E.ENGINE,0x14220))
    for off,expected,new in [(0x137c8,0x804acf90,E.P.BUFFERS),(0x13808,0x804ace90,E.SCRATCH),
                             (0x12348+64,0x804ad790,E.DELAY)]:
        assert struct.unpack_from('<I',native_state,off)[0]==expected
        struct.pack_into('<I',native_state,off,new)
    cases=[]
    for voice in range(16):
        r=r.fresh_call(E.RESET,regs={'R4':E.ENGINE,'R8':voice,'I6':STACK,'I7':STACK-8},return_address=STOP)
        put(STACK-4,STOP-1);put(STACK,STACK)
        # Sentinels prove each reset actually clears its own audio block.
        OR.poke_bytes(k,r.state,E.P.BUFFERS+voice*128,b'\x55'*128)
        fix=T.fx.Fixups()
        status,at,n=T.fx.run(r,200000,fix,stop_at=[STOP])
        assert (status,at)==('stop',STOP),(voice,status,at,n)
        assert D.register(k,r.state,'I6')==STACK and D.register(k,r.state,'I7')==STACK
        assert word(E.ENGINE+0x137c8+voice*4)==E.P.BUFFERS+voice*128
        assert word(E.ENGINE+0x12348+voice*0x48+64)==E.DELAY+voice*0x8000
        assert word(E.ENGINE+0x13808)==E.SCRATCH
        assert D.exact_bytes(k,r.state,E.P.BUFFERS+voice*128,128)==native_audio
        if voice==0:assert D.exact_bytes(k,r.state,E.ENGINE,0x14220)==native_state
        cases.append(dict(voice=voice,instructions=n,fixups=dict(fix.counts)))
    allowed=[(E.ENGINE,E.ENGINE+0x14220),(E.DELAY,E.DELAY+0x80000),(E.SCRATCH,E.SCRATCH+0x100),
             (C.S.data_address(E.P.BUFFERS),C.S.data_address(E.P.BUFFERS)+2048),
             (C.S.data_address(0x2ff000),C.S.data_address(0x300000))]
    outside=[a for a in r.state.overlay if not any(lo<=a<hi for lo,hi in allowed)]
    assert not outside,[(hex(a),r.state.overlay[a]) for a in sorted(outside)[:40]]
    # Run the actual adapted constructor on fresh memory, including original
    # header stores, parameter defaults, and its sixteen reset calls.
    init=OR.runner_for(k,memory,E.INIT,regs={'I6':STACK,'I7':STACK-8})
    init=init.fresh_call(E.INIT,regs={'R4':E.ENGINE,'R8':E.PARAMS,'R12':E.CONFIG,
                                    'I6':STACK,'I7':STACK-8},return_address=STOP)
    OR._poke(k,init.state,STACK-4,STOP-1,4)
    OR._poke(k,init.state,STACK,STACK,4)
    OR._poke(k,init.state,STACK+4,T.F(48000),4)
    # Relocation changes following bytes, which can confuse the heuristic
    # mixed-width decoder. Preserve the donor instruction boundaries.
    import sharc_disasm as dis
    width_fixes=[]
    for _,lo,hi,dest in E.SPANS:
        pc=lo
        while pc<hi:
            original=k.st.decode_at(memory,None,pc)
            target=dest+pc-lo;ins=k.st.decode_at(memory,None,target)
            if ins.length_bytes!=original.length_bytes:
                matches=[x for x in [dis.decode_loaded_at(memory,target),*dis._narrow_candidates_from_words(dis._loaded_words(memory,target),target*2,64)]
                         if x.kind=='confident' and x.length_bytes==original.length_bytes and x.type_name==original.type_name]
                assert len({(x.raw,x.type_name) for x in matches})==1,(hex(target),matches)
                ins=matches[0];width_fixes.append(hex(target))
            init._cache[target]=ins
            pc+=original.length_bytes//2
    init_fix=T.fx.Fixups()
    status,at,steps=T.fx.run(init,300000,init_fix,stop_at=[STOP])
    assert (status,at)==('stop',STOP),(status,at,steps)
    def iw(a):return k.st._dm_read(init.state,a,4).value
    assert D.register(k,init.state,'R0')==0
    assert D.register(k,init.state,'I6')==STACK and D.register(k,init.state,'I7')==STACK
    assert iw(E.ENGINE)==T.F(48000) and iw(E.ENGINE+4)==T.F(1/32)
    for voice in range(16):
        assert iw(E.ENGINE+0x137c8+voice*4)==E.P.BUFFERS+voice*128
        assert iw(E.ENGINE+0x12348+voice*0x48+64)==E.DELAY+voice*0x8000
    assert iw(E.ENGINE+0x13808)==E.SCRATCH
    init_allowed=allowed+[(E.PARAMS,E.PARAMS+0x2340),(E.CONFIG,E.CONFIG+0x100)]
    outside=[a for a in init.state.overlay if not any(lo<=a<hi for lo,hi in init_allowed)]
    assert not outside,[(hex(a),init.state.overlay[a]) for a in sorted(outside)[:40]]
    (folder/'right-engine-state.bin').write_bytes(D.exact_bytes(k,r.state,E.ENGINE,0x14220))
    report=dict(modify_units_correction=dict(counts=dict(modify_counts),sites=[hex(x) for x in sorted(modify_sites)]),ok=True,section7_sha256=C.SHA(blob),cases=cases,overlay_bytes=len(r.state.overlay),writes_confined_to_private_regions_and_stack=True,
                engine_state_sha256=C.SHA((folder/'right-engine-state.bin').read_bytes()),native_reference_instructions=rn,
                native_state_equal_except_three_rebound_pointers=True,
                constructor=dict(instructions=steps,fixups=dict(init_fix.counts),overlay_bytes=len(init.state.overlay),writes_confined=True,donor_boundary_decode_corrections=width_fixes),
                scope='Actual relocated native reset1C8B6D and effects-only constructor1C8E1C; native filter/AMP initialization on all16 independent right voices; private pointers, header stores and stack return.',
                limitations=['Oscillator/global initializers intentionally bypassed: this engine is only for processing already-rendered sampler audio.','No processing/startup/reset hooks or hardware claim.'])
    (folder/'right-engine-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    main(p.parse_args().folder)
