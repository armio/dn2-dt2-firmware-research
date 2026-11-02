#!/usr/bin/env python3
"""Compare original DT2 coefficient/history/mix with its composed wrapper."""
from pathlib import Path
import argparse,json,struct,math
import build_dt2_stereo_balance as P
import check_dt2_stereo_voices as V
import check_dn2_right_process as Q
C,T,OR,D=P.C,Q.T,Q.OR,Q.D
CTX,LEFT,RIGHT,OUTL,OUTR,STOP=0x805d9e80,0x2fd000,0x2fd080,0x2fd900,0x2fd980,0x177f00


def main(folder):
    raw=(folder/'section_7.bin').read_bytes();doc=json.loads((folder/'build-receipt.json').read_text());assert C.SHA(raw)==doc['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    import sharc_modify_units
    counts,sites=sharc_modify_units.install()
    m=k.ldr.LoadedMemory.from_stream(raw);donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
    r=OR.runner_for(k,m,P.CODE,regs={'I6':0x2ffe00,'I7':0x2ffd00})
    ref=OR.runner_for(k,donor,P.LO,regs={'I6':P.FRAME,'I7':0x2ffd00})
    widths=V.boundaries(k,m,r,folder,'stereo-balance',P.CODE,doc['wrapper_bytes'])
    widths+=Q.boundaries(k,m,r,donor,P.LO,P.HI,P.PAN)
    def put(rr,a,v):OR._poke(k,rr.state,a,v,4)
    OR.poke_bytes(k,ref.state,P.STATE,bytes(0x700))
    results=[]
    for name,n,panl,panr,ll,lr,gate in [('center',32,.5,.5,1,1,1),('pan-right',32,1,1,1,1,1),('pan-left',32,0,0,1,1,1),('unequal-levels',32,.5,.5,.5,1,1),('held-pan-ramp',32,.75,.75,1,1,0),('one-frame',1,.5,.5,1,1,0),('zero',0,.5,.5,1,1,0)]:
        state=P.STATE+4
        values=[LEFT,RIGHT,OUTL,OUTR,n,T.F(panl),T.F(panr),T.F(ll),T.F(lr),T.F(.25),state,gate,gate]
        for i,value in enumerate(values):put(r,CTX+4*i,value)
        l=struct.pack('<32f',*(.02*math.sin(x*.31)+.01 for x in range(32)))
        rt=struct.pack('<32f',*(.04*math.cos(x*.23) for x in range(32)))
        for rr in (r,ref):
            OR.poke_bytes(k,rr.state,LEFT,l);OR.poke_bytes(k,rr.state,RIGHT,rt)
            OR.poke_bytes(k,rr.state,OUTL,bytes(128));OR.poke_bytes(k,rr.state,OUTR,bytes(128))
        r=r.fresh_call(P.CODE,regs={'R4':CTX,'I6':0x2ffe00,'I7':0x2ffd00},return_address=STOP)
        saved={reg:D.register(k,r.state,reg) for reg in P.REGS}
        fx=Q.EffectsFixups();status,at,steps=T.fx.run(r,30000,fx,stop_at=[STOP]);assert (status,at)==('stop',STOP),(name,status,at,steps)
        assert {reg:D.register(k,r.state,reg) for reg in P.REGS}==saved
        ref_steps=0
        if n:
            for a,value in [(P.PARAM-104,T.F(panl)),(P.PARAM+116,T.F(panr)),(P.PARAM-108,T.F(ll)),(P.PARAM+112,T.F(lr)),
                            (P.FRAME-12,T.F(1/n)),(P.FRAME-40,T.F(1/n)),(P.FRAME-8,0),(P.GATE,gate),(P.AMP+20,gate),
                            (P.PAIRS,LEFT),(P.PAIRS+4,RIGHT),(P.PAIRS+8,OUTL),(P.PAIRS+12,OUTR)]:put(ref,a,value)
            regs=dict(I5=P.PARAM,I4=state,I10=state+0x380,I6=P.FRAME,I13=P.PARAM,I11=P.GATE,I9=P.AMP,I8=0,
                      I15=P.PAIRS+0x240,I14=0,M0=P.PAIRS+8,R15=n,R4=T.F(.25),R8=T.F(128),R0=T.F(128),R11=T.F(127),R12=0,R14=0)
            ref=ref.fresh_call(P.LO,regs=regs)
            fx=Q.EffectsFixups();status,at,ref_steps=T.fx.run(ref,30000,fx,stop_at=[0x1c7158]);assert (status,at)==('stop',0x1c7158),(name,status,at,ref_steps)
        for a,size in [(OUTL,128),(OUTR,128),(P.STATE,0x700)]:
            actual=D.exact_bytes(k,r.state,a,size);expected=D.exact_bytes(k,ref.state,a,size)
            assert actual==expected,(name,hex(a),[(i,x,y) for i,(x,y) in enumerate(zip(actual,expected)) if x!=y][:8])
        out=struct.unpack('<64f',D.exact_bytes(k,r.state,OUTL,128)+D.exact_bytes(k,r.state,OUTR,128))
        assert all(math.isfinite(x) for x in out)
        if n>1:assert max(map(abs,out))>0
        if name=='center':
            assert abs(out[0]*4-out[32])<1e-7, 'Distinct stereo channels lost their input ratio'
        if name=='pan-right':assert all(x==0 for x in out[:32])
        if name=='pan-left':assert all(x==0 for x in out[32:])
        results.append(dict(case=name,frames=n,instructions=steps,donor_instructions=ref_steps,peak=max(map(abs,out)),first_left=out[0],first_right=out[32]))
    report=dict(ok=True,section7_sha256=C.SHA(raw),cases=results,preserved_register_count=len(P.REGS),native_outputs_and_full_pan_history_equal=True,
                native_tables_byte_identical=True,decoder_boundary_corrections=widths,modify_corrections=dict(counts),
                limitations=['Channel pan/level inputs and gate flags are fixtures; UI-to-channel mapping still needs binding.','No final DN2 output hook or hardware verification.'])
    (folder/'stereo-balance-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);main(p.parse_args().folder)
