#!/usr/bin/env python3
"""Exercise paired sampler state/render through the installed DN2 adapter."""
from pathlib import Path
import argparse,json,math,struct
import build_dt2_stereo_voices as P
import check_dt2_sampler_dispatch as S
C,V=P.C,P.V
T,OR,D=S.T,S.OR,S.D
STACK=0x2ffe00
VOICE=1
LEFTREC=0x30e000+VOICE*472
RIGHTREC=P.RECORDS+VOICE*472
OUT,FRAME=0x30df00,0x25c566+146*VOICE


def boundaries(k,m,r,folder,stem,code,size):
    import sharc_disasm as dis
    syms=P.O.symbols((folder/(stem+'.doj')).read_bytes())
    offsets=sorted(v*2 for n,v in syms.items() if n.startswith('x_i'))+[size]
    fixed=[]
    for lo,hi in zip(offsets,offsets[1:]):
        pc=code+lo//2;ins=k.st.decode_at(m,None,pc)
        if ins.length_bytes!=hi-lo:
            matches=[x for x in [dis.decode_loaded_at(m,pc),*dis._narrow_candidates_from_words(dis._loaded_words(m,pc),pc*2,64)] if x.kind=='confident' and x.length_bytes==hi-lo]
            assert len({(x.raw,x.type_name) for x in matches})==1,(hex(pc),matches)
            ins=matches[0];fixed.append(hex(pc))
        r._cache[pc]=ins
    return fixed


def main(folder):
    raw=(folder/'section_7.bin').read_bytes();doc=json.loads((folder/'build-receipt.json').read_text())
    assert C.SHA(raw)==doc['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    import sharc_modify_units
    modify_counts,modify_sites=sharc_modify_units.install()
    memory=k.ldr.LoadedMemory.from_stream(raw)
    old=C.ROOT/'output/dn2-research/dt2-voice-samples-20261009'
    olddoc=json.loads((old/'build-receipt.json').read_text())
    cases=[];decode_fixes=set()
    def put(r,a,v,n=4):OR._poke(k,r.state,a,v,n)
    def word(r,a):return k.st._dm_read(r.state,a,4).value
    pcm=[int(12000*math.sin(i*math.tau/64))//2*2 for i in range(64)]*1000
    left=struct.pack('<64000h',*pcm);right=struct.pack('<64000h',*(-v//2 for v in pcm))
    regs=dict(I6=STACK,I7=STACK,R0=0x12345678,R9=32)
    def initialize(memory,machine,channel=None):
        r=OR.runner_for(k,memory,0x185800,regs=regs)
        decode_fixes.update(boundaries(k,memory,r,old,'voice-samples',V.CODE,olddoc['code_bytes']))
        if channel is None:decode_fixes.update(boundaries(k,memory,r,folder,'stereo-voices',P.CODE,doc['code_bytes']))
        OR.poke_bytes(k,r.state,0x2ffc00,bytes(0x400));OR.poke_bytes(k,r.state,OUT,bytes(128))
        for voice in range(16):
            put(r,0x25566c+0x234*voice,5 if voice==VOICE else 0)
            put(r,0x254a60+4*voice,OUT)
            put(r,0x25c520+2*voice,machine if voice==VOICE else 0,2)
        for off,pcm_bytes in ((0x2000,left),(0x40000,right)):
            OR.poke_bytes(k,r.state,V.B.POOL+off-10,pcm_bytes[-10:]+pcm_bytes+pcm_bytes[:10])
        pointers=(0x2000,0x40000) if channel is None else (channel,channel)
        for i,value in enumerate((*pointers,128000,48000,int(channel is None))):put(r,V.B.STATE+1023*20+i*4,value)
        put(r,0x310800,0);put(r,0x254b14+VOICE*4,T.F(60));put(r,0x25c564,14814,2)
        words=S.PARAMS[machine]
        controls={25:0x4000,26:3<<8,28:1023,31:words[0],32:words[1],33:words[2],34:0x6400,35:0,36:450,37:0,38:1800,39:0,40:900}
        for param,value in controls.items():put(r,FRAME+2*(param-25),value,2)
        return r
    reference_memory=k.ldr.LoadedMemory.from_stream((old/'section_7.bin').read_bytes())
    for machine in S.A.MACHINES:
        r=initialize(memory,machine)
        refs=[initialize(reference_memory,machine,channel) for channel in (0x2000,0x40000)]
        blocks=[]
        for block in range(2):
            if block:r=r.fresh_call(0x185800,regs=regs)
            if block:put(r,FRAME+18,0,2)  # Live sample-level fade to zero.
            for a in range(0x254b94,0x254c04,4):put(r,a,0)
            if block==0:put(r,0x254b94,1<<(8*VOICE))
            fix=T.fx.Fixups();S.models(k,memory,fix,None)
            status,at,n=T.fx.run(r,100000,fix,stop_at=[0x185d0a,C.FAULT])
            assert (status,at)==('stop',0x185d0a),(machine,block,status,at,n)
            assert word(r,P.VALID+4*VOICE)==1
            assert word(r,LEFTREC)==V.B.POOL+0x2000 and word(r,RIGHTREC)==V.B.POOL+0x40000
            lraw=D.exact_bytes(k,r.state,OUT,128);rraw=D.exact_bytes(k,r.state,P.BUFFERS+VOICE*128,128)
            lvalues,rvalues=struct.unpack('<32f',lraw),struct.unpack('<32f',rraw)
            peak=max(map(abs,lvalues));assert peak>0,(machine,block,peak)
            # Compare each channel with a separate execution of the existing
            # mono adapter. Native resampling need not be perfectly linear
            # under signed-16 conversion/rounding, so do not infer right PCM
            # by multiplying the left float output.
            reference_counts=[];leveled=[]
            for ch,ref in enumerate(refs):
                if block:ref=ref.fresh_call(0x185800,regs=regs)
                if block:put(ref,FRAME+18,0,2)
                for a in range(0x254b94,0x254c04,4):put(ref,a,0)
                if block==0:put(ref,0x254b94,1<<(8*VOICE))
                rf=T.fx.Fixups();S.models(k,reference_memory,rf,None)
                rs,ra,rn=T.fx.run(ref,100000,rf,stop_at=[0x185d0a,C.FAULT])
                assert (rs,ra)==('stop',0x185d0a),(machine,block,ch,rs,ra,rn)
                expected=D.exact_bytes(k,ref.state,OUT,128)
                assert (lraw,rraw)[ch]==expected,(machine,block,ch,'channel differs from mono execution')
                rs,ra,tailn=T.fx.run(ref,100000,rf,stop_at=[0x1c944c,C.FAULT])
                assert (rs,ra)==('stop',0x1c944c),(machine,block,ch,rs,ra,tailn)
                leveled.append(D.exact_bytes(k,ref.state,OUT,128))
                refs[ch]=ref;reference_counts.append(rn+tailn)
            lphase=D.exact_bytes(k,r.state,LEFTREC+0x1b0,8);rphase=D.exact_bytes(k,r.state,RIGHTREC+0x1b0,8)
            assert lphase==rphase,(machine,block,lphase.hex(),rphase.hex())
            status,at,tail=T.fx.run(r,100000,fix,stop_at=[0x1c944c,C.FAULT])
            assert (status,at)==('stop',0x1c944c),(machine,block,status,at,tail)
            assert D.exact_bytes(k,r.state,OUT,128)==leveled[0]
            assert D.exact_bytes(k,r.state,P.BUFFERS+VOICE*128,128)==leveled[1]
            assert D.register(k,r.state,'I6')==STACK and D.register(k,r.state,'I7')==STACK
            blocks.append(dict(instructions=n+tail,left_peak=peak,right_peak=max(map(abs,rvalues)),channels_equal_mono_references=True,reference_instructions=reference_counts,phase=struct.unpack('<Q',lphase)[0]))
        # A block with no sampler voices must not advertise old right audio.
        put(r,0x25566c+0x234*VOICE,0)
        r=r.fresh_call(0x185800,regs=regs)
        fix=T.fx.Fixups();S.models(k,memory,fix,None)
        status,at,n=T.fx.run(r,100000,fix,stop_at=[0x1c944c,C.FAULT])
        assert (status,at)==('stop',0x1c944c),(machine,status,at,n)
        assert all(word(r,P.VALID+i*4)==0 for i in range(16))
        cases.append(dict(machine=S.A.MACHINES[machine],blocks=blocks,live_level_matches_both_mono_references=True,stale_right_validity_cleared=True))
    report=dict(modify_units_correction=dict(counts=dict(modify_counts),sites=[hex(x) for x in sorted(modify_sites)]),ok=True,section7_sha256=C.SHA(raw),cases=cases,assembler_boundary_decode_corrections=sorted(decode_fixes),
                scope='Actual installed DN2 sampler adapter, original DT2 bind/arm/setup/render on independent left/right records, trigger then held block, and inactive block.',
                limitations=['Right audio has sample level but is pre-effects and not connected to device outputs.','Control and PCM inputs are fixtures; existing instruction/status-copy models retained.','No hardware stereo claim.'])
    (folder/'stereo-voices-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    main(p.parse_args().folder)
