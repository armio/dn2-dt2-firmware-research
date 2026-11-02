#!/usr/bin/env python3
"""Execute exact R007 guard/export/publication bytes against pinned R005."""
from pathlib import Path
import argparse
import copy
import itertools
import json
import struct

import build_dt2_usb_guarded_publication as P
import sharc_dn2_fixups as fx
import sharc_modify_units as units
from check_dt2_dsp_render_diagnostic import MarkerFixups, REGS

C=P.C


def check(folder):
    raw=(folder/'section_7.bin').read_bytes();oldraw=P.BASE.read_bytes()
    doc=json.loads((folder/'build-receipt.json').read_text());spec=doc['usb_guarded_publication']
    assert C.SHA(oldraw)==P.BASE_SHA and C.SHA(raw)==doc['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    fx.bind(str(C.SRC/'toolchains/digikit/tools'));units.install()
    old,m=(P.B.decode_view(k,data) for data in (oldraw,raw))
    labels={n:int(v,16) for n,v in spec['labels'].items()};hooks={h['name']:h for h in spec['hooks']}
    offsets=spec['instruction_offsets']+[spec['code_bytes']];decoded={}
    for a,b in zip(offsets,offsets[1:]):
        ins=P.P.E.F.decode_fixed(k,m,P.CODE+a//2,b-a);assert ins.length_bytes==b-a
        decoded[P.CODE+a//2]=ins
        if ins.type_name=='15a':
            reg=(ins.raw>>32)&0x7f
            assert not (0x10<=reg<=0x4f and ((reg>>3)&1)==ins.fields['g'])
    oldspec=doc['codec_delivery'];oo=oldspec['instruction_offsets']+[oldspec['code_bytes']]
    old_decoded={int(oldspec['code'],16)+a//2:P.P.E.F.decode_fixed(k,old,int(oldspec['code'],16)+a//2,b-a)
                 for a,b in zip(oo,oo[1:])}
    a,b=C.B.walk(oldraw).blocks,C.B.walk(raw).blocks
    assert len(b)==len(a)+3
    assert [(x.target,x.count) for x in b[-4:-1]]==[(P.PHYSICAL,spec['code_bytes']),(P.STATE,P.END-P.STATE),(P.SINK,P.SINK_END-P.SINK)]
    restored=bytearray(raw[:b[-4].offset]+raw[b[-1].offset:])
    for h in hooks.values():C.B.write_span(restored,int(h['physical'],16),bytes.fromhex(h['before']))
    first=a[7];restored[first.offset:first.end]=oldraw[first.offset:first.end]
    assert bytes(restored)==oldraw
    for lo,hi in ((0x1c266c,0x1c2692),(0x1c2692,0x1c26ef)):
        assert m.read_sw(lo,2*(hi-lo))==old.read_sw(lo,2*(hi-lo))
    for name in ('before','after'):assert m.read_sw(labels[name+'_replay.'],6)==bytes.fromhex(hooks[name]['before'])
    for family in ('codec_stage_commit','codec_delivery','buffer_phase_accounting'):
        d=doc[family];pc=int(d['code'],16);size=d['code_bytes']
        # Only legacy codec publisher phase15 entry is intentionally changed.
        if family!='codec_delivery':assert m.read_sw(pc,size)==old.read_sw(pc,size)

    def put(r,a,v):assert k.st._dm_write(r.state,a,4,k.st.Const(v&0xffffffff))
    def read(r,a):
        value=k.st._dm_read(r.state,a,4);assert isinstance(value,k.st.Const),(hex(a),value)
        return value.value
    def reg(r,n,v):r.state.uregs[k.st.UREG_CODES[n]]=k.st.Const(v&0xffffffff)
    def rval(r,n):return r.state.uregs[k.st.UREG_CODES[n]].value
    def dma(r,bus,original,kind='inactive',count=None):
        base,pages,mask,size,minimum,maximum=P.BUS[bus];target=original^mask
        start=original+0x28000000 if kind=='inactive' else target+0x28000000
        n=maximum-32 if count is None else count
        unit=4 if bus=='tdm' else 2
        assert maximum*unit==size
        cur=start+(maximum-n)*unit
        if kind=='drained':n=0;cur=start+size
        for off,value in ((4,start),(0x2c,cur),(0x34,n)):put(r,base+off,value)
    def runner(memory=m,simd=False,sat=False,tdm=0x2c08e8,spi=0x2c49d0):
        regs={n:(0x12345000+0x137*i)&0xffffffff for i,n in enumerate(REGS)}
        regs.update(MODE1=0x01000000|(0x200000 if simd else 0)|(0x2000 if sat else 0),
                    ASTATX=0x4005a5,ASTATY=0x200a5a,I6=0x2ff000,I7=0x2fef00,
                    I3=tdm,I13=spi,L6=0,L7=0,M5=0,M6=1,M7=0xffffffff)
        r=k.run.Runner(memory,0x1c265b,regs=regs,explicit_memory_model=True)
        r._cache.update(old_decoded)
        if memory is m:
            r._cache.update(decoded)
            # Phase15 replaces an instruction in the parent's cached publisher.
            # Never execute its old cached decode over the candidate branch.
            for h in hooks.values():
                pc=int(h['site'],16);r._cache[pc]=k.st.decode_at(m,None,pc)
        for n in ('MRF','MRB','MSF','MSB'):r.state.special[n]=k.st.MR((1<<80)-1,0x123456789abcdef01234)
        for bus,original in (('tdm',tdm),('spi',spi)):dma(r,bus,original)
        put(r,P.P.WIRE+24,0);put(r,P.P.WIRE+28,0)
        for page in P.P.T.PAGES:
            for off in range(0,28,4):put(r,page+off,0x70123400+off//4)
        return r
    def execute(r,name,*,clock=1000,extra=None,native=False,allowed=None):
        h=hooks[name];r.state.pc_sw=int(h['site'],16);r.state.stopped=None
        before=dict(r.state.overlay);fix=MarkerFixups()
        if not native and name in ('before','after'):
            fix.hooks[labels[name+'_clock.']+3]=lambda run:reg(run,'I0',clock)
        if extra:fix.hooks.update(extra)
        stop=int(h['resume'],16);result=fx.run(r,10000,fix,stop_at=[stop])
        assert result[:2]==('stop',stop),(name,result,r.state.stopped)
        assert not r.state.pending and not r.state.call_stack and not r.state.loops
        if not native:
            permitted=set(range(P.STATE,P.END))|(allowed or set())
            for address in set(before)|set(r.state.overlay):
                if before.get(address)!=r.state.overlay.get(address):assert address in permitted,(name,hex(address))
        return result[2]
    def same_arch(a,b,except_regs=()):
        ignored={k.st.UREG_CODES[n] for n in except_regs}
        assert {c:v for c,v in a.state.uregs.items() if c not in ignored}=={c:v for c,v in b.state.uregs.items() if c not in ignored},[(n,a.state.uregs.get(c),b.state.uregs.get(c)) for n,c in k.st.UREG_CODES.items() if c not in ignored and a.state.uregs.get(c)!=b.state.uregs.get(c)]
        assert a.state.special==b.state.special

    # Execute unchanged native initialization, rather than inferring alternating
    # ownership from addresses alone. A drained target's successor is the other
    # page in each exact circular list.
    descriptors=[]
    r=runner();r.state.pc_sw=0x1ca373
    result=fx.run(r,100,MarkerFixups(),stop_at=[0x1ca38f]);assert result[:2]==('stop',0x1ca38f)
    for descriptor,page,next_descriptor in ((0x2c28e8,0x2c08e8,0x2c2904),(0x2c2904,0x2c10e8,0x2c28e8)):
        assert read(r,descriptor)==next_descriptor and read(r,descriptor+4)==page
        descriptors.append(dict(bus='tdm',descriptor=hex(descriptor),page=hex(page),next_descriptor=hex(next_descriptor)))
    r=runner();reg(r,'R13',0xabc);r.state.pc_sw=0x1ca4f6
    result=fx.run(r,200,MarkerFixups(),stop_at=[0x1ca55e]);assert result[:2]==('stop',0x1ca55e)
    for descriptor,page,next_descriptor in ((0x2c2998,0x2c59d0,0x2c29b4),(0x2c29b4,0x2c49d0,0x2c2998)):
        assert read(r,descriptor)==next_descriptor and read(r,descriptor+4)==page
        assert read(r,descriptor+12)==1374 and read(r,descriptor+16)==2
        descriptors.append(dict(bus='spi',descriptor=hex(descriptor),page=hex(page),next_descriptor=hex(next_descriptor),count=1374,modify_bytes=2))

    abi=[];admission=[]
    for simd,sat,tp,sp,tk,sk in itertools.product((False,True),(False,True),P.BUS['tdm'][1],P.BUS['spi'][1],('inactive','drained'),('inactive','drained')):
        a=runner(old,simd,sat,tp,sp);b=runner(m,simd,sat,tp,sp)
        dma(b,'tdm',tp,tk);dma(b,'spi',sp,sk)
        execute(a,'before',native=True);steps=execute(b,'before')
        same_arch(a,b,('I3','I13'))
        assert rval(b,'I3')==tp^0x1800 and rval(b,'I13')==sp^0x1000
        assert read(b,P.G['accepted'])==1 and read(b,P.G['rejected'])==0 and read(b,P.G['armed'])==1
        reg(a,'I4',sp+112);reg(b,'I4',(sp^0x1000)+112)
        execute(a,'after',native=True);steps+=execute(b,'after',clock=11000)
        same_arch(a,b,('I3',));assert rval(b,'I13')==sp and read(b,P.G['crossed'])==0
        abi.append(dict(simd=simd,saturation=sat,tdm=hex(tp),spi=hex(sp),tdm_state=tk,spi_state=sk,instructions=steps))
    for bus in P.BUS:
        base,pages,mask,size,minimum,maximum=P.BUS[bus]
        for kind,value,expected in (('count',minimum-1,False),('count',minimum,True),('count',maximum,True),('count',maximum+1,False),
                                    ('count',0,False),('current',-4,False),('current',size,False),('unknown_start',0x12340000,False),
                                    ('drained_bad_cur',size-4,False),('drained_bad_count',1,False),('torn_start',0x12340000,False)):
            r=runner();original=rval(r,'I3' if bus=='tdm' else 'I13');start=original+0x28000000;extra={}
            if kind=='count':
                put(r,base+0x34,value);put(r,base+0x2c,start+(maximum-value)*(4 if bus=='tdm' else 2))
            elif kind=='current':put(r,base+0x2c,start+value)
            elif kind=='unknown_start':put(r,base+4,value)
            elif kind.startswith('drained'):
                dma(r,bus,original,'drained');put(r,base+(0x2c if kind=='drained_bad_cur' else 0x34),(original^mask)+0x28000000+value if kind=='drained_bad_cur' else value)
            else:extra[labels[f'before_{bus}_start_again.']]=lambda run,base=base,value=value:put(run,base+4,value)
            execute(r,'before',extra=extra,allowed=set(range(base,base+0x40)))
            assert bool(read(r,P.G['armed']))==expected,(bus,kind,value)
            if not expected:assert rval(r,'I3')==rval(r,'I13')==P.SINK and read(r,P.G['accepted'])==0 and read(r,P.G['rejected'])==1
            admission.append(dict(bus=bus,case=kind,value=value,accepted=expected))
    for register in ('I3','I13'):
        for value in (0,0x2c00e8,0x2c18e8,0x2c69d0):
            r=runner();reg(r,register,value);execute(r,'before');assert rval(r,'I3')==rval(r,'I13')==P.SINK
            execute(r,'after');assert rval(r,'I13')==(value if register=='I13' else 0x2c49d0)
            admission.append(dict(register=register,value=hex(value),accepted=False))
    crosses=[]
    for bus in P.BUS:
        base,pages,mask,size,minimum,maximum=P.BUS[bus]
        for kind in ('target_active','other_count0','count_reload','current_outside','torn_start','drained_to_other','drained_still','whole_target_completed'):
            r=runner();original=rval(r,'I3' if bus=='tdm' else 'I13');target=original^mask
            if kind.startswith('drained'):dma(r,bus,original,'drained')
            execute(r,'before');extra={}
            if kind=='target_active':put(r,base+4,target+0x28000000);put(r,base+0x2c,target+0x28000000+64)
            elif kind=='other_count0':put(r,base+0x34,0)
            elif kind=='count_reload':put(r,base+0x34,maximum)
            elif kind=='current_outside':put(r,base+0x2c,original+0x28000000+size)
            elif kind=='torn_start':extra[labels[f'after_{bus}_start_again.']]=lambda run,base=base:put(run,base+4,0x12340000)
            elif kind=='drained_to_other':dma(r,bus,original)
            elif kind=='whole_target_completed':dma(r,bus,original,'drained')
            execute(r,'after',clock=11000,extra=extra,allowed=set(range(base,base+0x40)))
            expected=not kind.startswith('drained')
            assert bool(read(r,P.G['crossed']))==expected,(bus,kind,read(r,P.G['cross_flags']))
            crosses.append(dict(bus=bus,case=kind,crossed=expected))
    for start,end,cross in ((1000,100999,False),(1000,101000,True),(0xffffff00,0x200,False)):
        r=runner();execute(r,'before',clock=start);execute(r,'after',clock=end)
        assert bool(read(r,P.G['crossed']))==cross
        assert read(r,P.G['last_elapsed'])==(end-start)&0xffffffff
        crosses.append(dict(start=start,end=end,late=cross))

    exported=[]
    for tp,sp,selection,reject in itertools.product(P.BUS['tdm'][1],P.BUS['spi'][1],(0,1),(False,True)):
        pair=[]
        for memory in (old,m):
            r=runner(memory,tdm=tp,spi=sp)
            setup=dict(I12=0x2e0000,R8=0x2a0000,R4=0x2a1000,R15=0x2a2000,R0=12,R12=31,R14=128,
                       M3=(-8+4*selection)&0xffffffff,M2=20-4*selection,M4=selection,MODE1=0x01002000)
            for n,v in setup.items():reg(r,n,v)
            for i in range(140):put(r,0x2ff000-4*i,0)
            for channel in range(42):
                ptr=0x2a0000+channel*0x100
                for off,value in ((0,ptr),(4,ptr),(8,0x3f000000)):put(r,0x2ff000-128*4+12*channel+off,value)
                for i in range(64):put(r,ptr+4*i,struct.unpack('<I',struct.pack('<f',(channel+1)*.001+i*.00001))[0])
            for bus in P.BUS:
                _,pages,_,size,_,_=P.BUS[bus]
                for page in pages:
                    for off in range(0,2048 if bus=='tdm' else 4096,4):put(r,page+off,0xa5a5a5a5)
            if reject:put(r,P.BUS['spi'][0]+0x34,1)
            before=dict(r.state.overlay);r.state.pc_sw=0x1c265b;fix=MarkerFixups()
            if memory is m:
                for name,now in (('before',1000),('after',11000)):
                    fix.hooks[labels[name+'_clock.']+3]=lambda run,now=now:reg(run,'I0',now)
            result=fx.run(r,40000,fix,stop_at=[0x1c270c]);assert result[:2]==('stop',0x1c270c),(tp,sp,selection,reject,result)
            pair.append((r,result[2],before))
        parent,new=pair[0][0],pair[1][0];same_arch(parent,new)
        for bus in P.BUS:
            _,pages,mask,size,_,_=P.BUS[bus];original=tp if bus=='tdm' else sp;target=original^mask
            for page in pages:
                for off in range(0,2048 if bus=='tdm' else 4096,4):
                    audio=(off%64<56) if bus=='tdm' else (28<=off<2716)
                    expected=read(parent,original+off) if page==target and audio and not reject else 0xa5a5a5a5
                    assert read(new,page+off)==expected,(bus,hex(page+off),selection,reject)
        # Explicit write-side-effect scope: stack/native scratch identical;
        # only live audio, private guard RAM and sink may differ.
        allowed=set(range(P.STATE,P.END))|set(range(P.SINK,P.SINK_END))
        for bus in P.BUS:
            for page in P.BUS[bus][1]:
                for off in range(2048 if bus=='tdm' else 4096):
                    if (off%64<56) if bus=='tdm' else (28<=off<2716):allowed.add(0x28000000+page+off)
        changed={a for runner,_,prior in pair for a in set(prior)|set(runner.state.overlay) if prior.get(a)!=runner.state.overlay.get(a)}
        for address in changed-allowed:assert parent.state.overlay.get(address)==new.state.overlay.get(address),(hex(address),selection,reject)
        exported.append(dict(tdm=hex(tp),spi=hex(sp),selection=selection,rejected=reject,parent_instructions=pair[0][1],guard_instructions=pair[1][1],live_audio_exact=True,spi_prefix_trailer_untouched=True))

    publication=[];pub_allowed=set(range(P.STATE,P.END))
    for page in P.P.T.PAGES:
        for off in (4,12,16):pub_allowed.update(range(0x28000000+page+off,0x28000000+page+off+4))
    heartbeat=P.P.Q.P.D.P.P.HEARTBEAT
    for simd,sat,phase,rotation in itertools.product((False,True),(False,True),range(16),range(3)):
        runners=[]
        for memory in (old,m):
            r=runner(memory,simd,sat);put(r,heartbeat,phase<<10);put(r,P.G['publication_phase'],rotation)
            for a,v in ((0x200e654c,11),(0x200e6554,12),(P.G['accepted'],21),(P.G['rejected'],22),(P.G['crossed'],31),(P.G['max_elapsed'],32)):put(r,a,v)
            prior=dict(r.state.overlay);r.state.pc_sw=0xbf2350
            result=fx.run(r,5000,MarkerFixups(),stop_at=[0xbf53b6]);assert result[:2]==('stop',0xbf53b6),result
            runners.append((r,prior,result[2]))
        a,b=runners[0][0],runners[1][0];same_arch(a,b)
        changed={ad for run,prior,_ in runners for ad in set(prior)|set(run.state.overlay) if prior.get(ad)!=run.state.overlay.get(ad)}
        for address in changed-(pub_allowed if phase==15 else set()):assert a.state.overlay.get(address)==b.state.overlay.get(address),(phase,rotation,hex(address))
        for page in P.P.T.PAGES:
            for off in (0,8,20,24):assert read(a,page+off)==read(b,page+off)
        if phase==15:
            rot=lambda x:((x<<16)|(x>>16))&0xffffffff
            assert rot(read(b,0x2c49d4))==0x4f53dc1f+rotation,(simd,sat,phase,rotation,hex(read(b,0x2c49d4)),hex(heartbeat),read(b,P.G['publication_phase']))
            assert [rot(read(b,0x2c49d0+off)) for off in (12,16)]==[[11,12],[21,22],[31,32]][rotation]
            assert read(b,P.G['publication_phase'])==(rotation+1)%3
        publication.append(dict(simd=simd,saturation=sat,phase=phase,rotation=rotation,parent_instructions=runners[0][2],guard_instructions=runners[1][2]))
    gates=[]
    for simd,sat in itertools.product((False,True),(False,True)):
        a=runner(old,simd,sat);b=runner(m,simd,sat)
        for r in (a,b):
            put(r,P.P.WIRE+24,0x52430000);put(r,heartbeat,15<<10);r.state.pc_sw=0xbf53b0
            result=fx.run(r,300,MarkerFixups(),stop_at=[0xbf53b6]);assert result[:2]==('stop',0xbf53b6),result
        same_arch(a,b)
        for page in P.P.T.PAGES:
            for off in range(0,28,4):assert read(a,page+off)==read(b,page+off)==0x70123400+off//4
        assert read(b,P.G['publication_phase'])==0;gates.append(dict(simd=simd,saturation=sat))
    result=dict(ok=True,section7_sha256=C.SHA(raw),base_sha256=P.BASE_SHA,exact_parent_reversal=True,
                native_export_loops_unchanged=True,native_descriptor_alternation_bound=True,
                dma_units={'tdm':{'count':512,'word_bytes':4,'page_bytes':2048},'spi':{'count':1374,'word_bytes':2,'page_bytes':2748}},
                native_descriptor_execution=descriptors,
                instruction_boundaries=len(decoded),abi_cases=abi,admission_cases=admission,
                crossing_cases=crosses,native_export_cases=exported,publication_cases=publication,
                recorder_gate_cases=gates,memory_ownership=spec['ownership'],
                limits=['Fixture DMA/clock values; no hardware IRQ, prefetch or remaining-window guarantee.',
                        'Absolute audio generation equality is untagged; fixed one-slot relative shift assumes transport lockstep.',
                        'Instruction counts are not cycle bounds; reject repeats old live data.'])
    (folder/'usb-guarded-publication-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(ok=True,sha256=C.SHA(raw),abi=len(abi),admission=len(admission),crossing=len(crosses),export=len(exported),publication=len(publication),recorder=len(gates)),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('folder',type=Path);check(ap.parse_args().folder)
