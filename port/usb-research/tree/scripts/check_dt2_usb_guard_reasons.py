#!/usr/bin/env python3
"""Execute R008 diagnostic bytes against exact R007 policy/ABI/native output."""
from pathlib import Path
import argparse
import itertools
import json
import struct

import build_dt2_usb_guard_reasons as Q
import sharc_dn2_fixups as fx
import sharc_modify_units as units
from check_dt2_dsp_render_diagnostic import MarkerFixups, REGS

P=Q.P;C=Q.C


def checksum(words,kind):
    v=Q.MAGIC^kind
    for word in words:v=(((v<<5)|(v>>27))^word)&0xffffffff
    return v


def check(folder):
    raw=(folder/'section_7.bin').read_bytes();oldraw=Q.BASE.read_bytes()
    doc=json.loads((folder/'build-receipt.json').read_text());spec=doc['usb_guard_reasons'];parent=json.loads(Q.BASE.with_name('build-receipt.json').read_text())['usb_guarded_publication']
    assert C.SHA(raw)==doc['section7_sha256'] and C.SHA(oldraw)==Q.BASE_SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;fx.bind(str(C.SRC/'toolchains/digikit/tools'));units.install()
    memories=[Q.B.decode_view(k,x) for x in (oldraw,raw)];old,m=memories
    labels=[{n:int(v,16) for n,v in d['labels'].items()} for d in (parent,spec)]
    decoded=[]
    for memory,d in zip(memories,(parent,spec)):
        offsets=d['instruction_offsets']+[d['code_bytes']]
        decoded.append({Q.CODE+a//2:P.P.E.F.decode_fixed(k,memory,Q.CODE+a//2,b-a) for a,b in zip(offsets,offsets[1:])})
    for pc,ins in decoded[1].items():
        assert ins.kind!='unknown',(hex(pc),ins)
        if ins.type_name=='15a':
            reg=(ins.raw>>32)&0x7f;assert not (0x10<=reg<=0x4f and ((reg>>3)&1)==ins.fields['g'])
    def mmio_accesses(code):
        return [(ins.fields['d'],(ins.fields['addr[31:16]']<<16)|ins.fields['addr[15:0]']) for ins in code.values()
                if ins.type_name=='14a' and ins.fields['g']==0 and 0x31000000<=((ins.fields['addr[31:16]']<<16)|ins.fields['addr[15:0]'])<0x32000000]
    assert mmio_accesses(decoded[0])==mmio_accesses(decoded[1]) and len(mmio_accesses(decoded[1]))==16
    assert all(direction==0 for direction,_ in mmio_accesses(decoded[1]))
    # Exact reversal: only replacement guard code, three hooks and boot forward
    # length differ; no descriptors, sample code, sink or initial state changes.
    nb=C.B.walk(raw).blocks;ob=C.B.walk(oldraw).blocks;assert len(nb)==len(ob)
    ncode=next(b for b in nb if b.target==Q.PHYSICAL);ocode=next(b for b in ob if b.target==Q.PHYSICAL)
    restored=bytearray(raw[:ncode.offset]+oldraw[ocode.offset:ocode.end]+raw[ncode.end:])
    for h in spec['hooks']:C.B.write_span(restored,int(h['physical'],16),bytes.fromhex(h['before']))
    first=ob[7];restored[first.offset:first.end]=oldraw[first.offset:first.end];assert bytes(restored)==oldraw
    for lo,hi in ((0x1c266c,0x1c26ef),(0x1ca020,0x1ca05e),(0x1ca373,0x1ca392),(0x1ca46a,0x1ca59f),(0x1cc1d6,0x1cc26a)):
        assert m.read_sw(lo,2*(hi-lo))==old.read_sw(lo,2*(hi-lo))

    def put(r,a,v):assert k.st._dm_write(r.state,a,4,k.st.Const(v&0xffffffff))
    def rd(r,a):
        v=k.st._dm_read(r.state,a,4);assert isinstance(v,k.st.Const),(hex(a),v);return v.value
    def reg(r,n,v):r.state.uregs[k.st.UREG_CODES[n]]=k.st.Const(v&0xffffffff)
    def rv(r,n):return r.state.uregs[k.st.UREG_CODES[n]].value
    def dma(r,bus,original,kind='inactive',count=None):
        base,_,mask,size,_,maximum=P.BUS[bus];start=(original if kind=='inactive' else original^mask)+0x28000000
        n=maximum-32 if count is None else count;cur=start+(maximum-n)*(4 if bus=='tdm' else 2)
        if kind=='drained':n=0;cur=start+size
        for off,v in ((4,start),(0x2c,cur),(0x34,n)):put(r,base+off,v)
    def runner(which=1,simd=False,sat=False,tdm=0x2c08e8,spi=0x2c49d0):
        regs={n:(0x12345000+0x137*i)&0xffffffff for i,n in enumerate(REGS)}
        regs.update(MODE1=0x01000000|(0x200000 if simd else 0)|(0x2000 if sat else 0),ASTATX=0x4005a5,ASTATY=0x200a5a,
                    I6=0x2ff000,I7=0x2fef00,I3=tdm,I13=spi,L6=0,L7=0,M5=0,M6=1,M7=0xffffffff)
        r=k.run.Runner(memories[which],0x1c265b,regs=regs,explicit_memory_model=True);r._cache.update(decoded[which])
        for family in ('codec_delivery',):
            d=doc[family];oo=d['instruction_offsets']+[d['code_bytes']];base=int(d['code'],16)
            r._cache.update({base+a//2:P.P.E.F.decode_fixed(k,memories[which],base+a//2,b-a) for a,b in zip(oo,oo[1:])})
        for h in spec['hooks']:r._cache[int(h['site'],16)]=k.st.decode_at(memories[which],None,int(h['site'],16))
        for n in ('MRF','MRB','MSF','MSB'):r.state.special[n]=k.st.MR((1<<80)-1,0x123456789abcdef01234)
        for b,o in (('tdm',tdm),('spi',spi)):dma(r,b,o)
        put(r,P.P.WIRE+24,0);put(r,P.P.WIRE+28,0)
        for page in P.P.T.PAGES:
            for off in range(0,28,4):put(r,page+off,0x70123400+off//4)
        return r
    def same(a,b,ignored=()):
        skip={k.st.UREG_CODES[n] for n in ignored}
        assert {c:v for c,v in a.state.uregs.items() if c not in skip}=={c:v for c,v in b.state.uregs.items() if c not in skip},[(n,a.state.uregs.get(c),b.state.uregs.get(c)) for n,c in k.st.UREG_CODES.items() if c not in skip and a.state.uregs.get(c)!=b.state.uregs.get(c)]
        assert a.state.special==b.state.special
    def execute(r,which,name,clock=1000,changes=None):
        h=next(h for h in spec['hooks'] if h['name']==name);r.state.pc_sw=int(h['site'],16);r.state.stopped=None
        fix=MarkerFixups();names={'before':clock,'after':clock,'tdm_sample':clock+100,'spi_sample':clock+200,'event':clock+300}
        for n,value in names.items():
            lab=n+'_clock.'
            if lab in labels[which]:fix.hooks[labels[which][lab]+3]=lambda run,value=value:reg(run,'I0',value)
        if changes:fix.hooks.update(changes)
        result=fx.run(r,10000,fix,stop_at=[int(h['resume'],16)]);assert result[:2]==('stop',int(h['resume'],16)),(name,result,r.state.stopped)
        assert not r.state.pending and not r.state.call_stack and not r.state.loops
        return result[2]
    def state_parity(a,b):
        # Every original guard outcome/counter/pointer remains identical. The
        # original timestamp/save slots may record differing preserved I0 etc.
        for name in ('accepted','rejected','crossed','armed','original_i13','tdm_target','spi_target','last_elapsed','max_elapsed','cross_flags'):
            assert rd(a,P.G[name])==rd(b,P.G[name]),name

    abi=[]
    for simd,sat,tp,sp,tk,sk in itertools.product((False,True),(False,True),P.BUS['tdm'][1],P.BUS['spi'][1],('inactive','drained'),('inactive','drained')):
        pair=[runner(i,simd,sat,tp,sp) for i in (0,1)]
        for i,r in enumerate(pair):dma(r,'tdm',tp,tk);dma(r,'spi',sp,sk);execute(r,i,'before');execute(r,i,'after',11000)
        same(*pair);state_parity(*pair);assert rd(pair[1],P.G['accepted'])==1 and rd(pair[1],P.G['crossed'])==0
        abi.append(dict(simd=simd,saturation=sat,tdm=hex(tp),spi=hex(sp),tdm_state=tk,spi_state=sk))

    reason_cases=[]
    for reason,(phase,bus,predicate) in Q.REASONS.items():
        for simd,sat in itertools.product((False,True),(False,True)):
            pair=[runner(i,simd,sat) for i in (0,1)];busbase,pages,mask,size,minimum,maximum=P.BUS[bus];original=pages[0];target=original^mask
            for which,r in enumerate(pair):
                if phase=='after':execute(r,which,'before')
                extra={};start=original+0x28000000
                if reason<=2:reg(r,'I3' if bus=='tdm' else 'I13',0x12340000)
                elif predicate=='start_bracket':extra[labels[which][f'{phase}_{bus}_start_again.']]=lambda run,base=busbase:put(run,base+4,0x12340000)
                elif predicate=='unknown_start':put(r,busbase+4,0x12340000)
                elif predicate=='other_count_below_floor':put(r,busbase+0x34,(minimum if phase=='before' else 1)-1)
                elif predicate=='other_count_above_max':put(r,busbase+0x34,maximum+1)
                elif predicate=='other_current_below_start':put(r,busbase+0x2c,start-4)
                elif predicate=='other_current_at_or_past_end':put(r,busbase+0x2c,start+size)
                elif predicate=='same_start_count_reload':put(r,busbase+0x34,maximum)
                elif predicate in ('target_count_not_zero','target_current_not_end','newly_drained_start','newly_drained_count'):
                    dma(r,bus,original,'drained')
                    if predicate=='target_count_not_zero':put(r,busbase+0x34,1)
                    if predicate=='target_current_not_end':put(r,busbase+0x2c,target+0x28000000+size-4)
                    if predicate=='newly_drained_count':put(r,P.F[f'before_{bus}_start'],target+0x28000000);put(r,P.F[f'before_{bus}_count'],1)
                else:raise AssertionError(predicate)
                execute(r,which,phase,11000 if phase=='after' else 1000,extra)
            a,b=pair;same(a,b);state_parity(a,b)
            assert rd(b,Q.COUNTERS+4*(reason-1))==1,(reason,simd,sat)
            assert sum(rd(b,Q.COUNTERS+4*i) for i in range(40))==1
            address=Q.REJECT if phase=='before' else Q.POST;words=[rd(b,address+4*i) for i in range(28)]
            assert words[1:4]==[1,reason,1],(reason,words)
            expectedmask=1 if reason==1 else 3 if reason==2 else 15 if phase=='before' else 63
            assert words[26]==expectedmask
            if phase=='after':assert words[20]==(11100 if bus=='tdm' else 11200)
            if reason<=2:assert words[8:16]==[0]*8
            reason_cases.append(dict(reason=reason,simd=simd,saturation=sat,valid_mask=expectedmask))

    special=[]
    for start,end in ((1000,101000),(0xffffff00,0x200)):
        pair=[runner(i) for i in (0,1)]
        for i,r in enumerate(pair):execute(r,i,'before',start);execute(r,i,'after',end)
        same(*pair);state_parity(*pair)
        if end==101000:
            words=[rd(pair[1],Q.POST+4*i) for i in range(28)];assert words[1]==1 and words[2]==0 and words[25]==4 and words[26]==0x27
        special.append(dict(start=start,end=end))
    # Both failures count independently, but the event retains its first bus.
    pair=[runner(i) for i in (0,1)]
    for i,r in enumerate(pair):
        execute(r,i,'before')
        for bus in P.BUS:put(r,P.BUS[bus][0]+0x34,0)
        execute(r,i,'after',11000)
    same(*pair);state_parity(*pair);assert rd(pair[1],Q.POST+8)==21 and rd(pair[1],Q.COUNTERS+20*4)==rd(pair[1],Q.COUNTERS+31*4)==1

    exported=[]
    for tp,sp,selection,reject in itertools.product(P.BUS['tdm'][1],P.BUS['spi'][1],(0,1),(False,True)):
        pair=[]
        for which in (0,1):
            r=runner(which,tdm=tp,spi=sp)
            for n,v in dict(I12=0x2e0000,R8=0x2a0000,R4=0x2a1000,R15=0x2a2000,R0=12,R12=31,R14=128,
                           M3=(-8+4*selection)&0xffffffff,M2=20-4*selection,M4=selection,MODE1=0x01002000).items():reg(r,n,v)
            for i in range(140):put(r,0x2ff000-4*i,0)
            for channel in range(42):
                ptr=0x2a0000+channel*0x100
                for off,v in ((0,ptr),(4,ptr),(8,0x3f000000)):put(r,0x2ff000-128*4+12*channel+off,v)
                for i in range(64):put(r,ptr+4*i,struct.unpack('<I',struct.pack('<f',(channel+1)*.001+i*.00001))[0])
            for bus in P.BUS:
                for page in P.BUS[bus][1]:
                    for off in range(0,2048 if bus=='tdm' else 4096,4):put(r,page+off,0xa5a5a5a5)
            if reject:put(r,P.BUS['spi'][0]+0x34,1)
            prior=dict(r.state.overlay);r.state.pc_sw=0x1c265b;fix=MarkerFixups()
            for name,now in (('before',1000),('after',11000),('tdm_sample',11100),('spi_sample',11200),('event',11300)):
                lab=name+'_clock.'
                if lab in labels[which]:fix.hooks[labels[which][lab]+3]=lambda run,now=now:reg(run,'I0',now)
            result=fx.run(r,40000,fix,stop_at=[0x1c270c]);assert result[:2]==('stop',0x1c270c),(tp,sp,selection,reject,result)
            pair.append((r,prior,result[2]))
        a,b=pair[0][0],pair[1][0];same(a,b);state_parity(a,b)
        changed={address for r,prior,_ in pair for address in set(prior)|set(r.state.overlay) if prior.get(address)!=r.state.overlay.get(address)}
        for address in changed-set(range(Q.STATE,Q.END)):
            assert a.state.overlay.get(address)==b.state.overlay.get(address),(hex(address),tp,sp,selection,reject)
        for bus in P.BUS:
            for page in P.BUS[bus][1]:
                for off in range(0,2048 if bus=='tdm' else 4096,4):
                    assert rd(a,page+off)==rd(b,page+off)
                    if reject:assert rd(b,page+off)==0xa5a5a5a5
                    if bus=='spi' and not 28<=off<2716:assert rd(b,page+off)==0xa5a5a5a5
        exported.append(dict(tdm=hex(tp),spi=hex(sp),selection=selection,rejected=reject,parent_instructions=pair[0][2],observer_instructions=pair[1][2],all_live_pages_equal=True))

    heartbeat=P.P.Q.P.D.P.P.HEARTBEAT
    def publish(r,which,hb):
        put(r,heartbeat,hb);r.state.pc_sw=0xbf2350;r.state.stopped=None;prior=dict(r.state.overlay)
        result=fx.run(r,6000,MarkerFixups(),stop_at=[0xbf53b6]);assert result[:2]==('stop',0xbf53b6),(result,r.state.stopped)
        return prior,result[2]
    rot=lambda x:((x<<16)|(x>>16))&0xffffffff
    publication=[]
    for simd,sat in itertools.product((False,True),(False,True)):
        for phase in range(16):
            pair=[runner(i,simd,sat) for i in (0,1)]
            prior=[publish(r,i,phase<<10)[0] for i,r in enumerate(pair)];same(*pair)
            allowed=set(range(Q.STATE,Q.END))
            if phase==15:
                for page in P.P.T.PAGES:
                    for off in (4,12,16):allowed.update(range(0x28000000+page+off,0x28000000+page+off+4))
            changed={a for r,pre in zip(pair,prior) for a in set(pre)|set(r.state.overlay) if pre.get(a)!=r.state.overlay.get(a)}
            for a in changed-allowed:assert pair[0].state.overlay.get(a)==pair[1].state.overlay.get(a),(phase,hex(a))
            for page in P.P.T.PAGES:
                for off in (0,8,20,24):assert rd(pair[0],page+off)==rd(pair[1],page+off)
            publication.append(dict(simd=simd,saturation=sat,phase=phase))
    wire=[];r=runner();initial_regs=dict(r.state.uregs)
    for epoch in range(4):
        kind=epoch;seed=[0x12340000+i for i in range(28)]
        for i,value in enumerate(seed):put(r,(Q.REJECT if kind==0 else Q.POST)+4*i,value)
        for i in range(40):put(r,Q.COUNTERS+4*i,1000+i)
        observed={};held_snapshot=None
        for call in range(1024):
            hb=(epoch<<14)|(15<<10)|call;publish(r,1,hb)
            assert r.state.uregs==initial_regs
            words=[rd(r,Q.SNAP+4*i) for i in range(28)]
            if held_snapshot is None:held_snapshot=words
            assert words==held_snapshot and words[0]==epoch+1 and words[27]==checksum(words[:27],kind)
            marker,seq,value=(rot(rd(r,0x2c49d0+off)) for off in (4,12,16))
            slot=(call//16)%31;cycle=(call//496)&1
            if slot<3:assert marker==(0x4f53dc1f,0x4f53dc20,0x4f53dc21)[slot]
            else:
                field=slot-3;assert marker==0x4f53e800|(kind<<8)|(cycle<<5)|field,(call,hex(marker),field)
                assert seq==words[0] and value==words[field]
                observed[(cycle,field)]=value
            # Mutating rolling journals/counters cannot mutate the latched bank.
            put(r,Q.REJECT+4,call);put(r,Q.POST+4,call);put(r,Q.COUNTERS,call)
        assert len(observed)==56
        if kind>=2:assert held_snapshot[6]==1+(kind-2)*20 and held_snapshot[7:27]==list(range(1000+(kind-2)*20,1020+(kind-2)*20))
        wire.append(dict(kind=kind,sequence=epoch+1,both_cycles_complete=True,immutable=True))
    gates=[]
    for simd,sat in itertools.product((False,True),(False,True)):
        pair=[runner(i,simd,sat) for i in (0,1)]
        for r in pair:
            put(r,P.P.WIRE+24,0x52430000);put(r,heartbeat,15<<10);r.state.pc_sw=0xbf53b0
            result=fx.run(r,300,MarkerFixups(),stop_at=[0xbf53b6]);assert result[:2]==('stop',0xbf53b6)
        same(*pair)
        for page in P.P.T.PAGES:
            for off in range(0,28,4):assert rd(pair[0],page+off)==rd(pair[1],page+off)==0x70123400+off//4
        assert rd(pair[1],Q.D['snapshot_sequence'])==0;gates.append(dict(simd=simd,saturation=sat))
    result=dict(ok=True,section7_sha256=C.SHA(raw),base_sha256=Q.BASE_SHA,exact_parent_reversal=True,guard_policy_parity=True,mmio_read_set_and_order_unchanged=True,
                abi_cases=abi,reason_cases=reason_cases,special_cases=special,native_export_cases=exported,publication_cases=publication,wire_cycles=wire,recorder_gate_cases=gates,
                limits=['Synthetic MMIO and clocks; no physical DMA timing or audio guarantee.','Diagnostic overhead changes timing without changing guard policy.'])
    (folder/'usb-guard-reasons-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(ok=True,sha256=C.SHA(raw),abi=len(abi),reason=len(reason_cases),export=len(exported),publication=len(publication),wire_windows=len(wire),recorder=len(gates)),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('folder',type=Path);check(ap.parse_args().folder)
