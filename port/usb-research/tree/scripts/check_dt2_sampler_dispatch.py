#!/usr/bin/env python3
"""Short composed audio/lifecycle checks through the installed DN2 hooks."""
from pathlib import Path
import argparse, importlib.util, json, struct, sys
import build_dt2_sampler_dispatch as A
import check_dt2_sampler_dsp as T
C=A.C
import sharc_oneshot_run as OR
import check_oneshot_adapter_direct as D
import oneshot_memory_gate as G

FIXTURES=C.ROOT/'output/dn2-research/oneshot-native-bounds-dsp-v2-20261008/loader-status-fixtures'
PARAMS={5:(0,0x7800,0),6:(0x100,0x300,0x200),7:(0x1800,0x6000,0x200),
        8:(0x1800,0x6000,0x200),9:(0x200,0x100,0x200),10:(0x200,0x100,0)}


class SamplerMemoryGate(G.MemoryGate):
    PACKED_PCM=(0x1707f1,0x1707f6,0x1708d7,0x1708e4)
    def _check_range(self,state,canonical,width,*,write,overlay_ok=True,alignment=None):
        # ADI sc58x-2158x PRM table 6-13, p6-33: internal short-word accesses
        # have NO alignment restriction. DT2 packs REVERSE/LOOP at +1bb/+1bc
        # with one legal short store. Keep external, PCM bounds and all other
        # gate checks; this corrects the old gate's blanket width alignment.
        if width==2 and G._inside(G._physical(canonical),width,G.L1):alignment=1
        if width==4 and state.pc_sw in self.PACKED_PCM and G._inside(G._physical(canonical),width,G.L1):alignment=1
        return super()._check_range(state,canonical,width,write=write,
                                   overlay_ok=overlay_ok,alignment=alignment)

    def _pcm_read(self,state,physical,width):
        # STRETCH interpolates from packed pairs of signed16 samples using
        # normal-word reads. Check the entire four-byte read against the bank.
        if width==4 and state.pc_sw in self.PACKED_PCM:
            self.counts['pcm_reads']+=1
            for sample in self.samples:
                if sample['guard_start']<=physical and physical+width<=sample['guard_end']:
                    sample['reads']['total']+=1;sample['reads']['packed_pcm']+=1
                    return
            self._flag('pcm_outside_guards',state,physical,width)
        else:super()._pcm_read(state,physical,width)


G.MemoryGate=SamplerMemoryGate


def models(k,m,fix,gate):
    path=FIXTURES/'loader_status_copy_model.py'
    spec=importlib.util.spec_from_file_location('dispatch_loader_model',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for path in sorted(FIXTURES.glob('loader-status-16ed*.json')):
        doc=json.loads(path.read_text())
        assert doc['ok'] and doc['helper_sha256']==C.SHA((FIXTURES/'loader_status_copy_model.py').read_bytes())
        bindings={x['pc_sw']:x for x in doc['bindings']}
        for pc,item in bindings.items():assert k.st.decode_at(m,None,pc).raw==item['raw']
        module.StatusCopyModel(k,bindings,gate=gate).install(fix)
    T.NativeConversionModel(k.st,m,0x16f700).install(fix)
    # Two original STRETCH Type4b LW stack reads. The pinned generic G3
    # post-fixup uses an 8-byte displacement and first attempts an unsupported
    # scalar 8-byte read. Hardware uses normal-word (4-byte) displacement and
    # a register pair (ADI PRM p6-2/6-5). Execute exactly those instructions.
    for pc,donor,disp,reg in [(0x1706f3,0x1c5769,-6,0),(0x170755,0x1c57cb,-9,6)]:
        ins=k.st.decode_at(m,None,pc)
        donor_mem=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
        assert ins.raw==k.st.decode_at(donor_mem,None,donor).raw
        assert ins.type_name=='4b' and T.fx.F(ins.fields,'l')==1
        def pair(rr,pc=pc,ins=ins,disp=disp,reg=reg):
            assert rr._decode(pc).raw==ins.raw
            pred=T.fx.seq._predicate(rr.state,T.fx.cond_of(ins.fields));assert pred is not None
            if pred:
                base=rr.state.uregs[k.st.UREG_CODES['I6']].value+4*disp
                for j in range(2):
                    value=k.st._dm_read(rr.state,base+4*j,4);assert isinstance(value,k.st.Const)
                    rr.state.uregs[reg+j]=value
            rr.state=T.fx.seq._advance(rr.state,ins)[0]
            fix.note('STRETCH byte-bound LW pair/normal displacement',pc)
        fix.hooks[pc]=pair


def main(folder):
    raw=(folder/'section_7.bin').read_bytes();receipt=json.loads((folder/'build-receipt.json').read_text())
    assert C.SHA(raw)==receipt['section7_sha256']
    k=C.M.Digikit(C.SRC/'toolchains/digikit');T.fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    m=k.ldr.LoadedMemory.from_stream(raw);rows=[]
    entry_regs=dict(R0=0x12345678,R9=32,I6=0x2ffff0,I7=0x2ffff0)
    for machine in A.MACHINES:
        voice=1;record=0x30e000+472*voice
        r=OR.runner_for(k,m,0x185800,regs=entry_regs)
        for key in ('MRF','MRB','MSF','MSB'):r.state.special[key]=k.st.MR((1<<80)-1,0x123456789abcdef01234)
        OR.poke_bytes(k,r.state,0x2ffc00,bytes(0x400));OR.poke_bytes(k,r.state,0x30df00,bytes(128))
        for v in range(16):
            OR._poke(k,r.state,0x25566c+0x234*v,5 if v==voice else 0,4)
            OR._poke(k,r.state,0x254a60+4*v,0x30df00,4)
            OR._poke(k,r.state,0x25c520+2*v,machine if v==voice else 0,2)
        gate=G.install(k,raw,bank_entries=[dict(pointer=0x311814,length=7200,rate=48000)],
                       pcm_code_spans=((0x185000,0x185465),(0x170500,0x17094d)))
        blocks=[]
        # Trigger and held block exercise actual setup, render, level and return.
        for b in range(4 if machine==7 else 2):
            if b:r=r.fresh_call(0x185800,regs=entry_regs)
            current=9 if machine==7 and b>=2 else machine
            transition=machine==7 and b==2
            trigger=b==0 or (machine==7 and b==3)
            active_before=D.exact_bytes(k,r.state,record+0x1b8,4)[0]
            OR._poke(k,r.state,0x25c520+2*voice,current,2)
            for at in range(0x254b94,0x254c04,4):OR._poke(k,r.state,at,0,4)
            if trigger:OR._poke(k,r.state,0x254b94,1<<(8*voice),4)
            OR._poke(k,r.state,0x254b14+4*voice,T.F(60),4)
            OR._poke(k,r.state,0x25c564,14814,2)
            OR._poke(k,r.state,A.WARP+4*voice,100000000,4)
            words=PARAMS[current]
            params={25:0x4000,26:3<<8,28:0,31:words[0],32:words[1],33:words[2],34:0x6400,
                    35:0,36:450,37:0,38:1800,39:0,40:900}
            for slot,value in params.items():OR._poke(k,r.state,0x25c566+146*voice+2*(slot-25),value,2)
            seen=[]
            def render(rr):seen.append(rr.state.pc_sw)
            fix=T.fx.Fixups();fix.hooks={0x185000:render,0x170500:render};models(k,m,fix,gate)
            gate.begin(f'{machine}-{b}')
            status,stop,count=T.fx.run(r,100000,fix,stop_at=[0x1c944c,C.FAULT])
            gate.end()
            audio=D.exact_bytes(k,r.state,0x30df00,128)
            peak=max(map(abs,struct.unpack('<32f',audio)))
            result=dict(block=b,machine=A.MACHINES[current],trigger=trigger,status=status,stop=str(stop),
                        instructions=count,renderer=seen,peak=peak,active_before=active_before,
                        active_after=D.exact_bytes(k,r.state,record+0x1b8,4)[0])
            blocks.append(result);print(A.MACHINES[machine],result,flush=True)
            assert status=='stop' and stop==0x1c944c,result
            expected=[] if transition or (not trigger and not active_before) else [0x170500 if current==7 else 0x185000]
            assert seen==expected,result
            assert (peak>0 if expected else peak==0),result
            if transition:assert D.exact_bytes(k,r.state,record,472)==bytes(472)
            for reg,val in entry_regs.items():
                if reg!='R9':assert D.register(k,r.state,reg)==val,(reg,D.register(k,r.state,reg),val)
        gate.assert_clean(require_pcm_reads=True)
        rows.append(dict(machine=A.MACHINES[machine],blocks=blocks,memory=gate.report()))

    # Test the actual relocated conditional decision, including family changes.
    decisions=[]
    entry=int(receipt['labels']['native_handoff_gate.'],16)
    for old,new,want in [(0,0,False),(1,2,False),(5,0,True),(0,10,True),
                         (6,7,True),(10,5,True),(7,7,False),(11,5,False)]:
        r=OR.runner_for(k,m,entry,regs={'R2':new,'R3':old})
        status,stop,_=T.fx.run(r,100,T.fx.Fixups(),stop_at=[0x18619f,0x1861ad])
        assert status=='stop' and stop==(0x1861ad if want else 0x18619f)
        decisions.append(dict(old=old,new=new,copy=want))
    report=dict(ok=True,section7_sha256=C.SHA(raw),cases=rows,handoff_decisions=decisions,
                limits=['Controlled post-unpack inputs; no full engine scheduling or hardware claim',
                        'WERP position and SLICE markers are explicit fixtures',
                        'Existing byte-bound emulator corrections and loader status-copy overlay retained',
                        'Internal short-word alignment follows ADI PRM table 6-13, p6-33'])
    (folder/'dispatch-check.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);main(p.parse_args().folder)
