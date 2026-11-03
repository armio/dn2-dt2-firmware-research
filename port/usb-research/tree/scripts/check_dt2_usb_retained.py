#!/usr/bin/env python3
"""Execute R010 USB retention hooks and native exporter; no hardware access."""
from pathlib import Path
import argparse
import copy
import itertools
import json
import struct

import build_dt2_usb_retained as Q
import build_dt2_usb_guarded_publication as P
import sharc_dn2_fixups as fx
import sharc_modify_units as units
from check_dt2_dsp_render_diagnostic import MarkerFixups, REGS

C = P.C


class Fixture:
    def __init__(self, folder):
        self.folder = folder
        self.raw = (folder/'section_7.bin').read_bytes()
        self.doc = json.loads((folder/'build-receipt.json').read_text())
        self.spec = self.doc['usb_retained']
        self.parent_raw = Q.BASE.read_bytes()
        assert C.SHA(self.parent_raw) == Q.BASE_SHA
        assert C.SHA(self.raw) == self.doc['section7_sha256']
        self.k = C.M.Digikit(C.SRC/'toolchains/digikit')
        self.k.ldr.L2_BYTE_LIMIT = 0x20100000
        fx.bind(str(C.SRC/'toolchains/digikit/tools'))
        units.install()
        self.parent = Q.B.decode_view(self.k, self.parent_raw)
        self.memory = Q.B.decode_view(self.k, self.raw)
        self.labels = {n:int(v,16) for n,v in self.spec['labels'].items()}
        self.hooks = {h['name']:h for h in self.spec['hooks']}
        self.decoded = {}
        base = int(self.spec['code'],16)
        offsets = self.spec['instruction_offsets']+[self.spec['code_bytes']]
        for lo, hi in zip(offsets, offsets[1:]):
            ins = P.P.E.F.decode_fixed(self.k,self.memory,base+lo//2,hi-lo)
            assert ins.length_bytes == hi-lo and ins.kind == 'confident',(hex(base+lo//2),ins)
            if ins.type_name == '15a':
                reg = (ins.raw>>32)&0x7f
                assert not (0x10<=reg<=0x4f and ((reg>>3)&1)==ins.fields['g'])
            self.decoded[base+lo//2] = ins
        # Reference executes original exporter instructions and loops. Restore
        # only the two native instructions replaced by earlier USB guards.
        reference = bytearray(self.parent_raw)
        for name,pc,word,_ in P.HOOKS[:2]:
            C.B.write_span(reference,C.S.code_address(pc),C.S.to_bytes(word))
        self.reference = Q.B.decode_view(self.k,bytes(reference))

    def put(self, r, address, value):
        assert self.k.st._dm_write(r.state,address,4,self.k.st.Const(value&0xffffffff))

    def read(self, r, address):
        value = self.k.st._dm_read(r.state,address,4)
        assert isinstance(value,self.k.st.Const),(hex(address),value)
        return value.value

    def reg(self, r, name, value):
        r.state.uregs[self.k.st.UREG_CODES[name]] = self.k.st.Const(value&0xffffffff)

    def rval(self, r, name):
        return r.state.uregs[self.k.st.UREG_CODES[name]].value

    def dma(self, r, bus, page, *, count=None, current=None):
        base,_,_,size,_,maximum = P.BUS[bus]
        count = maximum-32 if count is None else count
        start = page+0x28000000
        current = start+(maximum-count)*(4 if bus=='tdm' else 2) if current is None else current
        for offset,value in ((4,start),(0x2c,current),(0x34,count)):
            self.put(r,base+offset,value)

    def runner(self, memory=None, simd=False, sat=False, tdm=0x2c08e8, spi=0x2c49d0):
        memory = memory or self.memory
        regs = {name:(0x12345000+0x137*i)&0xffffffff for i,name in enumerate(REGS)}
        regs.update(MODE1=0x01000000|(0x200000 if simd else 0)|(0x2000 if sat else 0),
                    ASTATX=0x4005a5,ASTATY=0x200a5a,I6=0x2ff000,I7=0x2fef00,
                    I3=tdm,I13=spi,L6=0,L7=0,M5=0,M6=1,M7=0xffffffff)
        r = self.k.run.Runner(memory,0x1c265b,regs=regs,explicit_memory_model=True)
        for family in ('codec_delivery','usb_guard_reasons'):
            spec = self.doc[family]
            if 'instruction_offsets' not in spec:
                continue
            offsets = spec['instruction_offsets']+[spec['code_bytes']]
            base = int(spec['code'],16)
            r._cache.update({base+a//2:P.P.E.F.decode_fixed(self.k,memory,base+a//2,b-a)
                             for a,b in zip(offsets,offsets[1:])})
        if memory is self.memory:
            r._cache.update(self.decoded)
            for hook in self.hooks.values():
                pc = int(hook['site'],16)
                r._cache[pc] = self.k.st.decode_at(memory,None,pc)
        for name in ('MRF','MRB','MSF','MSB'):
            r.state.special[name] = self.k.st.MR((1<<80)-1,0x123456789abcdef01234)
        for bus,page in (('tdm',tdm),('spi',spi)):
            self.dma(r,bus,page)
        self.put(r,P.P.WIRE+24,0)
        self.put(r,P.P.WIRE+28,0)
        for page in P.P.T.PAGES:
            for offset in range(0,28,4):
                self.put(r,page+offset,0x70123400+offset//4)
        return r

    def execute(self, r, name, *, changes=None, limit=40000):
        hook = self.hooks[name]
        r.state.pc_sw = int(hook['site'],16)
        r.state.stopped = None
        fix = MarkerFixups()
        for label,value in (('attempt_clock.',1000),('finish_clock.',11000)):
            fix.hooks[self.labels[label]+3] = lambda run,value=value:self.reg(run,'I0',value)
        if changes:
            fix.hooks.update(changes)
        stop = int(hook['resume'],16)
        result = fx.run(r,limit,fix,stop_at=[stop])
        assert result[:2] == ('stop',stop),(name,result,r.state.stopped)
        assert not r.state.pending and not r.state.call_stack and not r.state.loops
        return result[2]

    def same_arch(self, a, b, ignored=()):
        skip = {self.k.st.UREG_CODES[n] for n in ignored}
        ar = {c:v for c,v in a.state.uregs.items() if c not in skip}
        br = {c:v for c,v in b.state.uregs.items() if c not in skip}
        assert ar == br,[(n,a.state.uregs.get(c),b.state.uregs.get(c))
                         for n,c in self.k.st.UREG_CODES.items()
                         if c not in skip and a.state.uregs.get(c)!=b.state.uregs.get(c)]
        assert a.state.special == b.state.special

    def export_fixture(self, r, selection=0, generation=1):
        # The production exporter uses linear DAGs. ABI-only tests deliberately
        # seed lengths with arbitrary values; carrying those into native MODIFY
        # would create symbolic circular-wrap addresses instead of real audio.
        for index in range(16):
            self.reg(r,f'L{index}',0)
        setup=dict(I12=0x2e0000,R8=0x2a0000,R4=0x2a1000,R15=0x2a2000,R0=12,R12=31,R14=128,
                   M3=(-8+4*selection)&0xffffffff,M2=20-4*selection,M4=selection,MODE1=0x01002000)
        for name,value in setup.items():
            self.reg(r,name,value)
        for i in range(140):
            self.put(r,0x2ff000-4*i,0)
        for channel in range(42):
            pointer = 0x2a0000+channel*0x100
            for offset,value in ((0,pointer),(4,pointer),(8,0x3f000000)):
                self.put(r,0x2ff000-128*4+12*channel+offset,value)
            for i in range(64):
                value = (channel+1)*.001+i*.00001+generation*.0001
                self.put(r,pointer+4*i,struct.unpack('<I',struct.pack('<f',value))[0])


def check(folder):
    f = Fixture(folder)
    ob,nb = C.B.walk(f.parent_raw).blocks,C.B.walk(f.raw).blocks
    assert len(nb) == len(ob)+3
    assert [(b.target,b.count) for b in nb[-4:-1]] == [
        (Q.PHYSICAL,f.spec['code_bytes']),(Q.STATE,Q.STATE_END-Q.STATE),
        (Q.SLOT_BASE,Q.SLOT_END-Q.SLOT_BASE)]
    restored = bytearray(f.raw[:nb[-4].offset]+f.raw[nb[-1].offset:])
    for hook in f.hooks.values():
        C.B.write_span(restored,int(hook['physical'],16),bytes.fromhex(hook['before']))
    first = ob[7]
    restored[first.offset:first.end] = f.parent_raw[first.offset:first.end]
    assert bytes(restored) == f.parent_raw
    for lo,hi in ((0x1c266c,0x1c26ef),(0x1ca020,0x1ca05e),(0x1ca373,0x1ca392),
                  (0x1ca46a,0x1ca59f),(0x1cc1d6,0x1cc26a)):
        assert f.memory.read_sw(lo,2*(hi-lo)) == f.parent.read_sw(lo,2*(hi-lo))
    assert f.memory.read_sw(0x1c9f12,6) == f.parent.read_sw(0x1c9f12,6)

    def field(r,name):return f.read(r,Q.FIELDS[name])
    def setfield(r,name,value):f.put(r,Q.FIELDS[name],value)
    def native_hook(r,name):
        h=f.hooks[name];r.state.pc_sw=int(h['site'],16);r.state.stopped=None
        stop=int(h['resume'],16)
        result=fx.run(r,1000,MarkerFixups(),stop_at=[stop])
        assert result[:2]==('stop',stop),(name,result,r.state.stopped)
        return result[2]
    def live_words(r,bus,page):
        size=2048 if bus=='tdm' else 2748
        return [f.read(r,page+i) for i in range(0,size,4)]
    def fill_live(r,value=0xa5a5a5a5):
        for bus in P.BUS:
            for page in P.BUS[bus][1]:
                for off in range(0,2048 if bus=='tdm' else 4096,4):f.put(r,page+off,value)
    def private_block(r,slot,generation):
        for off in range(0,Q.SLOT_BYTES,4):f.put(r,slot+off,(generation<<20)+off)
    def enqueue_fixture(r,generation,tdm=0x2c08e8,spi=0x2c49d0):
        f.reg(r,'I3',tdm);f.reg(r,'I13',spi)
        f.execute(r,'before')
        slot=field(r,'write_stage');assert slot in Q.SLOTS
        private_block(r,slot,generation)
        f.execute(r,'after')
        return slot
    def retry(r,changes=None):
        setfield(r,'producer_valid',0);setfield(r,'cycle_published',0)
        return f.execute(r,'after',changes=changes)
    def block_target(r,bus='tdm',original=0x2c08e8):
        f.dma(r,bus,original^P.BUS[bus][2],count=1)
    def assert_audio(r,slot,tdm,spi):
        for bus,page,source in (('tdm',tdm,slot),('spi',spi,slot+Q.SPI_OFFSET)):
            size=2048 if bus=='tdm' else 2748
            for off in range(0,size,4):
                audio=(off%64<56) if bus=='tdm' else (28<=off<2716)
                assert f.read(r,page+off)==(f.read(r,source+off) if audio else 0xa5a5a5a5), (bus,hex(page+off))

    abi=[]
    for simd,sat,tp,sp in itertools.product((False,True),(False,True),P.BUS['tdm'][1],P.BUS['spi'][1]):
        a=f.runner(f.reference,simd,sat,tp,sp);b=f.runner(simd=simd,sat=sat,tdm=tp,spi=sp)
        native_hook(a,'before');steps=f.execute(b,'before')
        f.same_arch(a,b,('I3','I13'))
        assert f.rval(b,'I3')==Q.SLOTS[0] and f.rval(b,'I13')==Q.SLOTS[0]+Q.SPI_OFFSET
        # Empty early hook must replay both displaced native instructions.
        a=f.runner(f.parent,simd,sat,tp,sp);b=f.runner(simd=simd,sat=sat,tdm=tp,spi=sp)
        for r in (a,b):
            for off in range(-512,516,4):f.put(r,0x2ff000+off,0)
        native_hook(a,'early');steps+=f.execute(b,'early');f.same_arch(a,b)
        assert field(b,'cycle_published')==0
        abi.append(dict(simd=simd,saturation=sat,tdm=hex(tp),spi=hex(sp),instructions=steps))

    exported=[]
    for tp,sp,selection in itertools.product(P.BUS['tdm'][1],P.BUS['spi'][1],(0,1)):
        a=f.runner(f.reference,tdm=tp,spi=sp);b=f.runner(tdm=tp,spi=sp)
        for r in (a,b):f.export_fixture(r,selection);fill_live(r)
        block_target(b,original=tp)
        pair=[]
        for r in (a,b):
            r.state.pc_sw=0x1c265b;r.state.stopped=None
            fix=MarkerFixups()
            for lab,value in (('attempt_clock.',1000),('finish_clock.',11000)):
                fix.hooks[f.labels[lab]+3]=lambda run,value=value:f.reg(run,'I0',value)
            result=fx.run(r,60000,fix,stop_at=[0x1c270c])
            assert result[:2]==('stop',0x1c270c),(result,r.state.stopped)
            assert not r.state.pending and not r.state.call_stack and not r.state.loops
            pair.append(result[2])
        f.same_arch(a,b)
        slot=Q.SLOTS[0]
        for bus,original,source in (('tdm',tp,slot),('spi',sp,slot+Q.SPI_OFFSET)):
            size=2048 if bus=='tdm' else 2748
            for off in range(0,size,4):
                audio=(off%64<56) if bus=='tdm' else (28<=off<2716)
                if audio:
                    expected=f.read(a,original+off)
                    assert expected!=0xa5a5a5a5,(bus,'reference exporter left canary',hex(original+off))
                    assert f.read(b,source+off)==expected,(bus,hex(source+off))
                else:assert f.read(b,source+off)==0
            for page in P.BUS[bus][1]:assert all(v==0xa5a5a5a5 for v in live_words(b,bus,page))
        assert field(b,'write_cursor')==1 and field(b,'read_cursor')==0
        assert field(b,'last_reason')==9 and field(b,'rejected')==1
        f.dma(b,'tdm',tp)
        retry(b)
        assert field(b,'committed')==1 and field(b,'read_cursor')==1
        assert_audio(b,slot,tp^0x1800,sp^0x1000)
        exported.append(dict(tdm=hex(tp),spi=hex(sp),selection=selection,
                             native_instructions=pair[0],retained_instructions=pair[1],
                             count1_retained=True,retry_exact=True))

    queue=[]
    r=f.runner();fill_live(r);block_target(r)
    slots=[]
    for generation in range(1,7):
        slots.append(enqueue_fixture(r,generation))
        assert field(r,'write_cursor')==min(generation,3) and field(r,'read_cursor')==0
    assert field(r,'overflow')==3 and field(r,'enqueued')==3
    assert slots[:3]==list(Q.SLOTS[:3]) and slots[3:]==[Q.SLOTS[3]]*3
    assert [f.read(r,slot) for slot in Q.SLOTS[:3]]==[g<<20 for g in (1,2,3)]
    for sequence in (1,2,3):
        f.dma(r,'tdm',0x2c08e8);f.dma(r,'spi',0x2c49d0)
        retry(r)
        if sequence==1:
            assert field(r,'committed')==1
            # Same page is not reused until DMA was observed consuming it.
            retry(r)
            assert field(r,'committed')==1 and field(r,'freshness_deferred')==1
        else:
            assert field(r,'committed')==sequence
        assert field(r,'last_sequence')==sequence
        assert_audio(r,Q.SLOTS[sequence-1],0x2c10e8,0x2c59d0)
        queue.append(dict(committed=sequence,last_sequence=field(r,'last_sequence')))
        if sequence<3:
            f.dma(r,'tdm',0x2c10e8,count=1);f.dma(r,'spi',0x2c59d0,count=1)
            retry(r)
            assert field(r,'committed')==sequence
            assert field(r,'seen_tdm')==field(r,'seen_spi')==1
    assert field(r,'read_cursor')==field(r,'write_cursor')==3

    # A drained snapshot predating publication is not fresh consumption of the
    # new block, even though it satisfies the unchanged ownership predicate.
    r=f.runner();fill_live(r);block_target(r)
    enqueue_fixture(r,1);enqueue_fixture(r,2)
    for bus in P.BUS:f.dma(r,bus,P.BUS[bus][1][1],count=0)
    retry(r);assert field(r,'committed')==1 and field(r,'read_cursor')==1
    retry(r);assert field(r,'committed')==1 and field(r,'freshness_deferred')==1
    assert field(r,'seen_tdm')==field(r,'seen_spi')==0
    for bus in P.BUS:f.dma(r,bus,P.BUS[bus][1][1],count=1)
    retry(r);assert field(r,'committed')==1
    assert field(r,'seen_tdm')==field(r,'seen_spi')==1
    for bus in P.BUS:f.dma(r,bus,P.BUS[bus][1][0])
    retry(r);assert field(r,'committed')==2 and field(r,'read_cursor')==2
    assert_audio(r,Q.SLOTS[1],0x2c10e8,0x2c59d0)
    drained_freshness=dict(unchanged_drained_does_not_consume=True,active_then_inactive_allows_copy=True)

    crossing=[]
    for bus in P.BUS:
        r=f.runner();fill_live(r);block_target(r);enqueue_fixture(r,1)
        f.dma(r,'tdm',0x2c08e8)
        base,pages,mask,size,_,maximum=P.BUS[bus]
        def cross(run,bus=bus,pages=pages):f.dma(run,bus,pages[1],count=maximum-8)
        retry(r,{f.labels['after_'+bus+'_start.']:cross})
        assert field(r,'crossed')==1 and field(r,'committed')==0 and field(r,'read_cursor')==0
        assert field(r,'write_cursor')==1 and field(r,'cycle_published')==1
        # No second write within the same render, even after post-check failure.
        prior=dict(r.state.overlay);f.execute(r,'after')
        assert field(r,'read_cursor')==0
        for address,value in prior.items():
            if any(0x28000000+page<=address<0x28000000+page+size for page in pages):
                assert r.state.overlay.get(address)==value
        for observed_bus in P.BUS:
            f.dma(r,observed_bus,P.BUS[observed_bus][1][1],count=1)
        retry(r)
        assert field(r,'committed')==0
        for observed_bus in P.BUS:f.dma(r,observed_bus,P.BUS[observed_bus][1][0])
        retry(r)
        assert field(r,'committed')==1 and field(r,'read_cursor')==field(r,'write_cursor')==1
        assert_audio(r,Q.SLOTS[0],0x2c10e8,0x2c59d0)
        crossing.append(dict(bus=bus,post_failure_retained=True,second_copy_suppressed=True,
                             retry_after_consumption_exact=True))

    # Corrupt depth and noncanonical native destinations cannot publish.
    invalid=[]
    for name,value in (('depth',4),('tdm',0x12340000),('spi',0x12340000)):
        r=f.runner();fill_live(r)
        if name=='depth':setfield(r,'write_cursor',value)
        else:f.reg(r,'I3' if name=='tdm' else 'I13',value)
        f.execute(r,'before');assert field(r,'producer_valid')==0
        f.execute(r,'after');assert field(r,'committed')==0
        for bus in P.BUS:
            for page in P.BUS[bus][1]:assert all(v==0xa5a5a5a5 for v in live_words(r,bus,page))
        invalid.append(name)
    publication=[]
    pairs=(('produced','committed'),('last_depth','max_depth'),('rejected','overflow'),
           ('crossed','last_elapsed'),('last_sequence','freshness_deferred'),('last_reason','bad_depth'))
    for simd,sat,phase in itertools.product((False,True),(False,True),range(len(pairs))):
        r=f.runner(simd=simd,sat=sat)
        setfield(r,'publication_phase',phase)
        for name,value in zip(pairs[phase],(0x12345678,0xabcdef01)):setfield(r,name,value)
        original=copy.deepcopy(r.state.uregs);special=copy.deepcopy(r.state.special)
        f.execute(r,'publication')
        changed={c for c,v in original.items() if r.state.uregs[c]!=v}
        assert changed <= {f.k.st.UREG_CODES['I0']}
        assert r.state.special==special
        assert f.rval(r,'I0')==((0xdc22+phase)<<16)|0x4f53
        rotate=lambda v:((v<<16)|(v>>16))&0xffffffff
        for page in P.P.T.PAGES:
            assert [rotate(f.read(r,page+off)) for off in (12,16)]==[0x12345678,0xabcdef01]
            for off in (0,4,8,20,24):assert f.read(r,page+off)==0x70123400+off//4
        assert field(r,'publication_phase')==(phase+1)%6
        publication.append(dict(simd=simd,saturation=sat,phase=phase))
    result=dict(ok=True,section7_sha256=C.SHA(f.raw),base_sha256=Q.BASE_SHA,
        exact_parent_reversal=True,native_audio_loops_and_control_paths_unchanged=True,
        instruction_boundaries=len(f.decoded),abi_cases=abi,native_export_cases=exported,
        ordered_queue_cases=queue,full_queue_drops_new_without_overwriting_old=True,
        drained_freshness=drained_freshness,post_crossing_cases=crossing,invalid_input_cases=invalid,
        publication_cases=publication,
        limits=['Fixture DMA/register timing; no hardware bus, IRQ or cycle-deadline proof.',
                'Post-check failure retains the queued pair but cannot undo already written live audio.',
                'Finite retention capacity counts overflow; it cannot absorb unbounded DMA unavailability.'])
    (folder/'usb-retained-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(ok=True,section7_sha256=C.SHA(f.raw),abi=len(abi),native_exports=len(exported),
                         queue=len(queue),post_crossings=len(crossing)),indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    check(parser.parse_args().folder)
