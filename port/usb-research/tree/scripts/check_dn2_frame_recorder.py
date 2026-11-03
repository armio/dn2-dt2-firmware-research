#!/usr/bin/env python3
"""Native R009 observer ABI, bounded writes, wrap and freeze checks; no device I/O."""
from pathlib import Path
import argparse
import json
import struct

from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import m68k_const as M
import build_dn2_frame_recorder as B

D=[getattr(M,f'UC_M68K_REG_D{i}') for i in range(8)]
A=[getattr(M,f'UC_M68K_REG_A{i}') for i in range(8)]
REGS=D+A+[M.UC_M68K_REG_SR]
BE=lambda x:struct.pack('>I',x&0xffffffff)
SP,STOP=0x49010000,0x4901f000


class CPU:
    def __init__(self,folder):
        self.doc=json.loads((folder/'build-receipt.json').read_text());self.raw=(folder/'main-os.bin').read_bytes()
        self.cfg=self.doc.get('frame_recorder');self.sy={k:int(v,16) for k,v in self.cfg['methods'].items()} if self.cfg else {}
        self.u=u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);u.ctl_set_cpu_model(M.UC_CPU_M68K_CFV4E)
        for a,n in ((0x40000000,0x8000000),(0x49000000,0x20000),(0x4e6d0000,0x20000),
                    (0x80000000,0x10000),(0xfc040000,0x80000),(0xec038000,0x1000)):
            u.mem_map(a,n)
        u.mem_write(B.B.BASE,self.raw);c=self.doc['runtime_copy'];o=int(c['source'],16)-B.B.BASE
        u.mem_write(int(c['destination'],16),self.raw[o:o+c['bytes']])
        self.tick=10000;self.instructions=0;self.observer=0;self.stop=STOP;self.inject=None
        self.reads=[];self.writes=[]
        u.hook_add(UC_HOOK_CODE,self.code);u.hook_add(UC_HOOK_MEM_READ,self.read);u.hook_add(UC_HOOK_MEM_WRITE,self.write)

    def rd(self,at):return int.from_bytes(self.u.mem_read(at,4),'big')
    def put(self,at,v):self.u.mem_write(at,BE(v))
    def regs(self):return [self.u.reg_read(r) for r in REGS]
    def seed(self):
        for i,r in enumerate(D+A[:7]):self.u.reg_write(r,0x12000000+i*0x1110)
        self.u.reg_write(M.UC_M68K_REG_SR,0x2015);self.u.reg_write(A[7],SP)
        self.instructions=self.observer=0;self.reads=[];self.writes=[]

    def code(self,u,pc,size,_):
        if pc==self.stop:u.emu_stop();return
        self.instructions+=1
        if self.cfg and B.START<=pc<B.CONTROL:self.observer+=1
        if self.inject and pc==self.inject[0]:
            action=self.inject[1];self.inject=None;action(self)

    def read(self,u,kind,at,size,value,_):
        pc=u.reg_read(M.UC_M68K_REG_PC)
        if B.START<=pc<B.CONTROL:self.reads.append((at,size))
        if at==0xfc07000c:u.mem_write(at,BE(self.tick));self.tick=(self.tick+10)&0xffffffff
        elif at==0xfc045610:u.mem_write(at,BE(0x4e6df980))
        elif at==0xec03802c:u.mem_write(at,BE(0x10000000))
        elif at==0xfc04539e:u.mem_write(at,b'\x00\x80')

    def write(self,u,kind,at,size,value,_):
        pc=u.reg_read(M.UC_M68K_REG_PC)
        if not self.cfg or not B.START<=pc<B.CONTROL:return
        self.writes.append((at,size,value))
        own=B.CONTROL<=at and at+size<=B.END
        stack=SP-1024<=at and at+size<=SP+64
        reply=0x47a39020<=at and at+size<=0x47a39044
        assert own or stack or reply,(hex(pc),hex(at),size)

    def run(self,start,end=STOP):
        self.stop=end
        try:self.u.emu_start(start,end,count=200000)
        except Exception as e:raise AssertionError(f'{e}; PC={self.u.reg_read(M.UC_M68K_REG_PC):08x}') from e
        assert self.u.reg_read(M.UC_M68K_REG_PC)==end

    def control(self,command,length=3):
        self.seed();self.u.mem_write(SP,BE(STOP));self.u.mem_write(0x47a39020,bytes(36))
        for r,v in ((D[2],command-3),(D[5],length),(A[3],0x47a39000),(A[2],0x47a39020),(A[1],0x47a39024)):
            self.u.reg_write(r,v)
        self.run(self.sy['recorder_control'])
        assert self.u.reg_read(A[7])==SP+4
        assert self.u.reg_read(A[1])==0x47a39044
        return self.u.mem_read(0x47a39023,1)[0],list(struct.unpack('>8I',self.u.mem_read(0x47a39024,32)))

    def spi(self,enabled=True,dest=0x800053a4,size=0xabc):
        data=bytes((i*17+3)&255 for i in range(0xabc));self.u.mem_write(0x80001a20,data)
        self.seed();self.u.mem_write(SP,BE(dest)+BE(0x80001a20)+BE(size))
        self.run(0x400cf7f2,0x400cf7f8)
        return self.regs(),bytes(self.u.mem_read(dest,size)),self.observer

    def queue(self,token=0x02f40080,ep=7,disabled=False):
        self.seed();td=0x8000e000;payload=0x80009800
        self.u.mem_write(td,bytes(64));self.u.mem_write(payload,bytes((i*13+9)&255 for i in range(1024)))
        for at,v in ((td,0xdead0001),(td+4,token),(td+8,payload),(td+12,0x8000a000),(td+32,756),
                     (0x4664af0c,(1<<ep) if disabled else 0)):
            self.put(at,v)
        self.u.mem_write(0x800001c0,bytes(64))
        self.u.mem_write(SP,BE(STOP)+BE(ep)+BE(td))
        self.run(0x47aadce2)
        return self.regs(),bytes(self.u.mem_read(td,64)),bytes(self.u.mem_read(0x800001c0,64)),self.observer

    def collector_begin(self):
        self.seed();self.u.reg_write(A[0],0x4e6df100);self.u.reg_write(A[4],0x47aa7800)
        self.run(0x47aada56,0x47aada5c)
        return self.regs(),self.observer

    def collector_end(self):
        self.seed();self.u.mem_write(0x47aa7800,bytes((i*7+11)&255 for i in range(4032)))
        self.run(0x47aadc92,0x47aadc9c)
        return self.regs(),bytes(self.u.mem_read(SP-8,8)),self.observer


def check(folder):
    p=CPU(B.PARENT);q=CPU(folder);cfg=q.cfg
    runtime=(folder/'runtime.bin').read_bytes();scope=B.verify_scope(q.raw,q.doc,runtime)
    assert q.rd(B.CONTROL)==B.MAGIC and q.rd(B.CONTROL+8)==0
    cases=[];overhead={}
    # Existing command fallback remains byte-for-byte ABI at the original handler.
    for command in (0,4,7,255):
        q.seed();q.u.reg_write(D[2],(command-3)&0xffffffff);before=q.regs()
        q.run(q.sy['recorder_control'],0x47a5201c);assert q.regs()==before
    cases.append('unknown and inherited command4 preserve registers/CCR before native fallback')
    for command in (5,6):
        for length in (2,4,16):
            before=bytes(q.u.mem_read(B.CONTROL,128));status,_=q.control(command,length)
            assert status==1 and bytes(q.u.mem_read(B.CONTROL,128))==before
    cases.append('malformed arm/freeze refuse without private state mutation')
    for enabled in (False,True):
        if enabled:
            status,reply=q.control(5);assert status==0 and reply[2]==1 and reply[3]==1
            status,_=q.control(5);assert status==1
        a,b=p.spi(),q.spi();assert a[:2]==b[:2];overhead['spi_'+str(enabled)]=b[2]
        a,b=p.queue(),q.queue();assert a[:3]==b[:3];overhead['queue_'+str(enabled)]=b[3]
        a,b=p.collector_begin(),q.collector_begin();assert a[0]==b[0];overhead['collector_begin_'+str(enabled)]=b[1]
        a,b=p.collector_end(),q.collector_end();assert a[:2]==b[:2];overhead['collector_end_'+str(enabled)]=b[2]
        if not enabled:assert all(q.rd(B.state(i))==0 for i in range(3))
    cases.append('disabled/enabled original memcpy, queue, gather hook registers/CCR/stack/output parity')
    a,b=p.queue(disabled=True),q.queue(disabled=True);assert a[:3]==b[:3] and b[0][0]==0xffffffff
    queue_record=B.RING+256*64+64
    assert q.rd(queue_record+44)==0xffffffff
    cases.append('native queue refusal D0/CCR retained and logged')
    spi_record=B.RING
    cached=bytes(q.u.mem_read(0x800053a4,28))
    assert [q.rd(spi_record+x) for x in (44,48,52,56)]==list(struct.unpack('>7I',cached))[1:5]
    assert q.rd(spi_record+36)==0x00800080
    cases.append('SPI exact observed marker/heartbeat/word3/word4 and CSR brackets')
    # Every circular producer survives multiple wraps, with exact slot commit IDs.
    for i,stream in enumerate(B.STREAMS):
        q.control(6);assert q.control(5)[0]==0
        calls=stream['capacity']+3
        for _ in range(calls):
            if i==0:q.spi()
            elif i==1:q.collector_begin();q.collector_end()
            else:q.queue()
        assert q.rd(B.state(i))==calls and q.rd(B.state(i,4))==3 and q.rd(B.state(i,12))==3
        for ordinal in range(3,calls):
            at=int(stream['ring_address'],16)+(ordinal%stream['capacity'])*64
            assert q.rd(at)==q.rd(at+60)==2*(ordinal+1)
            assert q.rd(at+4)==q.rd(B.CONTROL+12) and q.rd(at+8)==i+1
        assert q.rd(B.state(i,8))==0
    cases.append('all rings wrap with bounded stores, matching sequence+epoch and exact overwrite counts')
    # Freeze during the accepted native operation: busy remains until commit.
    q.control(6);q.control(5)
    def freeze_inflight(cpu):
        assert cpu.rd(B.state(0,8))==1
        cpu.put(B.CONTROL+20,cpu.tick);cpu.put(B.CONTROL+8,2)
    q.inject=(0x40134490,freeze_inflight);q.spi()
    assert q.rd(B.state(0))==1 and q.rd(B.state(0,8))==0 and q.rd(B.CONTROL+8)==2
    frozen=bytes(q.u.mem_read(B.CONTROL,B.END-B.CONTROL));q.spi();q.queue();q.collector_begin();q.collector_end()
    assert bytes(q.u.mem_read(B.CONTROL,B.END-B.CONTROL))==frozen
    _,reply=q.control(6);assert reply[7]==0
    before=bytes(q.u.mem_read(B.CONTROL,128));q.control(6);assert bytes(q.u.mem_read(B.CONTROL,128))==before
    cases.append('freeze in-flight commits once; subsequent hooks leave frozen body/counts unchanged; freeze idempotent')
    # Freeze can observe a paired gather still pending; ARM must refuse until its end.
    q.control(5);q.collector_begin();status,reply=q.control(6)
    assert status==0 and reply[7]==2 and q.control(5)[0]==1
    q.collector_end();assert q.rd(B.state(1,8))==0 and q.control(5)[0]==0
    cases.append('freeze busy mask and ARM refusal protect split gather while pending')
    q.control(6);q.control(5);q.put(B.state(2),0x7ffffffe);q.put(B.state(2,4),510)
    q.queue();assert q.rd(B.state(2))==0x7ffffffe and q.rd(B.state(2,8))==0
    cases.append('sequence counter saturates rather than wrapping')
    # No observation is made for non-matching copies; original operation still runs.
    q.control(6);q.control(5);a,b=p.spi(dest=0x80005000,size=128),q.spi(dest=0x80005000,size=128)
    assert a[:2]==b[:2] and q.rd(B.state(0))==0
    cases.append('non-audio memcpy rejected by observer without changing native memcpy')
    result=dict(ok=True,main_sha256=q.doc['main_sha256'],runtime_sha256=q.doc['runtime_sha256'],scope=scope,
                cases=cases,observer_instructions=overhead,
                limits=['Native CF execution with fixture memory/MMIO/timer, not hardware timing.',
                        'Four-word sparse XOR signatures are observations, not full payload identity.',
                        'Known accepted producer callsites share non-reentrant priority5 audio ISR; no additional IRQ policy.',
                        'No physical USB completion, DSP journal reconstruction, audible-continuity or dropout-elimination claim.'])
    (folder/'frame-recorder-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);check(p.parse_args().folder)
