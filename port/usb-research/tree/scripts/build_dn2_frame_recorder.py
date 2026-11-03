#!/usr/bin/env python3
"""R009 bounded CF observations; exact R008 parent, no hardware access."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct

import build_dt2_directory_model as L

B = L.B
ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT/'output/dn2-research/usb-guard-r008-20261102/main/expanded'
MAIN_SHA = 'af0f0eb6d0bcfbadad8a2aed69cc90e1c7f8d2dad0cf9ed77bf5784f689c3033'
RUNTIME_SHA = 'ddf418cc1f341222312556ba1dc225a43ab8981ab4f49996a71ef8cb8028aeb2'
BASE, SOURCE, OLD_BYTES, LIMIT = 0x47a58000, 0x4033259c, 420464, 0x47ad0000
START, CONTROL, RING = BASE+OLD_BYTES, 0x47ac0b00, 0x47ac0c00
SCHEMA, MAGIC = 'dn2-frame-recorder-r009-1', 0x46523039
FIELDS = 'sequence epoch event begin_tick end_tick callback_tick flags source a b c d e f g sequence_end'.split()
CONTROL_FIELDS = 'magic version state epoch arm_tick freeze_tick stream_count reserved'.split()
STATE_FIELDS = 'total next_index busy overwrites last_begin_tick last_end_tick reserved0 reserved1'.split()
STREAMS = []
at = RING
for i, (name, capacity, data) in enumerate((
    ('spi',128,dict(source='cached_reply',a='spi_sr_before',b='spi_csr_before_after',c='spi_sr_after',d='cached_marker_after',e='cached_heartbeat_after',f='cached_word3_after',g='cached_word4_after')),
    ('collector',128,dict(source='tdm_source',a='dma_before',b='dma_after',c='cached_marker_before',d='cached_heartbeat_before',e='cached_marker_after',f='cached_heartbeat_after',g='packed_stage_sparse_xor')),
    ('queue',512,dict(source='payload',a='descriptor',b='token_before',c='requested_bytes',d='native_queue_return',e='qh_current_after',f='qh_token_after',g='payload_sparse_xor')),
)):
    STREAMS.append(dict(name=name,event=i+1,capacity=capacity,state_address=hex(CONTROL+32+32*i),
                        ring_address=hex(at),record_bytes=64,fields=FIELDS,
                        offsets={n:4*j for j,n in enumerate(FIELDS)},data_fields=data))
    at += capacity*64
END = at
SITES = [('control','native',0x402cf688,'4eb947a5201c'),
         ('spi','native',0x400cf7f2,'4eb940134490'),
         ('collector_begin','runtime',0x47aada56,'43f9800053c0'),
         ('collector_end','runtime',0x47aadc92,'48780020487947aa7800'),
         ('queue','runtime',0x47aadce2,'4ef940005a86')]
SHA = lambda b: hashlib.sha256(b).hexdigest()
BE = lambda v: struct.pack('>I',v)
SAVE = ' lea -36(%sp),%sp\n movem.l %d0-%d3/%a0-%a2,(%sp)\n move.w %sr,%d0\n move.w %d0,28(%sp)\n'
RESTORE = ' move.w 28(%sp),%d0\n move.w %d0,%ccr\n movem.l (%sp),%d0-%d3/%a0-%a2\n lea 36(%sp),%sp\n'


def state(i, field=0):
    return CONTROL+32+32*i+field


def work(i):
    return CONTROL+128+32*i


def begin(i, gate=''):
    """Busy is claimed before state inspection; no control-side reset while busy."""
    stream=STREAMS[i]
    return SAVE+f''' moveq #1,%d0
 move.l %d0,{state(i,8):#x}
 clr.l {work(i):#x}
 cmp.l {CONTROL+8:#x},%d0
 bne.w recorder_begin_done_{i}
'''+gate+f''' move.l {state(i):#x},%d0
 cmpi.l #0x7ffffffe,%d0
 bcc.w recorder_begin_done_{i}
 move.l {state(i,4):#x},%d0
 lsl.l #6,%d0
 lea {stream['ring_address']},%a2
 adda.l %d0,%a2
 clr.l (%a2)
 clr.l 60(%a2)
 move.l %a2,{work(i):#x}
 move.l {CONTROL+12:#x},%d0
 move.l %d0,4(%a2)
 moveq #{i+1},%d0
 move.l %d0,8(%a2)
 move.l 0xfc07000c,%d0
 move.l %d0,12(%a2)
 move.l 0x4058e8d4,%d0
 move.l %d0,20(%a2)
 clr.l 24(%a2)
'''


def begin_done(i):
    return f''' bra.w recorder_begin_restore_{i}
recorder_begin_done_{i}:
 clr.l {state(i,8):#x}
recorder_begin_restore_{i}:
'''+RESTORE


def end(i, data):
    capacity=STREAMS[i]['capacity']
    return SAVE+f''' movea.l {work(i):#x},%a2
 cmpa.l #0,%a2
 beq.w recorder_end_restore_{i}
 move.l 0xfc07000c,%d0
 move.l %d0,16(%a2)
'''+data+f''' /* An accepted in-flight record commits after FREEZE. ARM rejects busy. */
 move.l {state(i):#x},%d0
 addq.l #1,%d0
 move.l %d0,%d1
 add.l %d1,%d1
 move.l %d1,60(%a2)
 move.l %d1,(%a2)
 move.l %d0,{state(i):#x}
 cmpi.l #{capacity},%d0
 bls.w recorder_not_overwritten_{i}
 addq.l #1,{state(i,12):#x}
recorder_not_overwritten_{i}:
 andi.l #{capacity-1},%d0
 move.l %d0,{state(i,4):#x}
 move.l 12(%a2),%d0
 move.l %d0,{state(i,16):#x}
 move.l 16(%a2),%d0
 move.l %d0,{state(i,20):#x}
 clr.l {work(i):#x}
 clr.l {state(i,8):#x}
recorder_end_restore_{i}:
'''+RESTORE


def assembly():
    s='.text\n.global recorder_control,recorder_spi,recorder_collector_begin,recorder_collector_end,recorder_queue\n'
    s+='recorder_control:\n'+SAVE+''' cmpi.l #2,%d2
 beq.w recorder_arm
 cmpi.l #3,%d2
 beq.w recorder_freeze
'''+RESTORE+''' jmp 0x47a5201c
recorder_arm:
 cmpi.l #3,%d5
 bne.w recorder_refused
 move.w #0x2700,%sr
'''+f''' move.l {CONTROL+8:#x},%d0
 cmpi.l #1,%d0
 beq.w recorder_unlock_refused
'''+''.join(f' tst.l {state(i,8):#x}\n bne.w recorder_unlock_refused\n' for i in range(3))+f''' move.l {CONTROL+12:#x},%d0
 cmpi.l #0x7ffffffe,%d0
 bcc.w recorder_unlock_refused
 addq.l #1,%d0
 move.l %d0,{CONTROL+12:#x}
 clr.l {CONTROL+8:#x}
 clr.l {CONTROL+20:#x}
'''+''.join(f' clr.l {state(i,o):#x}\n' for i in range(3) for o in (0,4,12,16,20))+f''' move.l 0xfc07000c,%d0
 move.l %d0,{CONTROL+16:#x}
 moveq #1,%d0
 move.l %d0,{CONTROL+8:#x}
 move.w 28(%sp),%d0
 move.w %d0,%sr
 bra.w recorder_control_reply
recorder_unlock_refused:
 move.w 28(%sp),%d0
 move.w %d0,%sr
 bra.w recorder_refused
recorder_freeze:
 cmpi.l #3,%d5
 bne.w recorder_refused
 move.l {CONTROL+8:#x},%d0
 cmpi.l #2,%d0
 beq.w recorder_control_reply
 move.l 0xfc07000c,%d0
 move.l %d0,{CONTROL+20:#x}
 moveq #2,%d0
 move.l %d0,{CONTROL+8:#x}
 bra.w recorder_control_reply
recorder_refused:
 moveq #1,%d0
 move.b %d0,3(%a2)
recorder_control_reply:
'''+RESTORE+f''' lea {CONTROL:#x},%a0
 moveq #7,%d1
recorder_reply_words:
 move.l (%a0)+,(%a1)+
 subq.l #1,%d1
 bne.s recorder_reply_words
 moveq #0,%d0
'''+''.join(f' tst.l {state(i,8):#x}\n beq.s recorder_reply_idle_{i}\n bset #{i},%d0\nrecorder_reply_idle_{i}:\n' for i in range(3))+''' move.l %d0,(%a1)+
 rts
'''
    spi_gate=''' move.l 40(%sp),%d0
 cmpi.l #0x800053a4,%d0
 bne.w recorder_begin_done_0
 move.l 44(%sp),%d0
 cmpi.l #0x80001a20,%d0
 bne.w recorder_begin_done_0
 move.l 48(%sp),%d0
 cmpi.l #0xabc,%d0
 bne.w recorder_begin_done_0
'''
    s+='recorder_spi:\n'+begin(0,spi_gate)+''' move.l #0x800053a4,%d0
 move.l %d0,28(%a2)
 move.l 0xec03802c,%d0
 move.l %d0,32(%a2)
 moveq #0,%d0
 move.w 0xfc04539e,%d0
 swap %d0
 move.l %d0,36(%a2)
'''+begin_done(0)+''' /* Duplicate original native memcpy arguments, preserving its entry CCR. */
 lea -8(%sp),%sp
 movem.l %d0,(%sp)
 move.w %sr,%d0
 move.w %d0,4(%sp)
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 move.l 20(%sp),-(%sp)
 move.w 16(%sp),%d0
 move.w %d0,%ccr
 movem.l 12(%sp),%d0
 jsr 0x40134490
 lea 20(%sp),%sp
'''+end(0,''' move.l 0xec03802c,%d0
 move.l %d0,40(%a2)
 move.w 0xfc04539e,%d0
 move.w %d0,38(%a2)
 move.l 0x800053a8,%d0
 move.l %d0,44(%a2)
 move.l 0x800053ac,%d0
 move.l %d0,48(%a2)
 move.l 0x800053b0,%d0
 move.l %d0,52(%a2)
 move.l 0x800053b4,%d0
 move.l %d0,56(%a2)
''')+' rts\n'
    s+='recorder_collector_begin:\n'+begin(1)+''' move.l 16(%sp),28(%a2)
 move.l 0xfc045610,%d0
 move.l %d0,32(%a2)
 move.l 0x800053a8,%d0
 move.l %d0,40(%a2)
 move.l 0x800053ac,%d0
 move.l %d0,44(%a2)
'''+begin_done(1)+''' lea 0x800053c0,%a1
 jmp 0x47aada5c
recorder_collector_end:
'''+end(1,''' move.l 0xfc045610,%d0
 move.l %d0,36(%a2)
 move.l 0x800053a8,%d0
 move.l %d0,48(%a2)
 move.l 0x800053ac,%d0
 move.l %d0,52(%a2)
 move.l 0x47aa7800,%d0
 move.l 0x47aa7804,%d1
 eor.l %d1,%d0
 move.l 0x47aa7fe0,%d1
 eor.l %d1,%d0
 move.l 0x47aa87bc,%d1
 eor.l %d1,%d0
 move.l %d0,56(%a2)
''')+''' pea 32
 pea 0x47aa7800
 jmp 0x47aadc9c
'''
    queue_gate=''' move.l 40(%sp),%d0
 cmpi.l #7,%d0
 bne.w recorder_begin_done_2
 movea.l 44(%sp),%a0
 cmpa.l #0x80000000,%a0
 bcs.w recorder_begin_done_2
 cmpa.l #0x8000ffc0,%a0
 bhi.w recorder_begin_done_2
 movea.l 8(%a0),%a1
 cmpa.l #0x80009800,%a1
 bcs.w recorder_begin_done_2
 cmpa.l #0x8000d400,%a1
 bhi.w recorder_begin_done_2
 move.l 32(%a0),%d0
 cmpi.l #16,%d0
 bcs.w recorder_begin_done_2
 cmpi.l #882,%d0
 bhi.w recorder_begin_done_2
'''
    s+='recorder_queue:\n'+begin(2,queue_gate)+''' move.l %a1,28(%a2)
 move.l %a0,32(%a2)
 move.l 4(%a0),%d0
 move.l %d0,36(%a2)
 move.l 32(%a0),%d0
 move.l %d0,40(%a2)
 subq.l #4,%d0
 andi.l #0xfffffffc,%d0
 move.l (%a1,%d0.l),%d2
 move.l 32(%a0),%d0
 lsr.l #1,%d0
 andi.l #0xfffffffc,%d0
 move.l (%a1,%d0.l),%d1
 eor.l %d1,%d2
 move.l (%a1),%d1
 eor.l %d1,%d2
 move.l 4(%a1),%d1
 eor.l %d1,%d2
 move.l %d2,56(%a2)
'''+begin_done(2)+''' /* Original queue ABI, including native return registers and CCR. */
 lea -8(%sp),%sp
 movem.l %d0,(%sp)
 move.w %sr,%d0
 move.w %d0,4(%sp)
 move.l 16(%sp),-(%sp)
 move.l 16(%sp),-(%sp)
 move.w 12(%sp),%d0
 move.w %d0,%ccr
 movem.l 8(%sp),%d0
 jsr 0x40005a86
 lea 16(%sp),%sp
'''+end(2,''' move.l (%sp),44(%a2)
 move.l 0x800001c4,%d0
 move.l %d0,48(%a2)
 move.l 0x800001cc,%d0
 move.l %d0,52(%a2)
''')+' rts\n.balign 4\n'
    return s


def verify_scope(raw,doc,runtime):
    parent=(PARENT/'main-os.bin').read_bytes()
    prior=(PARENT/'runtime.bin').read_bytes()
    assert SHA(parent)==MAIN_SHA and SHA(prior)==RUNTIME_SHA
    cfg=doc['frame_recorder'];off=SOURCE-B.BASE;n=len(runtime)
    assert cfg['schema']==SCHEMA and cfg['parent_main_sha256']==MAIN_SHA
    assert SHA(raw)==doc['main_sha256'] and SHA(runtime)==doc['runtime_sha256']
    assert doc['runtime_copy']==dict(source=hex(SOURCE),destination=hex(BASE),bytes=n)
    assert int(doc['runtime_limit'],16)==LIMIT and BASE+n==END
    assert raw[off:off+n]==runtime and len(raw)==off+n+48
    restored=bytearray(raw[:off+OLD_BYTES]);seen=set()
    allowed={(domain,at):bytes.fromhex(hx) for _,domain,at,hx in SITES}
    allowed['runtime',0x47aa5a0c]=b'R008'
    for patch in cfg['patches']:
        key=(patch['domain'],int(patch['address'],16));assert key in allowed and key not in seen
        seen.add(key);before=bytes.fromhex(patch['before']);after=bytes.fromhex(patch['after'])
        assert before==allowed[key] and len(before)==len(after)
        p=key[1]-B.BASE if key[0]=='native' else off+key[1]-BASE
        assert parent[p:p+len(before)]==before and restored[p:p+len(after)]==after
        if key[1]==0x47aa5a0c:assert after==b'R009'
        else:assert START<=int.from_bytes(after[2:6],'big')<CONTROL
        restored[p:p+len(before)]=before
    assert seen==set(allowed)
    oldboot=parent[off+OLD_BYTES:];assert len(oldboot)==48
    assert raw[off+n:]==oldboot.replace(BE(OLD_BYTES//4),BE(n//4))
    assert raw[0xb2:0xb8]==b'\x4e\xf9'+BE(SOURCE+n)
    restored[0xb2:0xb8]=parent[0xb2:0xb8];restored.extend(oldboot)
    assert bytes(restored)==parent
    initial=runtime[CONTROL-BASE:END-BASE]
    assert initial[:32]==struct.pack('>8I',MAGIC,1,0,0,0,0,3,0)
    assert not any(initial[32:])
    return dict(exact_parent_reversal=True,parent_main_sha256=MAIN_SHA,
                parent_runtime_sha256=RUNTIME_SHA,appended_bytes=n-OLD_BYTES,
                allowed_sites=len(allowed),runtime_reservation_unchanged=True)


def build(parent,out):
    raw=(parent/'main-os.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
    prior=(parent/'runtime.bin').read_bytes();off=SOURCE-B.BASE
    assert SHA(raw)==doc['main_sha256']==MAIN_SHA and SHA(prior)==doc['runtime_sha256']==RUNTIME_SHA
    assert len(prior)==OLD_BYTES and raw[off:off+OLD_BYTES]==prior
    out.mkdir(parents=True,exist_ok=False)
    source=assembly();code=B.R.assemble(source,START,out,'frame-recorder')
    assert START+len(code)<=CONTROL
    sy={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (recorder_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'frame-recorder.elf']))}
    payload=bytearray(prior)+code+bytes(CONTROL-START-len(code))
    payload.extend(struct.pack('>8I',MAGIC,1,0,0,0,0,3,0));payload.extend(bytes(END-BASE-len(payload)))
    image=bytearray(raw[:off])+payload;patches=[]
    for name,domain,at,hx in SITES:
        before=bytes.fromhex(hx);p=at-B.BASE if domain=='native' else off+at-BASE
        assert image[p:p+len(before)]==before,(name,hex(at))
        op=b'\x4e\xb9' if name in ('control','spi') else b'\x4e\xf9'
        after=op+BE(sy['recorder_'+name])+b'\x4e\x71'*((len(before)-6)//2)
        image[p:p+len(before)]=after
        patches.append(dict(name=name,domain=domain,address=hex(at),before=before.hex(),after=after.hex()))
    p=off+0x47aa5a0c-BASE;assert image[p:p+4]==b'R008';image[p:p+4]=b'R009'
    patches.append(dict(name='identity',domain='runtime',address='0x47aa5a0c',before=b'R008'.hex(),after=b'R009'.hex()))
    payload=bytes(image[off:]);boot=SOURCE+len(payload)
    bootstrap=(parent/'bootstrap.S').read_text().replace(f'#{OLD_BYTES//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+BE(boot)
    cfg=dict(schema=SCHEMA,parent=str(parent.resolve()),parent_main_sha256=MAIN_SHA,parent_runtime_sha256=RUNTIME_SHA,
             code_start=hex(START),code_bytes=len(code),append_end=hex(END),original_runtime_bytes=OLD_BYTES,
             patches=patches,methods={k:hex(v) for k,v in sy.items()},control_address=hex(CONTROL),control_bytes=32,
             control_fields=CONTROL_FIELDS,stream_state_bytes=32,stream_state_fields=STATE_FIELDS,streams=STREAMS,
             commands=dict(arm=5,freeze=6,request_bytes=3,payload_bytes=0,reply_bytes=32,reply_fields=CONTROL_FIELDS[:-1]+['busy_mask']),
             timer=dict(address='0xfc07000c',hz=132000000,bits=32),
             commit='Each producer owns its ring/count/busy. Known accepted SPI callers, collector and packed writer run in the same non-reentrant native audio ISR (priority5); no shared cross-context counter. Busy set before active check; accepted writers finish even after freeze. Commit sequence_end then sequence last, then total/index, busy clear last. ARM refuses active or busy; metadata-only reset under brief IPL7. Freeze never waits or masks interrupts.',
             read_protocol='FREEZE once; wait all three busy fields zero; require identical frozen 128-byte control+state block before/after body. Keep latest min(total,capacity) ordinals; slot=ordinal%capacity; require sequence==sequence_end==2*(ordinal+1), matching epoch/event.',
             sequence_limit=0x7ffffffe,default_off=True,circular=True,
             signatures='Four aligned longword XOR observations only; not full payload hashes or generation identities.',
             limits=['Physical USB completion unobserved: native EP7 uses null callbacks/no IOC and skips completion walk. QH observations do not measure occupancy.',
                     'SPI raw-to-cache copy occurs before native EOQ check; record does not assert transfer completion.',
                     'DSP header words are sequential observations, not per-audio generation. DSP unchanged.',
                     'Short trailing SPI ring cannot cover a full28-field UGR8 journal; raw words3/4 retained but DSP cause generally unavailable.',
                     'Collector records active non-silence gather only; queue records packed-writer submissions, excluding startup prefill.',
                     'Trailing retention nominally ~85ms SPI/collector and ~64ms USB queue. Earlier events overwrite; counts expose overwrites.',
                     'Probe adds CPU work. Tick brackets include native operation and preemption; hardware timing not proven.',
                     'At 0x7ffffffe records a stream stops recording until rearmed; counters never wrap.'])
    doc.update(build='R009',main_sha256=SHA(image),runtime_sha256=SHA(payload),bytes=len(image),
               runtime_copy=dict(source=hex(SOURCE),destination=hex(BASE),bytes=len(payload)),
               bootstrap=hex(boot),bootstrap_bytes=48,flash_ready=False,frame_recorder=cfg)
    doc.pop('staged_main_sha256',None)
    proof=verify_scope(bytes(image),doc,payload)
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    (out/'frame-recorder-scope.json').write_text(json.dumps(proof,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((parent/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_sha256=doc['runtime_sha256'],code_bytes=len(code),append_end=hex(END)),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,default=PARENT);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.parent,a.out)
