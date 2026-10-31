#!/usr/bin/env python3
"""Record the first two waveform RPC handshakes without changing the protocol."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
SHA='e26a218cb4114bfa4b2a38595062eafdfc7970e53e7bac1aba0adea2a4b2f608'
SITES=(('request',0x47a8adc8,bytes.fromhex('4feffff448d7001c')),
       ('sent',0x47a8ae22,bytes.fromhex('4ef9400cf318')),
       ('ready',0x47a8ae28,bytes.fromhex('203947a8b180')),
       ('received',0x47a8ae5a,bytes.fromhex('487947a8b194')))


def build(folder,out):
    raw=(folder/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((folder/'build-receipt.json').read_text())
    copy=doc['runtime_copy'];src=int(copy['source'],16);base=int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);tail=base+len(payload)
    assert len(payload)%4==0 and tail==0x47aa5d3c
    for _,at,before in SITES:assert payload[at-base:at-base+len(before)]==before
    # MOVEM/LEA preserve CCR. Save SR before any flag-changing instruction,
    # then briefly mask interrupts so task and callback writers cannot interleave.
    # Each hook restores exact SR before restoring registers and displaced code.
    prologue='''
 lea -24(%sp),%sp
 movem.l %d0-%d2/%a0-%a1,(%sp)
 move.w %sr,%d0
 move.w %d0,20(%sp)
 ori.l #0x700,%d0
 move.w %d0,%sr
'''
    epilogue='''
 move.w 20(%sp),%d0
 move.w %d0,%sr
 movem.l (%sp),%d0-%d2/%a0-%a1
 lea 24(%sp),%sp
'''
    asm='.text\n'
    asm+='''.global waveform_trace_request
waveform_trace_request:
'''+prologue+'''
 lea waveform_trace_state,%a0
 clr.l 12(%a0)
 move.l 4(%a0),%d0
 cmpi.l #2,%d0
 bcc.w trace_request_done
 lsl.l #7,%d0
 lea waveform_trace_records,%a1
 adda.l %d0,%a1
 addq.l #1,4(%a0)
 move.l %a1,12(%a0)
 addq.l #1,8(%a0)
 move.l 8(%a0),(%a1)
 move.l 28(%sp),%d0
 move.l %d0,8(%a1)
 move.l 36(%sp),12(%a1)
 move.l 32(%sp),%a0
 moveq #-1,%d1
 move.w (%a0),%d1
 swap %d1
 cmpi.l #4,%d0
 bcs.s trace_request_header
 move.w 2(%a0),%d1
trace_request_header:
 move.l %d1,4(%a1)
trace_request_done:
'''+epilogue+'''
 lea -12(%sp),%sp
 movem.l %d2-%d4,(%sp)
 jmp 0x47a8add0

.global waveform_trace_sent
waveform_trace_sent:
'''+prologue+'''
 lea waveform_trace_state,%a0
 move.l 12(%a0),%a1
 tst.l %a1
 beq.s trace_sent_done
 addq.l #1,72(%a1)
 tst.l 16(%a1)
 bne.s trace_sent_done
 addq.l #1,8(%a0)
 move.l 8(%a0),16(%a1)
trace_sent_done:
'''+epilogue+'''
 jmp 0x400cf318

.global waveform_trace_ready
waveform_trace_ready:
'''+prologue+'''
 lea waveform_trace_state,%a0
 move.l 12(%a0),%a1
 tst.l %a1
 beq.s trace_ready_done
 addq.l #1,68(%a1)
 tst.l 20(%a1)
 bne.s trace_ready_done
 addq.l #1,8(%a0)
 move.l 8(%a0),20(%a1)
 move.l 0x47a8b180,%d0
 move.l %d0,24(%a1)
 move.l 16(%a1),80(%a1)
trace_ready_done:
'''+epilogue+'''
 move.l 0x47a8b180,%d0
 jmp 0x47a8ae2e

.global waveform_trace_received
waveform_trace_received:
'''+prologue+'''
 lea waveform_trace_state,%a0
 move.l 12(%a0),%a1
 tst.l %a1
 beq.s trace_received_done
 addq.l #1,76(%a1)
 tst.l 28(%a1)
 bne.s trace_received_done
 addq.l #1,8(%a0)
 move.l 8(%a0),28(%a1)
 move.l 0x47a8b180,%d0
 move.l %d0,32(%a1)
 lea 0x47a8b200,%a0
'''
    for offset in range(0,32,4):asm+=f' move.l {offset}(%a0),{36+offset}(%a1)\n'
    asm+='''trace_received_done:
'''+epilogue+'''
 pea 0x47a8b194
 jmp 0x47a8ae60

.balign 4
.global waveform_trace_state
waveform_trace_state:
 .long 0x57545231,0,0,0
.global waveform_trace_records
waveform_trace_records:
 .space 256,0
.balign 4
'''
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(asm,tail,out,'waveform-rpc-trace'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
            B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'waveform-rpc-trace.elf']))}
    patches=[]
    for name,at,before in SITES:
        after=b'\x4e\xf9'+B.BE(symbols['waveform_trace_'+name])+b'\x4e\x71'*((len(before)-6)//2)
        payload[at-base:at-base+len(before)]=after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    bootstrap=(folder/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(folder/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['waveform_rpc_trace']=dict(baseline_sha256=SHA,appended_start=hex(tail),appended_bytes=len(payload)-copy['bytes'],
        methods={k:hex(v) for k,v in symbols.items() if k.startswith('waveform_trace_')},patches=patches,
        read_address=hex(symbols['waveform_trace_state']),read_bytes=272,
        header=dict(magic=0,request_count=4,event_sequence=8,active_record=12),record_bytes=128,record_count=2,
        fields=dict(request_sequence=0,kind_slot=4,request_bytes=8,response_bytes=12,command_sent_sequence=16,
            gpio_ready_sequence=20,gpio_ready_pending_bytes=24,response_received_sequence=28,
            response_received_pending_bytes=32,rx_prefix=36,rx_prefix_bytes=32,gpio_ready_count=68,
            command_sent_count=72,response_received_count=76,command_sent_sequence_seen_by_ready=80),
        semantics='Diagnostic only: first two RPC requests and first callback occurrence snapshots; later callbacks counted, third request disables recording. Exact SR and touched registers restored, bounded interrupt-masked writes, original callback/wait/protocol paths replayed.',
        limits=['No first-response validity or waveform fix.','No DSP timing or hardware success claim.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((folder/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],waveform_rpc_trace=doc['waveform_rpc_trace']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.folder,a.out)
