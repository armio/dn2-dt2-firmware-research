#!/usr/bin/env python3
"""Maintain ColdFire data-cache coherency for relocated waveform DMA buffers."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
SHA='716ff49552832bf3a40f68a5aee59979cb8b8eee3e879ff651c2f74cb77a9fca'
RX,TX=0x47a8b200,0x47a8c200
SITES=(('prepare',0x47a8b0b0,bytes.fromhex('700f720e41ef0018')),
       ('complete',0x47a8af5c,bytes.fromhex('4feffff048d70303')))


def build(folder,out):
    raw=(folder/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((folder/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src=int(copy['source'],16);base=int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);tail=base+len(payload)
    assert len(payload)%4==0
    assert raw[0x40000554-B.BASE:0x40000568-B.BASE]==bytes.fromhex('203ca50ce1004e7b0002203c4007e0204e7b0004')
    for _,at,before in SITES:assert payload[at-base:at-base+len(before)]==before
    # Existing CACR: SPA=1, IVO=0, DDPI=0. CPUSHL DC uses a physical
    # address, writes any dirty line back, then invalidates the matching line.
    # Pre-DMA clearing ensures post-DMA RX lines cannot be dirty CPU copies.
    prologue='''
 lea -24(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 move.w %sr,%d0
 move.w %d0,20(%sp)
'''
    epilogue='''
 move.w 20(%sp),%d0
 move.w %d0,%sr
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 24(%sp),%sp
'''
    asm='''.text
.global waveform_cache_prepare
waveform_cache_prepare:
'''+prologue+'''
 move.l 40(%sp),%d0
 tst.l %d0
 bgt.s cache_positive_length
 moveq #0,%d0
cache_positive_length:
 cmpi.l #4096,%d0
 bls.s cache_bounded_length
 move.l #4096,%d0
cache_bounded_length:
 move.l %d0,waveform_cache_rx_bytes
 lea 0x47a8b200,%a0
 bsr.w waveform_cache_range
 move.l waveform_cache_rx_bytes,%d0
 add.l %d0,%d0
 lea 0x47a8c200,%a0
 bsr.w waveform_cache_range
'''+epilogue+'''
 moveq #15,%d0
 moveq #14,%d1
 lea 24(%sp),%a0
 jmp 0x47a8b0b8

.global waveform_cache_complete
waveform_cache_complete:
'''+prologue+'''
 move.l waveform_cache_rx_bytes,%d0
 lea 0x47a8b200,%a0
 bsr.w waveform_cache_range
'''+epilogue+'''
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 jmp 0x47a8af64

.global waveform_cache_range
waveform_cache_range:
 tst.l %d0
 ble.s cache_range_done
 addi.l #15,%d0
 andi.l #0xfffffff0,%d0
 move.l %a0,%a1
 adda.l %d0,%a1
cache_range_loop:
 cpushl %dc,(%a0)
 lea 16(%a0),%a0
 cmpa.l %a1,%a0
 bcs.s cache_range_loop
cache_range_done:
 nop
 rts

.balign 4
.global waveform_cache_rx_bytes
waveform_cache_rx_bytes:
 .long 0
'''
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(asm,tail,out,'waveform-coherency'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'waveform-coherency.elf']))}
    patches=[]
    for name,at,before in SITES:
        after=b'\x4e\xf9'+B.BE(symbols['waveform_cache_'+name])+b'\x4e\x71'*((len(before)-6)//2)
        payload[at-base:at-base+len(before)]=after
        patches.append(dict(name=name,address=hex(at),before=before.hex(),after=after.hex()))
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    bootstrap=(folder/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(folder/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['waveform_coherency_fix']=dict(baseline_sha256=SHA,patches=patches,
        methods={k:hex(v) for k,v in symbols.items() if k.startswith('waveform_cache_')},
        appended_start=hex(tail),appended_bytes=len(payload)-copy['bytes'],rx=hex(RX),rx_bytes=4096,tx=hex(TX),tx_bytes=8192,
        cache_line_bytes=16,native_cacr='0xA50CE100',native_acr0='0x4007E020',
        native_donor_buffers=['0x4FE79340','0x4FE7A340'],
        reason='Donor buffers were cache-inhibited; relocated buffers are in ACR0 copyback DDR. No original transport cache maintenance existed. Live second reply exactly matched preceding small waveform.',
        semantics='Push+invalidate exact aligned RX/TX spans after CPU TX staging and before DMA enable. Clear RX again at completion before callback/trace/caller reads. Last byte count bounded to4KB RX/8KB TX. CPU never writes RX between these operations.',
        cache_policy_unchanged=True,trace_addresses_unchanged=True,dsp_unchanged=True,identity_unchanged='T1DD',
        primary_source='https://www.nxp.com/docs/en/reference-manual/MCF54418RM.pdf',
        source_sections=['6.3.1 CACR','6.3.2 ACR','6.4.1 caching modes','6.4.4.2.2 NOP drains push/store buffers','6.4.8 enhanced CPUSHL, Table6-10'],
        limitations=['Focused software ordering/range validation does not emulate a physical cache or DMA.','Hardware waveform correction awaits the next flash.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((folder/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],waveform_coherency_fix=doc['waveform_coherency_fix']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.folder,a.out)
