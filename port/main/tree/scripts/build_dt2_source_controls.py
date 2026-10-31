#!/usr/bin/env python3
"""Port Source knob selection and reconcile donor/native parameter IDs."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-waveform-update-20261009'
SHA='410252bd5dc9ded664b5a7bdce00ee1c88fc34f5a2564346bb2329846c0caf03'

def build(out):
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_controls';L.LIMIT=0x47aa0000
    L.CODE=[('source_knob',0x40017c18,0x40017d50),('selected_sound_callback',0x40016d2e,0x40016d60),
            ('selected_sound_manager',0x4001742e,0x4001749a)]
    L.DATA=[('selected_sound_type',0x401ed808,0x401ed810)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    L.EXTRA_BINDINGS={0x4005063e:0x4004b7f2,0x400c8840:0x400c248e,
        0x4004abb8:0x40046bfe,0x40035cca:0x40030e66,0x40041d30:0x4003e426,
        0x4005ab0e:0x40055bba,0x4005b87a:0x40056926,
        0x4011e8f0:0x40120264,0x4011e8fc:0x40120270,0x40197a04:0x40188086}
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'selected_sound_slot':0x40017c18,'knob_parameter':0x40017cd4};L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy']
    src,base=int(c['source'],16),int(c['destination'],16)
    image=bytearray((out/'main-os.bin').read_bytes()[:src-B.BASE]);payload=bytearray((out/'runtime.bin').read_bytes())
    start=int(doc['source_controls']['methods']['selected_sound_slot'],16)
    at=start+0x40017ca4-0x40017c18
    assert payload[at-base:at-base+4]==B.BE(0x4f314)
    payload[at-base:at-base+4]=B.BE(0x4f358)
    methods=doc['source_parameters']['methods'];resolve=base+len(payload)
    asm=f'''.text
.global source_page_resolve_ids
/* Source's literal references use donor200..254. Its native overview
 * descriptors return native IDs (ONESHOT1..13, others321..367). They are
 * disjoint. Validate native IDs against the selected Machine's slot map. */
source_page_resolve_ids:
 lea -12(%sp),%sp
 movem.l %d2-%d3/%a2,(%sp)
 move.l 20(%sp),%d3
 move.l %d3,%d0
 subi.l #200,%d0
 cmpi.l #54,%d0
 bls.s donor_id
 cmpi.l #367,%d3
 bhi.s invalid
 lea {methods['source_parameter_reverse']},%a0
 mvz.b (%a0,%d3.l),%d0
 tst.l %d0
 beq.s invalid
 subi.l #200,%d0
 bra.s get_slot
donor_id:
 moveq #-1,%d3
get_slot:
 lea {methods['source_parameter_slots']},%a0
 mvz.b (%a0,%d0.l),%d2
 move.l 16(%sp),-(%sp)
 jsr 0x4005a42e
 addq.l #4,%sp
 move.l %d0,%d1
 subi.l #5,%d1
 cmpi.l #5,%d1
 bhi.s invalid
 clr.l -(%sp)
 move.l %d0,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x400dc02a
 lea 12(%sp),%sp
 tst.l %d3
 bmi.s done
 cmp.l %d3,%d0
 beq.s done
invalid:
 moveq #0,%d0
done:
 movem.l (%sp),%d2-%d3/%a2
 lea 12(%sp),%sp
 rts
.balign 4
'''
    payload.extend(B.R.assemble(asm,resolve,out,'source-control-ids'))
    old=int(doc['source_page_access']['methods']['source_page_parameter_id'],16)
    expected=bytes.fromhex('202f00080480');assert payload[old-base:old-base+6]==expected
    payload[old-base:old-base+6]=b'\x4e\xf9'+B.BE(resolve)
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image.extend(payload);boot=B.BASE+len(image)
    asm=(out/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_copy={**c,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bytes=len(image),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['source_controls'].update(resolve_ids=hex(resolve),redirect=hex(old),pool_offset_patch=hex(at),
        parameter_namespace='Native IDs from descriptors; donor literal IDs accepted at page-read entry',
        limits=['Original Source knob selector is callable but full Source vtable/events still pending.',
                'Source event SAMP comparisons must use native IDs when consuming knob_parameter.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),resolve=hex(resolve))))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
