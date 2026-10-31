#!/usr/bin/env python3
"""Connect DT2 Source's original browser creation/commit callbacks to DN2."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-draw-20261009'
SHA='4f11868c2ab912d4baabaf4a95ff9051f5c9816ac1f28479231004cd472e9970'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text());p=doc['source_parameters']['methods']
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='source_browser';L.LIMIT=0x47aa0000
    L.CODE=[('source_open_browser',0x40017ed0,0x400181fe),
            ('source_selection_callbacks',0x40016ccc,0x40016de2),
            ('source_callback_managers',0x4001725e,0x4001742e),
            ('source_locked_bank',0x4001749a,0x4001753a),
            ('source_browser_bank',0x400187c4,0x40018900)]
    L.DATA=[('source_callback_types',0x401ed810,0x401ed830)]
    L.EXTRA_DATA={};L.EXTRA_STATE=[];L.EXTRA_CODE=[];L.EXTRA_TYPED_DATA=[];L.EXTRA_SPANS=[]
    binds={}
    for key in ('pcm_pages','sample_allocator','sample_loader','project_sample_load','sample_preview','waveform_rpc','waveform_cache','waveform_events','waveform_drawers','slice_storage','source_waveform_update','source_controls','source_draw'):
        L.EXTRA_SPANS[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:binds[int(e['target'],16)]=int(e['binding'],16)
    binds.update({0x4004297c:int(doc['browser_parameters']['symbols']['browser_resolve'],16),
                  0x4003b570:int(p['source_parameter_set'],16)})
    # This component uses Machine IDs only as donor table indices. Its
    # descriptor-based knob selector lives in a separate, already linked span.
    asm=f'''.text
.global source_browser_machine,source_browser_lock_read
source_browser_machine:
 move.l 4(%sp),-(%sp)
 jsr 0x4004b7f2
 move.l %d0,(%sp)
 jsr {p['source_donor_machine']}
 addq.l #4,%sp
 rts
source_browser_lock_read:
 move.l 12(%sp),%d0
 movea.l 4(%sp),%a0
 move.l %d0,-(%sp)
 move.l %a0,-(%sp)
 jsr {doc['source_page_access']['methods']['source_page_parameter_id']}
 addq.l #8,%sp
 tst.l %d0
 beq.s invalid
 move.l %d0,12(%sp)
 movea.l 4(%sp),%a0
 movea.l (%a0),%a0
 movea.l 0x90(%a0),%a0
 jmp (%a0)
invalid:
 moveq #-1,%d0
 rts
.balign 4
'''
    binds[0x4005063e]=0x4004b7f2
    L.EXTRA_BINDINGS=binds;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'open':0x40017ed0,'commit':0x40016d60,'selected_slot':0x40016ccc,
               'bank':0x400187c4,'locked_bank':0x4001749a}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());c=doc['runtime_copy'];base=int(c['destination'],16);src=int(c['source'],16)
    raw=bytearray((out/'main-os.bin').read_bytes()[:src-B.BASE]);payload=bytearray((out/'runtime.bin').read_bytes())
    start=base+len(payload);payload.extend(B.R.assemble(asm,start,out,'source-browser-adapters'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'source-browser-adapters.elf'])
    syms={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (source_browser_\w+)$',nm)}
    doc['source_browser']['methods'].update({k:hex(v) for k,v in syms.items()})
    for edit in doc['source_browser']['edits']:
        if edit['target']=='0x4005063e':
            at=int(edit['runtime'],16)-base
            assert payload[at:at+4]==B.BE(0x4004b7f2)
            payload[at:at+4]=B.BE(syms['source_browser_machine'])
            edit['binding']=hex(syms['source_browser_machine'])
    def relocate(old):
        for s in doc['source_browser']['spans']:
            lo,hi=int(s['donor'],16),int(s['end'],16)
            if lo<=old<hi:return int(s['runtime'],16)+old-lo
        raise ValueError(hex(old))
    # Preserve original calls/stack cleanup; replace only vtable loads with
    # same-size PC-relative LEAs of native-ID adapters.
    changes=[]
    for old,expected,target,reg in [
        (0x40017f70,'20680028',int(p['source_parameter_get'],16),0),
        (0x40018812,'20690028',int(p['source_parameter_get'],16),0),
        (0x400174ba,'20690040',int(p['source_parameter_lock_get'],16),0),
        (0x400174d4,'20690028',int(p['source_parameter_get'],16),0),
        (0x40017524,'20690044',int(p['source_parameter_lock_set'],16),0),
        (0x40016ce8,'22690090',int(doc['source_browser']['methods']['source_browser_lock_read'],16),1)]:
        at=relocate(old);assert payload[at-base:at-base+4]==bytes.fromhex(expected)
        delta=target-(at+2);assert -32768<=delta<=32767
        payload[at-base:at-base+4]=struct.pack('>Hh',0x41fa+reg*0x200,delta)
        changes.append(dict(donor=hex(old),runtime=hex(at),adapter=hex(target)))
    assert base+len(payload)<=L.LIMIT
    raw.extend(payload);boot=B.BASE+len(raw)
    bootstrap=(out/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    raw.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));raw[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(raw),runtime_sha256=B.T.SHA(payload),flash_ready=False,
        runtime_copy={**c,'bytes':len(payload)},bytes=len(raw),bootstrap=hex(boot),bootstrap_bytes=len(raw)-(boot-B.BASE))
    doc['source_browser'].update(parameter_call_adapters=changes,
        limits=['Original Source creation/commit/bank callbacks are callable; Source event/vtable integration pending.',
                'Browser ownership and hardware behavior require integration validation.'])
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],methods=doc['source_browser']['methods'])))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
