#!/usr/bin/env python3
"""Bridge DT2 Source parameter IDs to DN2 native parameter objects."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_waveform_drawers as W
import build_dt2_sampler_controls as C
B=W.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-waveform-drawers-20261009'
SHA='5ac4e53e08cbd8702ef2d54fba4a3e0ea9e5cfab364c355de37d9dbc33330008'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    donor=B.M.S.DONOR.read_bytes();doc=json.loads((INPUT/'build-receipt.json').read_text())
    controls=json.loads((B.T.ROOT/'output/dn2-research/dt2-sampler-table-complete-records-20261009/controls.json').read_text())
    records={r['donor_id']:(r['entry'],r['slot']) for m in controls['machines'] for r in m['records']}
    for old in range(202,210):
        record=C.DONOR_RECORD0+old*C.C.RECORD-B.BASE
        slot=struct.unpack_from('>I',donor,record+C.C.SLOT)[0]
        records[old]=(doc['slot_maps']['5'][slot-25],slot)
    assert set(records)==set(range(200,255))
    assert len({v[0] for v in records.values()})==55
    slots=[records[old][1] for old in range(200,255)]
    reverse={new:old for old,(new,slot) in records.items()}
    slots_asm=','.join(str(s) for s in slots)
    reverse_asm=','.join(str(reverse.get(n,0)) for n in range(368))
    source=f'''.text
.global source_parameter_id,source_parameter_get,source_parameter_set
.global source_parameter_lock_get,source_parameter_lock_set
.global source_donor_parameter_id,source_donor_machine
/* Resolve through the native active Machine slot map. DT2's parameter205
 * is an intentional sample-ID alias even on the other sampler Machines. */
source_parameter_id:
 move.l 8(%sp),%d0
 subi.l #200,%d0
 cmpi.l #54,%d0
 bhi.s parameter_invalid
 lea source_parameter_slots,%a0
 mvz.b (%a0,%d0.l),%d0
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 move.l %d0,%d2
 movea.l 12(%sp),%a2
 movea.l 16(%a2),%a0
 movea.l (%a0),%a1
 move.l %a0,-(%sp)
 movea.l 40(%a1),%a0
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.s parameter_invalid_pop
 movea.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s parameter_invalid_pop
 movea.l (%a2),%a0
 move.l %d2,-(%sp)
 move.l %a2,-(%sp)
 movea.l 80(%a0),%a0
 jsr (%a0)
 addq.l #8,%sp
 movea.l (%sp)+,%a2
 move.l (%sp)+,%d2
 rts
parameter_invalid_pop:
 movea.l (%sp)+,%a2
 move.l (%sp)+,%d2
parameter_invalid:
 moveq #0,%d0
 rts
/* Native IDs cannot fit the DT2 Source byte table. Keep donor IDs inside
 * the original view and translate at native parameter-operation boundaries. */
source_donor_parameter_id:
 move.l 4(%sp),%d0
 cmpi.l #367,%d0
 bhi.s donor_parameter_invalid
 lea source_parameter_reverse,%a0
 mvz.b (%a0,%d0.l),%d0
 rts
donor_parameter_invalid:
 moveq #0,%d0
 rts
source_donor_machine:
 move.l 4(%sp),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s donor_machine_invalid
 cmpi.l #5,%d0
 bne.s donor_machine_done
 moveq #6,%d0
donor_machine_done:
 rts
donor_machine_invalid:
 moveq #-1,%d0
 rts
'''
    for name,offset in [('get',40),('lock_get',64),('lock_set',68),('set',None)]:
        source+=f'''
source_parameter_{name}:
 move.l 8(%sp),%d0
 move.l 4(%sp),%a0
 move.l %d0,-(%sp)
 move.l %a0,-(%sp)
 jsr source_parameter_id
 addq.l #8,%sp
 tst.l %d0
 beq.s {name}_invalid
 move.l %d0,8(%sp)
'''
        if offset is None:source+=' jmp 0x40037326\n'
        else:source+=f''' movea.l 4(%sp),%a0
 movea.l (%a0),%a0
 movea.l {offset}(%a0),%a0
 jmp (%a0)
'''
        source+=f'''{name}_invalid:
 moveq #-1,%d0
 rts
'''
    source+=f'''.balign 4
source_parameter_slots:
 .byte {slots_asm}
source_parameter_reverse:
 .byte {reverse_asm}
.balign 4
'''
    copy=doc['runtime_copy'];base,src=int(copy['destination'],16),int(copy['source'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'source-parameters'))
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'source-parameters.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['source_parameters']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('source_')},
        records={str(old):dict(native=new,slot=slot) for old,(new,slot) in sorted(records.items())},
        bytes=len(payload)-copy['bytes'],spans=[],edits=[],
        limits=['Adapters are callable; SourcePageView call sites and vtable boundaries still need integration.',
                'Only sampler parameter IDs are accepted; unsupported IDs return invalid without writing.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['source_parameters']['methods']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
