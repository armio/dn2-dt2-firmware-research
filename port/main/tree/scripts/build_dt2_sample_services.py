#!/usr/bin/env python3
"""Connect original DT2 browser sample services to native DN2 data models."""
from pathlib import Path
import argparse,json,struct
import build_dt2_sample_manager as S
B=S.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-voice-page-controller-20261009'
SHA='fc1a2c508d0e5f66103f5c83707544b9f9d94e8de3f908f97b76851fdec6d14c'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);at=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    # SoundParamChangedInfo carries a parameter SLOT, not a table record ID.
    # Every sampler maps SAMP to28 (rawSound+20+2*28 == +0x4C). Thus native
    # ONESHOT record4 can supply the same slot for all six native Machines.
    slots={}
    for kind in range(5,11):
        record=doc['slot_maps'][str(kind)][3]
        fields=struct.unpack_from('>5I',payload,60*record)
        assert fields==(1,28,0,1023,0),(kind,fields)
        slots[kind]=record
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    name=b'21SoundParamChangedInfo\0'
    for image,vt,ti in ((donor,0x401f2990,0x401f2964),(native,0x401db734,0x401db708)):
        assert struct.unpack_from('>I',image,vt-4-B.BASE)[0]==ti
        ptr=struct.unpack_from('>I',image,ti+4-B.BASE)[0]
        assert image[ptr-B.BASE:ptr-B.BASE+len(name)]==name
    # Guard the DN2 stock synths: their slot28 is not a sampler selection.
    # The called body is otherwise the complete original DT2 assignment code.
    source='''.text
.global sound_assign_sample
sound_assign_sample:
 move.l %a2,-(%sp)
 movea.l 8(%sp),%a2
 movea.l (%a2),%a0
 movea.l 40(%a0),%a0
 move.l %a2,-(%sp)
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.s assignment_unsupported
 movea.l %d0,%a0
 mvz.b 222(%a0),%d0
 subi.l #5,%d0
 cmpi.l #5,%d0
 bhi.s assignment_unsupported
 movea.l (%sp)+,%a2
 jmp sound_assign_body
assignment_unsupported:
 movea.l (%sp)+,%a2
 moveq #0,%d0
 rts
.balign 4
'''
    provisional=B.R.assemble('.equ sound_assign_body,0x49000000\n'+source,at,out,'sample-service-size')
    body_at=at+len(provisional)
    code=B.R.assemble(f'.equ sound_assign_body,{body_at:#x}\n'+source,at,out,'sample-services')
    entry=0x40050daa;end,rows=B.M.function(donor,entry)
    assert end==0x40050e1e
    body=bytearray(donor[entry-B.BASE:end-B.BASE]);edits=[]
    mapping={0x400d9ed8:0x400dbcc4,0x401f2990:0x401db734}
    for operand,target,_,_ in B.M.operands(rows):
        dest=mapping[target]
        struct.pack_into('>I',body,operand-entry,dest)
        edits.append(dict(donor=hex(operand),runtime=hex(body_at+operand-entry),before=hex(target),after=hex(dest)))
    assert body[0x40050de2-entry:0x40050de6-entry]==bytes.fromhex('487800cd')
    body[0x40050de4-entry:0x40050de6-entry]=struct.pack('>H',4)
    edits.append(dict(donor='0x40050de4',runtime=hex(body_at+0x40050de4-entry),before=205,after=4,
                      meaning='Native record4 returns common SAMP slot28'))
    payload.extend(code);payload.extend(body);payload.extend(bytes(-len(payload)%4))
    sites=[]
    for edit in doc['sample_manager']['edits']:
        if edit['target']!=hex(entry):continue
        assert edit['kind']=='absolute operand'
        address=int(edit['runtime'],16);old=int(edit['binding'],16)
        assert payload[address-base:address-base+4]==B.BE(old)
        struct.pack_into('>I',payload,address-base,at)
        edit['binding']=hex(at);sites.append(hex(address))
    assert len(sites)==2,sites
    del doc['sample_manager']['unresolved_services'][hex(entry)]
    # SampleList's FUNC+YES uses a different shared_ptr factory overload:
    # (counter_out, unused, unused, unused, slot32*, preview_mode8*).
    # Copy that original overload and bind it to the already-linked picker.
    picker_entry=0x4019b89a;picker_end,picker_rows=B.M.function(donor,picker_entry)
    picker_at=base+len(payload)
    picker=bytearray(donor[picker_entry-B.BASE:picker_end-B.BASE])
    vt_span=next(s for s in doc['sample_manager']['spans'] if s['name']=='picker_owner_vtable')
    picker_bindings={0x4011e8f0:0x40120264,
        0x401ee5e8:int(vt_span['runtime'],16)+8,
        0x4001d80e:int(doc['sample_manager']['methods']['picker_constructor'],16)}
    for operand,target,_,_ in B.M.operands(picker_rows):
        struct.pack_into('>I',picker,operand-picker_entry,picker_bindings[target])
    payload.extend(picker);payload.extend(bytes(-len(payload)%4))
    picker_sites=[]
    for edit in doc['pool_model']['edits']:
        if edit['before']!=hex(picker_entry):continue
        assert edit['component']=='view_body'
        address=int(doc['pool_model']['methods']['view_body'],16)+int(edit['operand'],16)-0x4001e17a
        assert payload[address-base:address-base+4]==B.BE(int(edit['after'],16))
        struct.pack_into('>I',payload,address-base,picker_at)
        edit['after']=hex(picker_at);picker_sites.append(hex(address))
    assert len(picker_sites)==1
    for component in ('pool_model','sample_list_view'):
        doc[component]['unresolved']=[e for e in doc[component]['unresolved'] if e['donor']!=hex(picker_entry)]
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_services']=dict(methods={'sound_assign_sample':hex(at),'quick_assign_picker_factory':hex(picker_at)},
        donor_assignment=dict(entry=hex(entry),end=hex(end),runtime=hex(body_at),edits=edits),
        sample_records=slots,sample_slot=28,assignment_sites=sites,picker_factory_sites=picker_sites,
        picker_factory_donor=[hex(picker_entry),hex(picker_end)],
        limits=['PCM loading, persistent identities and preview remain separate unfinished services',
                'Stock synth Machines are left unchanged by this sample-only operation'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),services=doc['sample_services']['methods']),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
