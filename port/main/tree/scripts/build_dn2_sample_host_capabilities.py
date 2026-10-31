#!/usr/bin/env python3
"""Advertise original DT2 sample commands in DN2's native Ping response."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-host-lifecycle-20261010'
SHA='41c3268bea2c52977812ecd71bfd63e2f92cb889997207760129a98698ec3544'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    commands=donor[0x4021e564-B.BASE:0x4021e590-B.BASE]
    stock=native[0x40207f30-B.BASE:0x40207f46-B.BASE]
    assert len(commands)==44 and len(set(commands))==44 and set(stock)<set(commands)
    cases=[]
    for command in commands:
        target=0x40138fde+struct.unpack_from('>h',native,0x40138fde-B.BASE+2*(command-1))[0]
        assert target!=0x4013bc68,hex(command)  # unsupported-command branch
        cases.append(dict(command=hex(command),native_parser_case=hex(target)))
    copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);table=base+len(payload)
    payload.extend(commands);assert base+len(payload)<=0x47ab0000
    image=bytearray(raw[:src-B.BASE])+payload
    patches=[(0x40125d6e,bytes.fromhex('48780016'),bytes.fromhex('4878002c')),
        (0x40125da4,b'\x48\x79'+B.BE(0x40207f46),b'\x48\x79'+B.BE(table+len(commands))),
        (0x40125daa,bytes.fromhex('43e90016'),bytes.fromhex('43e9002c')),
        (0x40125dae,b'\x48\x79'+B.BE(0x40207f30),b'\x48\x79'+B.BE(table))]
    for address,before,after in patches:
        assert image[address-B.BASE:address-B.BASE+len(before)]==before
        image[address-B.BASE:address-B.BASE+len(after)]=after
    # Keep DN2's product code (0x2b), software version and identity paths.
    assert image[0x40125df4-B.BASE:0x40125df6-B.BASE]==bytes.fromhex('722b')
    out.mkdir(parents=True,exist_ok=False)
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},
        runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_host_capabilities']=dict(table=hex(table),commands=list(commands),stock_commands=list(stock),
        added_commands=sorted(set(commands)-set(stock)),donor_table='0x4021e564',native_ping='0x40125cbe',
        product_code=43,patches=[dict(address=hex(a),before=b.hex(),after=c.hex()) for a,b,c in patches],
        native_parser_cases=cases,
        limits=['Advertisement does not prove each request path or physical Transfer compatibility.'])
    doc['sample_host']['vtable_getter_evidence_note']='Third virtual entry reads sequence ID at +4; command byte is +8. Getter equality does not prove payload layouts.'
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),table=hex(table),commands=len(commands)),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
