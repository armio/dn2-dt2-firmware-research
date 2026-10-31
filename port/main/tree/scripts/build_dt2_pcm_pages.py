#!/usr/bin/env python3
"""Retain DT2 PCM page/publish code and bind the existing DN2 page transport."""
from pathlib import Path
import argparse,json,re,struct
import build_dn2_project_sample_active as A
B=A.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-backup-20261009'
SHA='58b809d01ebac61abd1740588412389896b2b70f8464daa48f6225c677c14799'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    # Both physical writers are exact native twins, including their register
    # addresses and byte-strobe order. Verify the entire page wrapper too,
    # permitting only known mutex/delay/PC-relative helper relocations.
    twins={0x400ccda0:0x400cf178,0x400cce2c:0x400cf204}
    evidence=[]
    for entry,target in twins.items():
        end,rows=B.M.function(donor,entry);size=end-entry
        assert donor[entry-B.BASE:end-B.BASE]==native[target-B.BASE:target-B.BASE+size]
        evidence.append(dict(donor=hex(entry),native=hex(target),bytes=size,kind='exact complete function'))
    transport=0x400cd638;native_transport=0x400cf9aa;end,rows=B.M.function(donor,transport)
    mapped=bytearray(donor[transport-B.BASE:end-B.BASE])
    mapping={0x42948b14:0x42440964,0x400015a0:0x400015a0,0x400016d2:0x400016d2,
             0x40136268:0x4013464c}
    for operand,target,_,_ in B.M.operands(rows):struct.pack_into('>I',mapped,operand-transport,mapping[target])
    for pc,hx,mn,ops in rows:
        match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
        if match:
            target=int(match[1],16);assert target in twins
            struct.pack_into('>h',mapped,pc-transport+2,twins[target]-(native_transport+pc-transport+2))
    assert bytes(mapped)==native[native_transport-B.BASE:native_transport-B.BASE+len(mapped)]
    evidence.append(dict(donor=hex(transport),native=hex(native_transport),bytes=len(mapped),
                         kind='complete function twin after mutex, delay and helper relocation'))
    # New[]/delete[] are thin native aliases; retain the donor owner cleanup body.
    assert donor[0x4011e8f6-B.BASE:0x4011e8fc-B.BASE]==b'\x4e\xf9'+B.BE(0x4011e674)
    assert native[0x4012026a-B.BASE:0x40120270-B.BASE]==b'\x4e\xf9'+B.BE(0x4011ffe8)
    assert donor[0x4011e902-B.BASE:0x4011e908-B.BASE]==b'\x4e\xf9'+B.BE(0x4011e87a)
    assert native[0x40120276-B.BASE:0x4012027c-B.BASE]==b'\x4e\xf9'+B.BE(0x401201ee)
    entries={'deinterleave':0x4015358c,'write_pages':0x40153734,
             'publish_stereo':0x40153b28,'publish_mono':0x40153b90,'owned_buffer_destroy':0x401cab98}
    functions={};spans=[];edits=[]
    for name,entry in entries.items():
        end,rows=B.M.function(donor,entry);payload.extend(bytes(-len(payload)%4));at=base+len(payload)
        payload.extend(donor[entry-B.BASE:end-B.BASE]);functions[name]=at;spans.append((entry,end,at,rows))
    bindings={0x400cd638:native_transport,0x4011e8f6:0x4012026a,0x4011e902:0x40120276,
              **{entry:functions[name] for name,entry in entries.items()}}
    for entry,end,at,rows in spans:
        for operand,target,_,_ in B.M.operands(rows):
            dest=bindings[target];struct.pack_into('>I',payload,at-base+operand-entry,dest)
            edits.append(dict(donor=hex(operand),runtime=hex(at+operand-entry),target=hex(target),binding=hex(dest)))
        for pc,hx,mn,ops in rows:
            match=re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if match:assert entry<=int(match[1],16)<end,(hex(pc),ops)
    payload.extend(bytes(-len(payload)%4));assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['pcm_pages']=dict(methods={k:hex(v) for k,v in functions.items()},transport='0x400cf9aa',
        twins=evidence,spans=[dict(donor=hex(lo),end=hex(hi),runtime=hex(at)) for lo,hi,at,_ in spans],edits=edits,
        limits=['Original page protocol retained; DSP receive routing still needs tracing',
                'Allocator, manager load/unload, preview and full restoration are not connected'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['pcm_pages']['methods']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);build(p.parse_args().output)
