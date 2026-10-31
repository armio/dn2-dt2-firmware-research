#!/usr/bin/env python3
"""Bind the complete original DT2 used-sample bitmap scan to DN2 models."""
from pathlib import Path
import argparse,json,struct
import build_dt2_sample_services as S
B=S.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-services-20261009'
SHA='4cf75471e28014ee1375ab190f9107493e7ffd44d8b4393b30c21a65ddeafd3a'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    out.mkdir(parents=True,exist_ok=False)
    def append(blob):
        at=base+len(payload);payload.extend(blob);payload.extend(bytes(-len(payload)%4));return at
    # Native preset Sound accessor and PatternLocks member accessor are exact
    # complete code twins. Preset-valid vtable slots call corresponding native
    # validity/empty methods; the containing class has the same 128*960 layout.
    for old,new,end in [(0x40053176,0x4004dfb0,0x400531a2),
                        (0x4003f3ba,0x4003b3a0,0x4003f3c6)]:
        assert donor[old-B.BASE:end-B.BASE]==native[new-B.BASE:new+end-old-B.BASE]
    assert struct.unpack_from('>I',donor,0x401f57dc+0x68-B.BASE)[0]==0x40052f0a
    assert struct.unpack_from('>I',native,0x401de518+0x68-B.BASE)[0]==0x4004dd52
    valid_old=bytearray(donor[0x40052f0a-B.BASE:0x40052f48-B.BASE])
    valid_new=bytearray(native[0x4004dd52-B.BASE:0x4004dd90-B.BASE])
    for offset,old,new in [(0x14,0x400f575c,0x400f7138),(0x2e,0x40050022,0x4004b1da)]:
        assert valid_old[offset:offset+4]==B.BE(old) and valid_new[offset:offset+4]==B.BE(new)
        valid_old[offset:offset+4]=valid_new[offset:offset+4]=bytes(4)
    assert valid_old==valid_new
    helper_at=base+len(payload)
    helpers=B.R.assemble((B.T.ROOT/'scripts/asm/dt2_used_samples.S').read_text(),helper_at,out,'used-samples')
    append(helpers)
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'used-samples.elf'])
    symbols={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3}
    bitset=bytearray(donor[0x401a678e-B.BASE:0x401a67d6-B.BASE])
    bitset[0x401a67a8-0x401a678e:0x401a67ac-0x401a678e]=B.BE(0x40212952)
    bitset[0x401a67ae-0x401a678e:0x401a67b2-0x401a678e]=B.BE(0x401cb336)
    assert native[0x40212952-B.BASE:0x40212952-B.BASE+12]==b'bitset::set\0'
    bitset_at=append(bitset)
    entry,end=0x40043c1c,0x40043d9a
    body=bytearray(donor[entry-B.BASE:end-B.BASE]);at=base+len(payload);edits=[]
    mapping={0x400d9ed8:0x400dbcc4,0x401360f4:0x401344d8,
        0x401a678e:bitset_at,0x4003f3ba:0x4003b3a0,
        0x400405ce:symbols['used_sample_lock'],0x40053176:0x4004dfb0,
        0x40050e1e:symbols['used_sample_from_sound']}
    for operand,target,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,entry,end)):
        struct.pack_into('>I',body,operand-entry,mapping[target])
        edits.append(dict(donor=hex(operand),runtime=hex(at+operand-entry),before=hex(target),after=hex(mapping[target])))
    def patch(pc,before,after,why):
        offset=pc-entry;assert body[offset:offset+len(before)]==before
        assert len(before)==len(after);body[offset:offset+len(before)]=after
        edits.append(dict(donor=hex(pc),runtime=hex(at+offset),before=before.hex(),after=after.hex(),reason=why))
    patch(0x40043c2c,bytes.fromhex('00cd'),bytes.fromhex('0004'),'Native SAMP slot28')
    patch(0x40043c52,B.BE(0x5574),B.BE(0x5d71),'Native kit stride (offset superseded by accessor)')
    patch(0x40043cae,B.BE(0x43d0),B.BE(0x4414),'Native pattern objects')
    for pc in (0x40043d10,0x40043d28):
        patch(pc,B.BE(0x4f314),B.BE(0x4f358),'Native preset pool member')
    call=B.R.assemble(f'''.text
 move.l %d3,-(%sp)
 move.l %d4,-(%sp)
 move.l %a2,-(%sp)
 jsr {symbols['used_sample_from_kit']:#x}
 lea 12(%sp),%sp
 move.l %d0,%d1
''',at+0x40043c5c-entry,out,'used-sample-kit-call')
    assert len(call)<=36 and len(call)%2==0
    patch(0x40043c5c,donor[0x40043c5c-B.BASE:0x40043c80-B.BASE],
        call+b'\x4e\x71'*((36-len(call))//2),'Native saved-kit sample getter with sampler-only guard')
    append(body)
    sites=[]
    for edit in doc['sample_manager']['edits']:
        if edit['target']!=hex(entry):continue
        address=int(edit['runtime'],16);old=int(edit['binding'],16)
        assert payload[address-base:address-base+4]==B.BE(old)
        struct.pack_into('>I',payload,address-base,at);edit['binding']=hex(at);sites.append(hex(address))
    assert sites
    del doc['sample_manager']['unresolved_services'][hex(entry)]
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['used_samples']=dict(methods=dict(bitmap=hex(at),bitset_set=hex(bitset_at),
        **{k:hex(v) for k,v in symbols.items() if k.startswith('used_sample_')}),
        donor=[hex(entry),hex(end)],edits=edits,manager_call_sites=sites,
        scope='Original full 129-kit,128-pattern,128-preset and eight OFF-slot scan',
        limits=['Incremental reference-cache scheduling and pool in-use query remain separate',
                'Identity storage, sample loading and preview services remain unfinished'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]: (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),used_samples=doc['used_samples']['methods']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
