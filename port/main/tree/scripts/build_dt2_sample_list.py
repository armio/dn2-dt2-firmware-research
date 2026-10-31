#!/usr/bin/env python3
"""Link native DT2 sample-list drawing and slot access into the DN2 runtime.

This supplies callable view methods, not a fabricated popup or pool. The
factory, event routing, pool owner, preview and commit callbacks remain to
connect before a firmware can expose the browser.
"""
from pathlib import Path
import argparse
import json
import re
import struct

import map_dt2_browser_runtime as M
import build_dt2_sampler_runtime as R

T,BASE,BE=R.T,R.BASE,R.BE
INPUT=T.ROOT/'output/dn2-research/dt2-werp-live-v3-20261009'
INPUT_SHA='e2b5ae894ed433c311b905fc0c5e60215436003b35cecb1ae38b2b25f3103f61'
FUNCTIONS={name:M.S.FUNCTIONS[name] for name in
           ('list_draw','list_set_slot','list_get_slot','list_set_mode','list_set_preview_mode')}


def resident_copies(raw):
    rows=[]
    loader=raw[0x40322910-BASE:0x40322a50-BASE]
    for match in re.finditer(b'\x22\x3c(.{4})\x45\xf9(.{4})\x43\xf9(.{4})\x22\xd2',loader,re.S):
        words,source,dest=(struct.unpack('>I',x)[0] for x in match.groups())
        assert 0<=source-BASE<source-BASE+4*words<=len(raw)
        rows.append(dict(source=hex(source),destination=hex(dest),bytes=4*words))
    assert len(rows)==5
    return rows


def region_twin(donor,recipient,lo,hi,dest):
    """Verify all bytes except individually enumerated absolute operands."""
    source=donor[lo-BASE:hi-BASE]
    other=recipient[dest-BASE:dest-BASE+len(source)]
    masked=bytearray(source); normalized=bytearray(other);pairs={}
    for at,value,_,_ in M.operands(M.S.disasm(donor,BASE,lo,hi)):
        off=at-lo
        new=struct.unpack_from('>I',other,off)[0]
        assert value not in pairs or pairs[value]==new
        pairs[value]=new
        masked[off:off+4]=normalized[off:off+4]=bytes(4)
    assert masked==normalized,(hex(lo),hex(dest))
    return pairs


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes()
    assert T.SHA(raw)==INPUT_SHA
    donor=M.S.DONOR.read_bytes();assert T.SHA(donor)==M.S.SHA
    recipient=M.RECIPIENT.read_bytes()
    mapping=json.loads((M.OUT/'map.json').read_text())
    assert T.SHA(recipient)==mapping['recipient_sha256']
    resolved={int(x['donor'],16):int(x['dn2_twins'][0],16) for x in mapping['functions']
              if len(x.get('dn2_twins',[]))==1}
    # Context identifies the correct StringArg ctor/dtor among short twins.
    pairs=region_twin(donor,recipient,0x40114374,0x4011450a,0x40115ce8)
    assert pairs[0x4021cb58]==0x40206524
    resolved.update({0x40114374:0x40115ce8,0x401144f8:0x40115e6c})
    # The item-ID getter is literal, identical code with no address operands.
    assert donor[0x401154e0-BASE:0x401154ea-BASE]==recipient[0x40116e54-BASE:0x40116e5e-BASE]
    resolved[0x401154e0]=0x40116e54
    # Shared font object mapping from a complete native panel renderer twin.
    fonts=region_twin(donor,recipient,0x40061464,0x40061678,0x4005b7d4)
    assert fonts[0x44d2e70c]==0x44507ef8
    resolved[0x44d2e70c]=0x44507ef8
    # Generic font/string interface singleton, previously mapped by the
    # complete native control function 40069b8e..40069dd8.
    controls=json.loads((T.ROOT/'output/dn2-research/oneshot-gui-navigation-20261008/control-twins.json').read_text())
    row=next(x for x in controls if x['dt2']=='0x40069b8e')
    cp=region_twin(donor,recipient,int(row['dt2'],16),int(row['end'],16),int(row['dn2_twins'][0],16))
    assert cp[0x402a96a0]==0x402941d0
    resolved[0x402a96a0]=0x402941d0
    out.mkdir(parents=True,exist_ok=False)
    receipt=json.loads((INPUT/'build-receipt.json').read_text())
    copy=receipt['runtime_copy'];source=int(copy['source'],16);runtime=int(copy['destination'],16)
    payload=bytearray(raw[source-BASE:source-BASE+copy['bytes']])
    methods={};chunks=[]
    for name,(lo,hi) in FUNCTIONS.items():
        at=runtime+len(payload)
        methods[name]=at
        resolved[lo]=at
        chunks.append((name,lo,hi,len(payload)))
        payload.extend(donor[lo-BASE:hi-BASE])
    strings={}
    for _,lo,hi,_ in chunks:
        for _,target,_,_ in M.operands(M.S.disasm(donor,BASE,lo,hi)):
            if target in resolved:continue
            assert 0x40229000<=target<0x4022a000,hex(target)
            end=donor.index(0,target-BASE)+1
            text=donor[target-BASE:end]
            assert len(text)<128
            resolved[target]=runtime+len(payload)
            strings[hex(target)]=dict(address=hex(resolved[target]),bytes=text.hex())
            payload.extend(text)
    edits=[]
    for name,lo,hi,off in chunks:
        for at,target,mn,ops in M.operands(M.S.disasm(donor,BASE,lo,hi)):
            dest=resolved[target]
            struct.pack_into('>I',payload,off+at-lo,dest)
            edits.append(dict(function=name,operand=hex(at),before=hex(target),after=hex(dest)))
        linked=bytes(payload[off:off+hi-lo])
        (out/(name+'.bin')).write_bytes(linked)
        (out/(name+'.asm')).write_text('\n'.join(f'{a:08x} {h:24s} {m:10s} {o}' for a,h,m,o in
             M.S.disasm(linked,methods[name],methods[name],methods[name]+len(linked)))+'\n')
    payload.extend(bytes(-len(payload)%4))
    assert runtime+len(payload)<=R.LIMIT
    image=bytearray(raw[:source-BASE])+payload
    bootstrap_at=BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(R.assemble(asm,bootstrap_at,out,'bootstrap'))
    image[0xb2:0xb8]=b'\x4e\xf9'+BE(bootstrap_at)
    (out/'runtime.bin').write_bytes(payload);(out/'main-os.bin').write_bytes(image)
    receipt.update(baseline_sha256=INPUT_SHA,main_sha256=T.SHA(image),bytes=len(image),
        copies=resident_copies(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=T.SHA(payload),
        bootstrap=hex(bootstrap_at),bootstrap_bytes=len(image)-(bootstrap_at-BASE),
        sample_list=dict(methods={k:hex(v) for k,v in methods.items()},strings=strings,patches=edits,
                         inherited_dsp=str(INPUT/'dsp/section_7.bin'),
                         donor_code_bytes=sum(hi-lo for lo,hi in FUNCTIONS.values()),
                         connected_to_ui=False,
                         remaining=['Native constructor/factory and model lifetime','Encoder and event routing',
                                    'Pool restoration/loading','Audition, commit/cancel and +Drive quick assignment']),
        flash_ready=False)
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'],methods=receipt['sample_list']['methods'],
                         runtime_bytes=len(payload),flash_ready=False),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
