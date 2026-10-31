#!/usr/bin/env python3
"""Correct host sample assignment and retain state until queued callbacks finish."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-host-capabilities-20261010'
SHA='54e97d5c92a502ff003e9738cdc45c0d98fb4879f14678b8aa328f4b7a570c0c'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());life=doc['sample_host_lifecycle']
    copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    source=''.join(f'.equ {k},{v}\n' for k,v in life['constants'].items())
    source+=(B.T.ROOT/'scripts/asm/dn2_sample_host_lifecycle_assignment.S').read_text()
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'sample-host-lifecycle'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-host-lifecycle.elf']))}
    assert base+len(payload)<=0x47ab0000
    image=bytearray(raw[:src-B.BASE])+payload
    span=next(s for s in doc['sample_host']['spans'] if int(s['donor'],16)<=0x40127efa<int(s['end'],16))
    slot_site=int(span['runtime'],16)+0x40127efa-int(span['donor'],16)
    offset=slot_site-base
    assert payload[offset:offset+2]==bytes.fromhex('e189')
    # SAMP is an integer parameter (0..1023). The host callback's Q8 shift
    # sends slot7 as1792 and the native setter clamps it to1023.
    payload[offset:offset+2]=bytes.fromhex('4e71')
    image[src-B.BASE+offset:src-B.BASE+offset+2]=bytes.fromhex('4e71')
    patches=[]
    for site,opcode,name in [(0x4012693e,b'\x4e\xb9','sample_host_route'),(0x4012549a,b'\x4e\xf9','sample_host_native_destroy')]:
        old=int(life['methods'][name],16);new=symbols[name]
        assert image[site-B.BASE:site-B.BASE+6]==opcode+B.BE(old)
        image[site-B.BASE:site-B.BASE+6]=opcode+B.BE(new)
        patches.append(dict(address=hex(site),old=hex(old),new=hex(new)))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    life.update(methods={k:hex(v) for k,v in symbols.items() if k.startswith('sample_host_')},
        deferred_retirement=True,patches=patches,
        limits=['Registry mutations assume native RPC owner serialization.',
                'Detached pending state is collected on the next host state lookup after completion; without further requests it remains until reboot.',
                'Project changes during queued jobs and physical transfer remain separate integration work.'])
    doc['sample_host_assignment']=dict(sample_slot_units='integer',removed_q8_shift=dict(donor='0x40127efa',runtime=hex(slot_site),before='e189',after='4e71'),
        limits=['Other assignment modes and project changes during a pending job need integration.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=life['methods']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
