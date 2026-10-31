#!/usr/bin/env python3
"""Select the original DT2 Source view through native MainScreen page lookup."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_source_factory as F
B=F.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-source-factory-20261009'
SHA='31f1259b1ab709b235902f0ff09a28a3f94748b61cd53dd87a21c2a175058591'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);at=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    source=f'.equ source_factory,{doc["source_factory"]["methods"]["factory"]}\n'
    source+=(B.T.ROOT/'scripts/asm/dn2_source_page_route.S').read_text()
    payload.extend(B.R.assemble(source,at,out,'source-page-route'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'source-page-route.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    for addr,original,name in [(0x4005e844,'2002e78847f40800','source_open_pair_hook'),
                               (0x4005d14e,'e78c22422441d5c4','source_get_pair_hook'),
                               (0x4019e9c2,'4feffff448d71c00','source_main_destroy_hook')]:
        before=bytes.fromhex(original);assert image[addr-B.BASE:addr-B.BASE+8]==before
        opcode=b'\x4e\xf9' if name=='source_main_destroy_hook' else b'\x4e\xb9'
        after=opcode+B.BE(symbols[name])+b'\x4e\x71'
        image[addr-B.BASE:addr-B.BASE+8]=after
        patches.append(dict(address=hex(addr),before=before.hex(),after=after.hex(),role=name))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
               runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
               bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['source_page_route']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('source_')},patches=patches,
        behavior='Native audio SYN entry selects a separate original DT2 Source view for native Machines5..10; stock/MIDI pages retained.',
        limits=['External notification delivery and physical UI behavior require validation.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),route=doc['source_page_route']),indent=2))

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--out',type=Path,required=True);build(a.parse_args().out)
