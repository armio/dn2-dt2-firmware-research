#!/usr/bin/env python3
"""Add an on-screen pointer diagnostic for the T1 startup exception."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-browser-preferences-20261010'
SHA='6df33ef8f78a6588ff397fcf48bf3f19d4e04a1fbc5ebf62f1ded00611447a68'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);entry=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    source=(B.T.ROOT/'scripts/asm/dn2_boot_kit_diagnostic.S').read_text()
    payload.extend(B.R.assemble(source,entry,out,'boot-kit-diagnostic'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (boot_kit_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'boot-kit-diagnostic.elf']))}
    image=bytearray(raw[:src-B.BASE])+payload
    at=0x40191768-B.BASE
    assert image[at:at+6]==bytes.fromhex('20522668005c')
    image[at:at+6]=b'\x4e\xf9'+B.BE(symbols['boot_kit_guard'])
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['boot_kit_diagnostic']=dict(methods={k:hex(v) for k,v in symbols.items()},hook='0x40191768',
        fault_observed='T1 immediate boot: V0B M0 PA100A100; stack return40191776, Kit446CACE4, Project446CABF0.',
        purpose='Expose invalid Kit vtable/callee via native exception stack display; diagnosis, not a root-cause fix.',
        stack_words=['Kit pointer','actual vtable','callee at vtable+6C or FFFFFFFF','TB1D marker',
        'native vtable+6C','native vtable+5C','native getter first instruction word',
        'Project singleton','Kit+4','Kit current index+44','native caller return','expected native Kit vtable'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],diagnostic=doc['boot_kit_diagnostic']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
