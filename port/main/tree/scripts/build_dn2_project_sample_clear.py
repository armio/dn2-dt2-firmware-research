#!/usr/bin/env python3
"""Pair the native raw NEW PROJECT reset with an empty active sample table."""
from pathlib import Path
import argparse,json
import build_dn2_project_sample_active as A
B=A.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-project-sample-active-20261009'
SHA='00e28cb42a0f8f1a43c952c43aa009f94a3d7e0cc67d06ce6fadb55dc18c5836'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);out.mkdir(parents=True,exist_ok=False)
    entry=0x400e7940;original=bytes.fromhex('4fefffec48d70c1c')
    assert raw[entry-B.BASE:entry-B.BASE+8]==original
    trampoline=base+len(payload);payload.extend(original+b'\x4e\xf9'+B.BE(entry+8));payload.extend(bytes(-len(payload)%4))
    methods=doc['project_sample_active']['methods'];at=base+len(payload)
    defines=f'.equ NATIVE_RAW_CLEAR,{trampoline:#x}\n.equ PROJECT_STATE,{methods["sample_project_state"]}\n.equ PROJECT_PUBLISH,{methods["sample_project_publish"]}\n'
    payload.extend(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_project_sample_clear.S').read_text(),at,out,'project-sample-clear'))
    payload.extend(bytes(-len(payload)%4))
    relabel_trampolines={}
    for address,prologue in ((0x400f6898,'4feffff448d7001c'),(0x400f68f6,'4feffff048d70c0c')):
        original_relabel=bytes.fromhex(prologue)
        assert raw[address-B.BASE:address-B.BASE+8]==original_relabel
        relabel_trampolines[address]=base+len(payload)
        payload.extend(original_relabel+b'\x4e\xf9'+B.BE(address+8));payload.extend(bytes(-len(payload)%4))
    relabel_at=base+len(payload)
    symbols={'NATIVE_MOVE':relabel_trampolines[0x400f6898],
             'NATIVE_SWAP':relabel_trampolines[0x400f68f6],
             'CACHE_ENTRY':int(doc['project_sample_cache']['methods']['sample_cache_entry'],16)}
    defines='\n'.join(f'.equ {k},{v:#x}' for k,v in symbols.items())+'\n'
    payload.extend(B.R.assemble(defines+(B.T.ROOT/'scripts/asm/dn2_project_sample_relabel.S').read_text(),relabel_at,out,'project-sample-relabel'))
    payload.extend(bytes(-len(payload)%4))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','--defined-only',out/'project-sample-relabel.elf'])
    relabel_methods={s[2]:int(s[0],16) for line in nm.splitlines() if len(s:=line.split())==3 and s[2].startswith('sample_cache_')}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload
    image[entry-B.BASE:entry-B.BASE+8]=b'\x4e\xf9'+B.BE(at)+b'\x4e\x71'
    for address,key in ((0x400f6898,'sample_cache_move'),(0x400f68f6,'sample_cache_swap')):
        image[address-B.BASE:address-B.BASE+8]=b'\x4e\xf9'+B.BE(relabel_methods[key])+b'\x4e\x71'
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_clear']=dict(method=hex(at),native_entry=hex(entry),trampoline=hex(trampoline),
        raw_boot_buffer='0x41218970',native_return='void',
        callers=['0x4003e988','0x40042968','0x400bb2ee'],
        limits=['Boot mirror restoration happens before Project construction and remains unconnected',
                'Temporary raw/serialized copies, PCM restore and hardware validation remain pending'])
    doc['project_sample_relabel']=dict(methods={k:hex(v) for k,v in relabel_methods.items()},
        trampolines={hex(k):hex(v) for k,v in relabel_trampolines.items()},
        preserves='Physical cache payload and companion remain paired during native slot move/swap')
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),method=hex(at)),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);build(p.parse_args().output)
