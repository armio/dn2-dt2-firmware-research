#!/usr/bin/env python3
"""Preserve sample identities through native working-project Save/copy."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-browser-job-epoch-20261010'
SHA='826108c90b796e12ddef81f73b0f0caf416a1d11f15d8d0aa8d2f05ff25ec6d1'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    assert raw[0x400e1494-B.BASE:0x400e1496-B.BASE]==b'\x4e\xf9'
    original=int.from_bytes(raw[0x400e1496-B.BASE:0x400e149a-B.BASE],'big')
    constants={'PROJECT_LOCK':doc['sample_restore_lifecycle']['methods']['sample_restore_lock'],
        'PROJECT_PUBLISH':doc['project_sample_active']['methods']['sample_project_publish'],
        'SERIAL_ENTRY':doc['project_sample_active']['methods']['sample_project_serial_entry'],
        'CACHE_ENTRY':doc['project_sample_cache']['methods']['sample_cache_entry'],
        'ORIGINAL_SERIALIZE':hex(original)}
    source=''.join(f'.equ {k},{v}\n' for k,v in constants.items())+(B.T.ROOT/'scripts/asm/dn2_project_sample_copy.S').read_text()
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(source,start,out,'project-sample-copy'))
    methods={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (sample_snapshot_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'project-sample-copy.elf']))}
    assert base+len(payload)<=0x47ab0000 and len(payload)%4==0
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    def patch(address,before,after):
        assert len(before)==len(after) and image[address-B.BASE:address-B.BASE+len(before)]==before
        image[address-B.BASE:address-B.BASE+len(before)]=after
        patches.append(dict(address=hex(address),before=before.hex(),after=after.hex()))
    patch(0x4012f052,b'\x2f\x3c'+B.BE(0xc4b004),b'\x2f\x3c'+B.BE(0xc4f214))
    # A4 is called twice (4012F07A and4012F0EA) with the native memcpy ABI.
    patch(0x4012f074,b'\x49\xf9'+B.BE(0x40134490),b'\x49\xf9'+B.BE(methods['sample_snapshot_copy']))
    patch(0x400e1494,b'\x4e\xf9'+B.BE(original),b'\x4e\xf9'+B.BE(methods['sample_snapshot_serialize']))
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['project_sample_copy']=dict(methods={k:hex(v) for k,v in methods.items()},constants=constants,patches=patches,
        native_routine='0x4012f00a',native_payload_bytes=0xc4b004,temporary_allocation_bytes=0xc4f214,
        temporary_companion_offset='0xc4b004',temporary_companion_bytes=0x4210,
        invalid_source='Mark destination companion invalid; existing cache commit rejects missing/mismatched identity state.',
        lifetime='Companion belongs to the augmented temporary allocation, freed by unchanged native4012F124.',
        limits=['Other raw/cache-to-temporary copy paths remain to connect.',
                'Physical scheduling and save/power-off behavior require device validation.'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),copy=doc['project_sample_copy']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
