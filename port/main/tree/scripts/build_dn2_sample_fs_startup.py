#!/usr/bin/env python3
"""Mount the ported sample filesystem from the established native UI hook."""
from pathlib import Path
import argparse,json,re
import build_dn2_sample_cursor_tracks as P
B=P.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-cursor-tracks-20261009'
SHA='53656af9881f8b5c4a52b15402c291f823ef502f7903aefde4a22fd0d7205e34'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray((INPUT/'runtime.bin').read_bytes());at=base+len(payload)
    fn={int(a,16):int(b,16) for a,b in (line.split() for line in (INPUT/'fn_new_map.txt').read_text().splitlines())}
    asm=f'.equ fs_initialize,{fn[0x4015a43a]:#x}\n.equ fs_mount,{fn[0x4015a450]:#x}\n'
    asm+=(B.T.ROOT/'scripts/asm/dn2_sample_fs_startup.S').read_text()
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(asm,at,out,'sample-fs-startup'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-fs-startup.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    image=bytearray(raw[:src-B.BASE])+payload
    worker=json.loads((B.T.ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3/runtime-candidate/worker-symbols.json').read_text())
    patches=[]
    def replace_runtime(address,old,new,why):
        assert len(old)==len(new)
        c=next(c for c in doc['copies'] if int(c['destination'],16)<=address<int(c['destination'],16)+c['bytes'])
        offset=int(c['source'],16)-B.BASE+address-int(c['destination'],16)
        assert image[offset:offset+len(old)]==old,(hex(address),image[offset:offset+len(old)].hex())
        image[offset:offset+len(new)]=new
        patches.append(dict(runtime=hex(address),file_offset=hex(offset),before=old.hex(),after=new.hex(),why=why))
    replace_runtime(worker['os_poll'],bytes.fromhex('4fefffd848d73cfc'),
        b'\x4e\xf9'+B.BE(symbols['sample_fs_startup'])+b'\x4e\x71','UI poll initializes and mounts sample filesystem once')
    # Reject the obsolete OSB1 fixed-bank upload request: it uses a different
    # DSP protocol and must not reset a filesystem now used by the browser.
    replace_runtime(worker['os_request'],bytes.fromhex('0c82000000016600'),
        bytes.fromhex('7002154000034e75'),'Old command4 returns unsupported; no private bank loader')
    assert base+len(payload)<=int(doc['runtime_limit'],16) and len(payload)%4==0
    boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_fs_startup']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('sample_fs_')},
        patches=patches,entry=hex(worker['os_poll']),legacy_request=hex(worker['os_request']),
        native_initialize=hex(fn[0x4015a43a]),native_mount=hex(fn[0x4015a450]),
        automatic_mount=True,automatic_format=False,legacy_bank_request_enabled=False,
        limits=['Native MMC wait duration is hardware dependent; initialization runs once on the UI task.',
                'Sample restoration from saved Project identities remains to be connected.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),startup=doc['sample_fs_startup']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
