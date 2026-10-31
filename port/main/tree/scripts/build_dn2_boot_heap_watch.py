#!/usr/bin/env python3
"""T1D3: trace the overlapping native heap allocation identified on hardware."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-boot-kit-watch-r3-20261010'
SHA='8b0f43a1814718a9c0d6e6d9e689606a12943347e16f6a91f65fa1ffaa49daf0'
SITES=[('project_allocated',0x4018a99a,'2f39405c6dd8'),('malloc_enter',0x4011ffe8,'4fefffd448d77cfc'),('malloc_return',0x401201b2,'4cd77cfc4fef002c'),('free_enter',0x401201ee,'4feffff448d7001c')]
def build(out):
 raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
 doc=json.loads((INPUT/'build-receipt.json').read_text());c=doc['runtime_copy'];src,base=int(c['source'],16),int(c['destination'],16)
 payload=bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']]);entry=base+len(payload);out.mkdir(parents=True,exist_ok=False)
 source='.equ WATCH_DONE,'+doc['boot_kit_watch']['methods']['boot_watch_done']+'\n'+(B.T.ROOT/'scripts/asm/dn2_boot_heap_watch.S').read_text()
 payload.extend(B.R.assemble(source,entry,out,'boot-heap-watch'));payload.extend(bytes(-len(payload)%4))
 sy={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (boot_heap_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'boot-heap-watch.elf']))}
 assert base+len(payload)<=int(doc['runtime_limit'],16)
 image=bytearray(raw[:src-B.BASE])+payload;patches=[]
 for name,addr,hx in SITES:
  before=bytes.fromhex(hx);assert image[addr-B.BASE:addr-B.BASE+len(before)]==before
  after=b'\x4e\xf9'+B.BE(sy['boot_heap_'+name])+b'\x4e\x71'*((len(before)-6)//2)
  image[addr-B.BASE:addr-B.BASE+len(before)]=after;patches.append(dict(name=name,address=hex(addr),before=hx,after=after.hex()))
 boot=B.BASE+len(image)
 asm=(INPUT/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
 image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
 doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**c,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
 doc['boot_heap_watch']=dict(methods={k:hex(v) for k,v in sy.items()},patches=patches,marker='54423344',purpose='Detect premature Project free, lost allocation bit or overlapping native malloc result before the clear; no allocator repair.',stack_words=['marker','reason B0 lost Project bit/F0 free Project block/A0 overlapping allocation','Project pointer','native caller','event pointer','allocation request or free argument','D2 (allocated16-byte units at A0 only)','Project allocation bitmap byte','free-list order15 head','free-list order16 head','last free caller','last free pointer'])
 for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
 print(json.dumps(dict(main_sha256=doc['main_sha256'],heap_watch=doc['boot_heap_watch']),indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
