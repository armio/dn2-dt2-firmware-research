#!/usr/bin/env python3
"""T1D2: trap the first Kit header overwrite or first corrupt boot checkpoint."""
from pathlib import Path
import argparse,json,re
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-boot-kit-diagnostic-r1-20261010'
SHA='3429127ee0ebdf30e086a672e96c64244a1aedf65c6bf77fefa03a839908b205'
SITES=[('kit_return',2,0x40041340,8),('project_return',3,0x4018a9aa,8),
 ('reset_entry',4,0x40040b4e,8),('base_reset_return',5,0x40040b94,8),
 ('settings_reset_return',6,0x40040baa,6),('dispatch',7,0x40191768,6),
 ('memcpy',0xc1,0x40134490,8),('memset',0xc2,0x401344d8,8)]
def build(out):
 raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
 doc=json.loads((INPUT/'build-receipt.json').read_text());c=doc['runtime_copy'];src,base=int(c['source'],16),int(c['destination'],16)
 payload=bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']]);entry=base+len(payload)
 out.mkdir(parents=True,exist_ok=False)
 source=(B.T.ROOT/'scripts/asm/dn2_boot_kit_watch.S').read_text()
 for name,tag,addr,size in SITES:
  body=raw[addr-B.BASE:addr-B.BASE+size]
  # Displaced conditional branch at reset checkpoint is PC relative: replay
  # the original BTST and branch by its actual native destination instead.
  if name=='settings_reset_return':
   assert body.hex()=='080200016720'
   replay=' btst #1,%d2\n beq.w boot_watch_no_kit\n jmp 0x40040bb0\nboot_watch_no_kit:\n jmp 0x40040bd0\n'
  elif name=='base_reset_return':
   assert body.hex()=='508f08020000670e'
   replay=' addq.l #8,%sp\n btst #0,%d2\n beq.w boot_watch_no_settings\n jmp 0x40040b9c\nboot_watch_no_settings:\n jmp 0x40040baa\n'
  else:replay=' .byte '+','.join(hex(v) for v in body)+f'\n jmp {addr+size:#x}\n'
  source+=f'\n.global boot_watch_{name}\nboot_watch_{name}:\n save_watch\n move.l #{tag},%d0\n bsr.w boot_watch_check\n restore_watch\n'+replay
 payload.extend(B.R.assemble(source,entry,out,'boot-kit-watch'))
 symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (boot_watch_\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'boot-kit-watch.elf']))}
 payload.extend(bytes(-len(payload)%4));assert base+len(payload)<=int(doc['runtime_limit'],16)
 image=bytearray(raw[:src-B.BASE])+payload;patches=[]
 for name,tag,addr,size in [('init',1,0x4003256c,6)]+SITES:
  before=image[addr-B.BASE:addr-B.BASE+size];after=b'\x4e\xf9'+B.BE(symbols['boot_watch_'+name])+b'\x4e\x71'*((size-6)//2)
  image[addr-B.BASE:addr-B.BASE+size]=after
  patches.append(dict(name=name,stage=tag,address=hex(addr),before=before.hex(),after=after.hex()))
 boot=B.BASE+len(image)
 asm=(INPUT/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
 image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
 doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**c,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
 doc['boot_kit_watch']=dict(methods={k:hex(v) for k,v in symbols.items()},patches=patches,marker='54423244',purpose='First Kit startup corruption/overlapping memcpy or memset diagnostic; no repair.',stack_words=['marker','stage or C1 memcpy/C2 memset','watched Kit','current vtable','last good stage','destination / checkpoint stack+4','source or fill / checkpoint stack+8','length / checkpoint stack+12','caller / checkpoint stack top','Project singleton','Kit+4','Kit+44'])
 for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
 print(json.dumps(dict(main_sha256=doc['main_sha256'],watch=doc['boot_kit_watch']),indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
