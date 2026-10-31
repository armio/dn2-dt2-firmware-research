#!/usr/bin/env python3
"""T1D5: size DN2's native DSP decompression buffer for the expanded DSP image."""
from pathlib import Path
import argparse,json,hashlib,shutil
ROOT=Path(__file__).resolve().parents[1]
BASE=0x40000400
SOURCE=ROOT/'output/dn2-research/dn2-boot-freelist-watch-20261010'
SHA='e94a488627aafcbff41fc663c7db4a3971a7b453df1656c8ee02590eac861422'
def build(out):
 raw=bytearray((SOURCE/'main-os.bin').read_bytes())
 assert hashlib.sha256(raw).hexdigest()==SHA
 dsp=(ROOT/'output/dn2-research/dt2-sample-cursor-dsp-20261009/section_7.bin').read_bytes()
 capacity=0x200000
 assert len(dsp)+1<=capacity
 patches=[]
 for addr,insn in [(0x400cf576,'2f3c'),(0x400cf5e4,'0c82')]:
  off=addr-BASE;before=bytes.fromhex(insn+'00100000');after=bytes.fromhex(insn)+capacity.to_bytes(4,'big')
  assert raw[off:off+6]==before
  raw[off:off+6]=after
  patches.append({'address':hex(addr),'before':before.hex(),'after':after.hex()})
 doc=json.loads((SOURCE/'build-receipt.json').read_text())
 doc.update(main_sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),flash_ready=False)
 doc['dsp_boot_capacity_fix']={'output_capacity':capacity,'unpacked_dsp_bytes':len(dsp),'prefix_bytes':1,'compressed_input_capacity':0x100000,'patches':patches,'cause':'Expanded DSP section exceeds native1MiB decompression output allocation; overflow damages native heap before Project initialization.','diagnostics_retained':True}
 out.mkdir(parents=True,exist_ok=False)
 (out/'main-os.bin').write_bytes(raw)
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 for name in ('runtime.bin','bootstrap.S','fn_new_map.txt','ram_map.txt'):shutil.copy2(SOURCE/name,out/name)
 print(json.dumps({'main_sha256':doc['main_sha256'],'fix':doc['dsp_boot_capacity_fix']},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
