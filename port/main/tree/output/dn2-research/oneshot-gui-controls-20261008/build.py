#!/usr/bin/env python3
"""Build an offline UI-only component. Does not compose or flash firmware."""
from pathlib import Path
import argparse, hashlib,json,struct,subprocess
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
J=ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v1'
T=ROOT/'output/dn2-research/oneshot-gui-navigation-20261008/control-twins.json'
ap=argparse.ArgumentParser();ap.add_argument('--base',type=lambda s:int(s,0),default=0x47a53a00);args=ap.parse_args()
BASE=0x40000400;LOAD=args.base
D=(J/'inputs/dt2-main.bin').read_bytes();N=(J/'runtime-candidate/main-os.bin').read_bytes()
sha=lambda x:hashlib.sha256(x).hexdigest()
assert sha(D)=='57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'
assert sha(N)=='a44c4584e82e0e5bedcdc5a46a479ecd70c74c6b21340d58e73a5aa44634c77a'
read=lambda d,a,n:d[a-BASE:a-BASE+n]
twins=[]
for row in json.loads(T.read_text()):
 if len(row['dn2_twins'])!=1:continue
 a=int(row['dt2'],16);b=int(row['dn2_twins'][0],16);n=row['size'];raw=bytearray(read(D,a,n));native=read(N,b,n)
 for r in row['relocations']:
  off=r['offset'];assert struct.unpack_from('>I',raw,off)[0]==int(r['donor'],16)
  struct.pack_into('>I',raw,off,int(r['dn2'],16))
 assert raw==native
 twins.append({'donor':hex(a),'recipient':hex(b),'bytes':n,'native_sha256':sha(native)})
for a,b,n in [(0x40112cb2,0x40114626,412),(0x40112e4e,0x401147c2,128),(0x40112ece,0x40114842,90),
              (0x402c269c,0x402ad1a4,68),(0x402c2658,0x402ad160,68)]:
 assert read(D,a,n)==read(N,b,n)
 twins.append({'donor':hex(a),'recipient':hex(b),'bytes':n,'exact':True})
SAMPLE=read(D,0x400c7c32,288);LOOP=read(D,0x400c674c,120)
(P/'sample.bin').write_bytes(SAMPLE);(P/'loop.bin').write_bytes(LOOP)
BIN=J/'toolchain/build'
def run(argv):
 r=subprocess.run([str(x) for x in argv],cwd=P,capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
 return r.stdout
def assemble():
 run([BIN/'gas/as-new','-mcpu=5475',P/'controls.S','-o',P/'controls.o'])
 run([BIN/'ld/ld-new',f'-Ttext={LOAD:#x}','-e','0','--no-warn-rwx-segments',P/'controls.o','-o',P/'controls.elf'])
 run([BIN/'binutils/objcopy','-O','binary','-j','.text',P/'controls.elf',P/'controls.bin'])
 return {r[2]:int(r[0],16) for line in run([BIN/'binutils/nm-new','--defined-only',P/'controls.elf']).splitlines() if len(r:=line.split())==3}
symbols=assemble()
M={0x40113cf4:0x40115668,0x40112cb2:0x40114626,0x40112ece:0x40114842,0x402a96a0:0x402941d0,
   0x4023a62d:0x40210858,0x4023deb8:0x402170ba,0x4025da35:0x4021222c,0x402299b7:0x40212b42,0x4024072f:0x402170bc,
   0x44f345cc:0x44644dfc,0x40113e88:0x401157fc,0x4293b23c:symbols['os_controls_loop_delegate']+8,
   0x4293b234:symbols['os_controls_loop_delegate'],0x4293b240:symbols['os_controls_loop_delegate']+12,
   0x401e4b82:symbols['os_controls_unreachable']}
for a,b in [(0x4023a62d,0x40210858),(0x4023deb8,0x402170ba),(0x4025da35,0x4021222c),(0x402299b7,0x40212b42),(0x4024072f,0x402170bc)]:
 def string(d,va):start=va-BASE;return d[start:d.index(b'\0',start)+1]
 assert string(D,a)==string(N,b)
changes=[]
for name,raw in [('sample',SAMPLE),('loop',LOOP)]:
 code=bytearray(raw)
 for old,new in M.items():
  token=struct.pack('>I',old);pos=0
  while (pos:=raw.find(token,pos))>=0:
   struct.pack_into('>I',code,pos,new);changes.append({'function':name,'offset':pos,'old':hex(old),'new':hex(new)});pos+=4
 if name=='sample':
  assert code[12:16]==bytes.fromhex('222f0024')
  code[12:16]=bytes.fromhex('72014e71')
  changes.append({'function':'sample','offset':12,'old_bytes':'222f0024','new_bytes':'72014e71','why':'display actual single resolved slot0 as native A1, for every raw selection'})
 (P/f'{name}.bin').write_bytes(code)
assert assemble()==symbols
code=(P/'controls.bin').read_bytes();assert len(code)<1024
(P/'controls.asm').write_text(run([BIN/'binutils/objdump','-d','-m','m68k:cfv4e',P/'controls.elf']))
rows=[(1,'TUNE',0x20,0x400bd30a),(2,'PLAY',0x20,0x400bc50c),(4,'SAMP',0x24,symbols['os_controls_sample']),
      (5,'STRT',0x40,0x400bbfee),(11,'LEN',0x40,0x400bbfee),(12,'LOOP',0x40,symbols['os_controls_loop']),(13,'LEV',0x20,0x400c08fc)]
result={'scope':'uncomposed offline native UI callbacks and guarded RAM style initializer','load':hex(LOAD),'end':hex(LOAD+len(code)),
 'bytes':len(code),'sha256':sha(code),'main_sha256':sha(N),'donor_sha256':sha(D),'native_twins':twins,'relocations':changes,
 'symbols':{k:hex(v) for k,v in symbols.items() if k.startswith('os_controls_')},
 'gui_table':'0x4243325c','gui_stride':68,'init_abi':'int os_controls_init(void); returns 0 not ready, 1 already ready, 3 newly initialized; no workspace',
 'drawer_abi':'void drawer(void *unused_closure, int value, Canvas *canvas, int x, int y, int compact)',
 'sample_formatter_patch':{'address':'0x401f80b8','old':'0x400e31d0','new':hex(symbols['os_controls_sample_format']),'bytes':4,'why':'ONESHOT ID4 display only: current one-slot bank is A1'},
 'rows':[{'id':i,'name':name,'gui_address':hex(0x4243325c+68*i),'old_flags':0,'new_flags':flags,'old_drawer':'0x400c0822','new_drawer':hex(cb),'retained_manager':'0x400bdc1a'} for i,name,flags,cb in rows],
 'preservation':'Only GUI table +0 and +32 change for seven displayed ONESHOT IDs. Separate ID4 ROM formatter pointer changes only displayed text; all parameter ranges/slots/input metadata and remaining GUI fields remain intact. DSP and storage unchanged.'}
assert read(N,0x401f80b8,4)==bytes.fromhex('400e31d0')
(P/'build.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
