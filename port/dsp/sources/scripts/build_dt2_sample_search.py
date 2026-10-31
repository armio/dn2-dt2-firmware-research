#!/usr/bin/env python3
"""Link original DT2 zero-crossing/transient searches and slice suggestions."""
from pathlib import Path
import argparse,json,struct
import build_dt2_waveform_analysis as A
C,R,W=A.C,A.R,A.W
BASE=C.ROOT/'output/dn2-research/dt2-waveform-analysis-20261009/section_7.bin'
SHA='3ad1809d24e3d80ffb60e94c1e988798a77e284797e2b4308f7e07117ec6714b'
SPANS=(('searches',0x1c414a,0x1c42b8,0x18e800),
       ('handlers',0x1c3ec7,0x1c3f57,0x18ea00),
       ('transients',0x1c5a86,0x1c6010,0x18ec00),
       ('filter-init',0x1cc35d,0x1cc3dc,0x18f200),
       ('atan',0x1c07d2,0x1c086e,0x18f300))
NATIVE=(('log',0x1c0c46,0x1c0cbe,0x1c0b66),
        ('cos',0x1c10ce,0x1c1132,0x1c1018),
        ('sin',0x1c1132,0x1c119a,0x1c107c),
        ('exp',0x1c11fb,0x1c1252,0x1c11a5),
        ('sqrt',0x1c1284,0x1c12b4,0x1c122e),
        ('tan',0x1c12b4,0x1c1336,0x1c125e))
DATA=(('phase-coefficients',0x25f150,0x25f170,0x31f000),
      ('atan-coefficients',0x240910,0x240944,0x31f020),
      ('transient-state',0x25c824,0x25c914,0x31f100))
TABLE=0x31f300
BINDINGS={0x1c0d68:0x1c0c76,0x1c0c36:0x170d00,0x1c06ba:0x185480,
          0x241280:0x241250,0x256cc0:W.SCRATCH-4}

def mapped(v,*,required=False):
 for _,lo,hi,to in (*SPANS,*NATIVE,*DATA):
  if lo<=v<hi:return to+v-lo
 if v in BINDINGS:return BINDINGS[v]
 return A.mapped(v,required=required)

def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==SHA
 k=C.M.Digikit(C.SRC/'toolchains/digikit')
 d=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());n=k.ldr.LoadedMemory.from_stream(raw)
 twins=[]
 for name,lo,hi,to in NATIVE:
  body,bindings,_=R.relocate(k,d,lo,hi,to,mapper=mapped)
  assert body==n.read_sw(to,len(body)),name
  twins.append(dict(name=name,donor=hex(lo),end=hex(hi),native=hex(to),bytes=len(body),bindings=bindings))
 exp_constants=d.read(C.S.data_address(0x241280),60)
 assert exp_constants is not None and len(exp_constants)==60
 assert exp_constants==n.read(C.S.data_address(0x241250),60)
 blocks=[];records=[];listings={}
 for name,lo,hi,to in SPANS:
  body,bindings,listing=R.relocate(k,d,lo,hi,to,mapper=mapped)
  blocks.append((C.S.code_address(to),body));listings[name]=listing
  records.append(dict(name=name,donor=hex(lo),end=hex(hi),target=hex(to),bytes=len(body),bindings=bindings))
 for name,lo,hi,to in DATA:
  body=d.read(C.S.data_address(lo),hi-lo);assert body is not None and len(body)==hi-lo,name
  blocks.append((C.S.data_address(to),body))
 wait=W.mapped(0x1c3c1d)
 table=[mapped(v) for v in (0x1c3c3e,0x1c3c4f,0x1c3c72)]+[wait]*3+[mapped(v) for v in (0x1c3d75,0x1c3db0,0x1c3e02,0x1c3ec7,0x1c3f16)]
 blocks.append((C.S.data_address(TABLE),struct.pack('<11I',*table)))
 regions=C.B.load_regions(raw)
 for addr,body in blocks:
  assert not any(a<addr+len(body) and addr<a+len(b) for a,b in regions),hex(addr)
  regions.append((addr,body))
 image=bytearray(raw);patches=[]
 for pc,old,new in [(W.mapped(0x1c3c0f),9,11),(W.mapped(0x1c3c11),A.TABLE,TABLE)]:
  ins=k.st.decode_at(n,None,pc)
  if pc==W.mapped(0x1c3c0f):
   assert n.read_sw(pc,4)==struct.pack('<HH',0x0f8f,old);after=struct.pack('<HH',0x0f8f,new)
  else:
   assert C.S.get_field(ins.raw,'data32')==old;after=C.S.to_bytes(C.S.retarget(ins.raw,'data32',pc,new))
  C.B.write_span(image,C.S.code_address(pc),after);patches.append(dict(pc=hex(pc),before=hex(old),after=hex(new)))
 image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),spans=records,native_twins=twins,
   data=[dict(name=n,donor=hex(a),end=hex(z),target=hex(t)) for n,a,z,t in DATA],
   table=hex(TABLE),patches=patches,enabled_commands=[0,1,2,6,7,8,9,10],flash_ready=False,
   remaining=['Original recording RPCs3..5 and their data path','Dynamic RAM reservation and remaining UI/audio integration','Full MAIN/DSP integration and hardware validation'])
 out.mkdir(parents=True,exist_ok=False);(out/'section_7.bin').write_bytes(image)
 for name,listing in listings.items():(out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps({key:doc[key] for key in ('section7_sha256','enabled_commands','flash_ready')},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
