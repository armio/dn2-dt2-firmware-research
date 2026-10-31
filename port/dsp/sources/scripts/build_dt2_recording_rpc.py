#!/usr/bin/env python3
"""Connect DT2 recording extrema, PCM readback and normalization RPCs3/4/5.

The recording input producer is not connected by this component. Its original
float buffers are retained at their donor addresses pending final RAM ownership.
"""
from pathlib import Path
import argparse,json,struct
import build_dt2_sample_search as S
C,R,W=S.C,S.R,S.W
BASE=C.ROOT/'output/dn2-research/dt2-sample-search-20261009/section_7.bin'
SHA='cb1e9a9a160ce6305076ea068543d814d02877b22ddd9b34d3f89b16693572b5'
SPANS=(('normalize',0x1c35cd,0x1c367e,0x190000),
       ('recording-readers',0x1c39cf,0x1c3bf0,0x190100),
       ('handlers',0x1c3c95,0x1c3d75,0x190400))
STATE,SCRATCH,TABLE=0x32c000,0x32c100,0x32ca00
OLD_STATE,STATE_SIZE=0x256a44,0x54
RECORD=0x82a001c8
CAPACITY=0x305700
RECORD_BYTES=CAPACITY*4*2

def mapped(v,*,required=False):
 for _,lo,hi,to in SPANS:
  if lo<=v<hi:return to+v-lo
 if OLD_STATE<=v<OLD_STATE+STATE_SIZE:return STATE+v-OLD_STATE
 if 0x256dc8<=v<0x2575c8:return SCRATCH+v-0x256dc8
 return S.mapped(v,required=required)

def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==SHA
 k=C.M.Digikit(C.SRC/'toolchains/digikit')
 d=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());n=k.ldr.LoadedMemory.from_stream(raw)
 blocks=[];records=[];listings={}
 for name,lo,hi,to in SPANS:
  body,bindings,listing=R.relocate(k,d,lo,hi,to,mapper=mapped)
  blocks.append((C.S.code_address(to),body));listings[name]=listing
  records.append(dict(name=name,donor=hex(lo),end=hex(hi),target=hex(to),bytes=len(body),bindings=bindings))
 state=d.read(C.S.data_address(OLD_STATE),STATE_SIZE);assert state is not None and len(state)==STATE_SIZE
 table=[mapped(a) for a in (0x1c3c3e,0x1c3c4f,0x1c3c72,0x1c3c95,0x1c3d0a,0x1c3d54,0x1c3d75,0x1c3db0,0x1c3e02,0x1c3ec7,0x1c3f16)]
 blocks.extend([(C.S.data_address(STATE),state),(C.S.data_address(SCRATCH),bytes(2048)),(C.S.data_address(TABLE),struct.pack('<11I',*table))])
 regions=C.B.load_regions(raw)
 for addr,body in blocks:
  assert not any(a<addr+len(body) and addr<a+len(b) for a,b in regions),hex(addr)
  regions.append((addr,body))
 assert RECORD+RECORD_BYTES==R.POOL
 assert not any(a<RECORD+RECORD_BYTES and RECORD<a+len(b) for a,b in regions)
 image=bytearray(raw);pc=W.mapped(0x1c3c11);ins=k.st.decode_at(n,None,pc)
 assert C.S.get_field(ins.raw,'data32')==S.TABLE
 C.B.write_span(image,C.S.code_address(pc),C.S.to_bytes(C.S.retarget(ins.raw,'data32',pc,TABLE)))
 image=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 doc=dict(baseline_sha256=SHA,section7_sha256=C.SHA(image),spans=records,
  enabled_commands=list(range(11)),state=hex(STATE),scratch=hex(SCRATCH),table=hex(TABLE),
  recording_buffer=dict(address=hex(RECORD),frames_per_channel=CAPACITY,bytes=RECORD_BYTES,end=hex(R.POOL),placement='Original DT2 RAM, provisional until native dynamic reservation is established'),
  flash_ready=False,recording_input_connected=False,
  remaining=['Connect native recording input/lifecycle and main-side recording controls if required by UI',
   'Reserve original analysis/recording/PCM memory against native dynamic allocations',
   'Finish MAIN/DSP/FS integration and hardware validation'])
 out.mkdir(parents=True,exist_ok=False);(out/'section_7.bin').write_bytes(image)
 for name,listing in listings.items():(out/(name+'.asm')).write_text('\n'.join(listing)+'\n')
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps({key:doc[key] for key in ('section7_sha256','enabled_commands','recording_buffer','flash_ready')},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
