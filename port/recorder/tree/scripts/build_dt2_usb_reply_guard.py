#!/usr/bin/env python3
"""Keep legacy sampler ACK publication outside packed USB audio under SIMD."""
from pathlib import Path
import argparse, json
import build_dt2_recording_input as P
import build_dt2_dsp_render_diagnostic as D
C=P.C
BASE=C.ROOT/'output/dn2-research/dt2-recording-input-t1e3-v10-20261015/section_7.bin'
SHA='3f31d9db776ea6fcf3ee74510fabf2cccdaf3a8b4b68f7e0a5651d80d6f3a8df'
CODE,SAVE=0xbfa000,0x200f4300
SITES=((0xbf5988,10),(0xbf59b2,0),(0xbf59dd,0))
PAGES=(0x2c49d0,0x2c59d0)

def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
 m=P.L.decode_view(k,raw);image=bytearray(raw);body=bytearray();hooks=[]
 for index,(site,reg) in enumerate(SITES):
  before=b''.join(C.S.to_bytes(0x110000000000|(reg<<32)|(p+24)) for p in PAGES)
  assert m.read_sw(site,12)==before,(hex(site),m.read_sw(site,12).hex())
  entry=CODE+len(body)//2;scratch=SAVE+4*index
  words=[0x111000000000|scratch,D.ureg_copy(reg),
         *(0x111000000000|(p+24) for p in PAGES),
         0x101000000000|scratch,0x063e00000000|(site+6)]
  body.extend(b''.join(C.S.to_bytes(w) for w in words))
  C.B.write_span(image,C.S.code_address(site,window='l2'),C.S.to_bytes(0x063e00000000|entry))
  hooks.append(dict(site=hex(site),entry=hex(entry),resume=hex(site+6),register='R'+str(reg),scratch=hex(scratch),before=before.hex(),bytes=len(words)*6))
 blocks=[(C.S.code_address(CODE,window='l2'),bytes(body)),(SAVE,bytes(12))]
 for a,b in blocks:
  assert not any(a<c+len(d) and c<a+len(b) for c,d in C.B.load_regions(raw)),hex(a)
 result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['usb_reply_guard']=dict(base=str(BASE),base_sha256=SHA,code=hex(CODE),code_bytes=len(body),hooks=hooks,contract='Publish the original ACK word at reply+24 through scalar universal I0. Rn/Sn, I0, MODE1 and status unchanged; no implicit S-lane write at reply+28, which owns TRACK7 first packed sample. All native42 export arithmetic/source selection unchanged.',limits=['Hardware attribution of periodic TRACK7 spikes remains pending; this closes a demonstrated SIMD reply/audio overlap.', 'TRACK13 long note cutoffs are a separate investigation.'])
 out.mkdir(parents=True,exist_ok=False);(out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),hooks=hooks),indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
