#!/usr/bin/env python3
"""Normalize STRETCH grain pitch to source frames per 48k output sample."""
from pathlib import Path
import argparse,json,re
import build_dt2_dsp_stereo_rate_fix as Q
import build_dt2_sampler_frame_bridge as F
C,B,A,O=Q.C,Q.B,Q.A,Q.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-stereo-rate-fix-20261010/section_7.bin'
SHA='2813ae316435bbf92d6b119047d8a470a4e148cd2fb07dfdb6afb50a7006f726'
CODE,SAVE=0xbf6400,0x200eca00

def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 site,resume=0xbc83ad,0xbc83b1
 displaced=m.read_sw(site,8);donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
 assert displaced==donor.read_sw(0x1c4dde,8)
 source=f'''.SECTION/PM seg_pmco;
.GLOBAL stretch_source_rate.;
stretch_source_rate.:
      F4 = F2 * F0; // Replaced with exact native encoding below.
      // Native F4 is notePitch * 0.25 * compensated(sourceHz/96000).
      // Preserve shift status: the later IF NOT SV still needs LEFTZ flags.
      DM({SAVE:#x}) = ASTATX;
      DM({SAVE+4:#x}) = ASTATY;
      DM({SAVE+8:#x}) = MODE1;
      BIT CLR MODE1 0x200000;
      NOP;
      NOP;
      NOP;
      DM({SAVE+12:#x}) = R0;
      DM({SAVE+16:#x}) = R1;
      R0 = DM(97, I5);
      R1 = 48000;
      COMP(R0, R1);
      IF EQ JUMP 0x0; // -> restore.
      R1 = 0x41000000;
      F0 = F4 * F1;
      DM(115, I5) = R0;
.GLOBAL restore.;
restore.:
      R1 = DM({SAVE+16:#x});
      R0 = DM({SAVE+12:#x});
      MODE1 = DM({SAVE+8:#x});
      NOP;
      NOP;
      NOP;
      ASTATY = DM({SAVE+4:#x});
      ASTATX = DM({SAVE:#x});
.GLOBAL replay_flags.;
replay_flags.:
      F4 = F2 * F0; // Placeholder replaced with exact native flags-byte store.
      JUMP {resume:#x};
'''
 out.mkdir(parents=True,exist_ok=False);asm=out/'stretch-rate.asm';asm.write_text(source)
 be,offsets=A._selas(asm,out)
 labels={n:CODE+v for n,v in O.symbols((out/'stretch-rate.doj').read_bytes()).items() if n in ('stretch_source_rate.','restore.','replay_flags.')}
 source=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],source)
 asm.write_text(source);be,again=A._selas(asm,out);assert again==offsets
 # Selas aliases ASTATX/Y to 0x73/74; the actual chip uses 0x76/77.
 be=bytearray(be);status=[]
 for off in offsets:
  if be[off] in (0x10,0x11) and be[off+1] in (0x73,0x74):
   at=int.from_bytes(be[off+2:off+6],'big');assert at in (SAVE,SAVE+4)
   old=be[off+1];be[off+1]+=3;status.append(dict(offset=off,old=old,actual=be[off+1]))
 assert len(status)==4
 # MODE1 has the same assembler-generation alias mismatch (0x70 vs 0x72).
 modes=[]
 for off in offsets:
  if be[off] in (0x10,0x11) and be[off+1]==0x70:
   assert int.from_bytes(be[off+2:off+6],'big')==SAVE+8
   be[off+1]=0x72;modes.append(off)
 assert len(modes)==2
 code=bytearray(O.load_bytes(bytes(be)))
 assert offsets[1]==4
 code[:4]=displaced[:4]
 replay=2*(labels['replay_flags.']-CODE);assert offsets[offsets.index(replay)+1]-replay==4
 code[replay:replay+4]=displaced[4:]
 physical=C.S.code_address(CODE,window='l2');assert physical+len(code)<=SAVE
 regions=C.B.load_regions(raw)
 for address,data in ((physical,code),(SAVE,bytes(20))):
  assert not any(address<a+len(v) and a<address+len(data) for a,v in regions)
 patch=C.S.to_bytes(0x063e00000000|CODE)+b'\x01\x00';image=bytearray(raw)
 C.B.write_span(image,C.S.code_address(site,window='l2'),patch)
 result=C.B.insert_before_final(bytes(image),C.B.block(physical,bytes(code))+C.B.block(SAVE,bytes(20)))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['dsp_stretch_rate_fix']=dict(base=str(BASE),base_sha256=SHA,code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),scratch=hex(SAVE),scratch_bytes=20,instruction_offsets=offsets,labels={n:hex(v) for n,v in labels.items()},status_alias_corrections=status,mode_alias_corrections=modes,
  hook=dict(site=hex(site),resume=hex(resume),before=displaced.hex(),after=patch.hex(),donor_site='0x1c4dde'),
  reason='STRETCH grain correction subtracted notePitch*2048 despite the readhead advancing notePitch*sourceHz/48000*2048, causing cumulative drift for non48k sources.',
  correction='record+0x1CC = F4*8 = notePitch*sourceHz/48000; preserve native pitch Q31 step and speed+1C8; retain original48k value.',
  mode='SSE cleared only in added scalar update, with three instruction slots after each MODE1 write; original MODE1 and ASTATX/Y restored before replay.',
  limits=['Native48k input arithmetic retained. Device timing confirmation pending.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hook=doc['dsp_stretch_rate_fix']['hook'])))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
