#!/usr/bin/env python3
"""Read native sample Hz in ONESHOT pitch; retain the proven 48 kHz path."""
from pathlib import Path
import argparse,json,re
import build_dt2_dsp_l1_code_fix as P
import build_dt2_sampler_frame_bridge as F
C,B,A,O=P.C,P.B,F.A,F.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-l1-code-fix-20261010/section_7.bin'
SHA='d4e9efee48b0e95a725f9e471d5ee144ef96c581472bac9c43c609b56b162e99'
CODE=0xbf6200

def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text());rows=doc['dsp_l1_code_fix']['placements']
 mv=lambda a:P.mapped(a,rows)
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 site,resume,finished,convert=[mv(a) for a in (0x185709,0x18570d,0x185714,0x187ec0)]
 displaced=m.read_sw(site,8);assert displaced.hex()=='810f1e008b0101d4'
 source=f'''.SECTION/PM seg_pmco;
.GLOBAL oneshot_source_rate.;
oneshot_source_rate.:
      // The existing pitch scope saves the data/DAG registers used here.
      I4 = DM(0x30dc98);
      R2 = DM(97, I4);
      R1 = 48000;
      COMP(R2, R1);
      IF EQ JUMP 0x0; // -> native_48000.
      // DT2 1C4B33..1C4B65: compensated Hz/96000 and pow*0.25.
      F2 = FLOAT R2;
      R11 = 0x4f800000;
      IF LT F2 = F2 + F11;
      R14 = 0x372ec33e;
      F12 = F2 * F14;
      R8 = 0x3e800000;
      R1 = 0x47bb8000;
      F0 = F0 * F8;
      F8 = MANT F12;
      F1 = F12 * F1;
      R8 = 30;
      IF NOT AV F1 = F1 - F2;
      F2 = F1 * F14;
      IF NOT AV F12 = F12 - F2;
      F4 = F0 * F12;
      F4 = SCALB F4 BY R8;
      // Native DT2 conversion truncates before its exact 64-bit shift by3.
      CJUMP {convert:#x} (DB);
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x0; // return: rate_converted.
.GLOBAL rate_converted.;
rate_converted.:
      R2 = LSHIFT R1 BY 3;
      R1 = LSHIFT R0 BY 3;
      R2 = R2 OR LSHIFT R0 BY -29;
      R0 = R1;
      R1 = R2;
      JUMP {finished:#x};
.GLOBAL native_48000.;
native_48000.:
      R1 = 30;
      F4 = SCALB F0 BY R1;
      JUMP {resume:#x};
'''
 out.mkdir(parents=True,exist_ok=False);asm=out/'source-rate.asm';asm.write_text(source)
 be,offsets=A._selas(asm,out);labels={n:CODE+v for n,v in O.symbols((out/'source-rate.doj').read_bytes()).items() if n in ('oneshot_source_rate.','rate_converted.','native_48000.')}
 source=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],source)
 source=re.sub(r'(DM\(I7, M7\) = )0x0(; // return: (\w+\.))',lambda x:x[1]+hex(labels[x[3]]-1)+x[2],source)
 asm.write_text(source);be,again=A._selas(asm,out);assert again==offsets
 code=bytearray(O.load_bytes(be))
 # Selas accepts OR LSHIFT syntax but omits its OR opcode bit. Preserve the
 # complete three-instruction native64-bit shift sequence byte-for-byte.
 shift_at=2*(labels['rate_converted.']-CODE)
 expected=bytes.fromhex('3e02000021033e02000010033e02007820e3')
 assert code[shift_at:shift_at+18]==expected
 donor=k.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes())
 code[shift_at:shift_at+18]=donor.read_sw(0x1c4b7e,18)
 code=bytes(code)
 physical=C.S.code_address(CODE,window='l2');assert physical==0x200ec400 and physical+len(code)<0x200f0000
 assert not any(physical<a+len(v) and a<physical+len(code) for a,v in C.B.load_regions(raw))
 image=bytearray(raw);patch=C.S.to_bytes(0x063e00000000|CODE)+b'\x01\x00'
 C.B.write_span(image,C.S.code_address(site,window='l2'),patch)
 result=C.B.insert_before_final(bytes(image),C.B.block(physical,code))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 header=C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)
 result=result[:first.offset]+header+result[first.end:];assert C.B.walk(result).complete
 doc.update(baseline_sha256=SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['dsp_stereo_rate_fix']=dict(base=str(BASE),base_sha256=SHA,reason='ONESHOT fixed48k pitch ignored the loaded native sample rate; stereo channel rendering itself was already present.',
  source_rate_field='record+0x184, unsigned Hz',code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),instruction_offsets=offsets,
  labels={n:hex(v) for n,v in labels.items()},hook=dict(site=hex(site),resume=hex(resume),converted_return=hex(finished),before=displaced.hex(),after=patch.hex()),
  native_reference='DT2 1C4B33..1C4B84: compensated sampleHz/96000, pow*0.25, SCALB30, truncate64, shift64 left3.',
  native_shift_copy=dict(donor='0x1c4b7e',runtime=hex(labels['rate_converted.']),bytes=18),
  preserves_48000_arithmetic=True,other_machine_code_unchanged=True,stereo_pcm_layout_unchanged=True,
  limits=['Hardware playback at non48k has not yet been checked.','Existing ONESHOT48k result is preserved rather than changing its fine-pitch rounding.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hook=doc['dsp_stereo_rate_fix']['hook']),indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
