"""One guarded per-active-voice pitch hook; keeps frozen V7/drive/GUI inputs intact."""
from pathlib import Path
import hashlib,json,re,sys,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
SRC=ROOT/'firmware/ghidra/oneshot-proof/v7-source'
sys.path[:0]=[str(SRC/'src'),str(SRC/'scripts')]
import sharc_waverider_render as m1
import sharc_waverider_m3 as m3
from dnfw.image import bootstream as B,sharc_object as O
m1.SELAS=str(ROOT/'firmware/ghidra/oneshot-proof/v6-source/toolchain/selache-2b26d3b/target/release/selas')
BASE_SHA='fb4a5261a0396ed970fe267af06acd152037d084390175676d683cc064ed0429'
CODE_DM=0x30ac20;CODE_SW=CODE_DM//2
SAVE_DM=0x30dd90
HOOK=0x185cf0;RESUME=HOOK+3
HELPER_DM=0x30fd80;HELPER_SW=HELPER_DM//2
regs=[f'{bank}{i}' for bank in ('R','I','M') for i in range(16)]

def sha(b):return hashlib.sha256(b).hexdigest()
def source():
 s='''// Keyboard pitch v1. Runs after existing non-null/ACTIVE guards, once per block.
// Read native per-voice pitch after unpack; note/fine/glide already combined.
// The full native TUNE word supplies semitones = word/256 - 64.
// Match DT2 root note60, combined ±64 semitone bound, native powf helper.
// Save all data and address/modifier registers. Existing seed, phase, active,
// event/handoff, donor renderer, sample storage and storage protocol are unchanged.
.SECTION/PM seg_pmco;
.GLOBAL pitch_entry.;
pitch_entry.:
'''
 for i,r in enumerate(regs):s+=f'      DM({SAVE_DM+4*i:#x}) = {r};\n'
 s+='''      R0 = MR0F;
      DM(0x30de50) = R0;
      R0 = MR1F;
      DM(0x30de54) = R0;
      R0 = MR2F;
      DM(0x30de58) = R0;
      CALL 0x16f380;
      R0 = DM(0x30dc94);
      R0 = LSHIFT R0 BY 2;
      R1 = 0x254b14;
      R0 = R1 + R0;
      I4 = R0;
      R8 = DM(0, I4);
      // Reject NaN/Inf before floating operations; root note is neutral.
      R0 = LSHIFT R8 BY -23;
      R1 = 255;
      R0 = R0 AND R1;
      COMP(R0, R1);
      IF NE JUMP 0x0; // -> pitch_note_ok.
      R8 = 0x42700000;
.GLOBAL pitch_note_ok.;
pitch_note_ok.:
      R0 = DM(0x30dc9c);
      R1 = 0xfffffffc;
      R1 = R0 AND R1;
      I4 = R1;
      R12 = DM(0, I4);
      R1 = 2;
      R0 = R0 AND R1;
      R0 = LSHIFT R0 BY 3;
      R1 = 0;
      R0 = R1 - R0;
      R12 = LSHIFT R12 BY R0;
      R1 = 0xffff;
      R12 = R12 AND R1;
      R0 = -8;
      F12 = FLOAT R12 BY R0;
      R2 = 0x42800000;
      R1 = 0x42700000;
      F0 = F12 - F2;
      F1 = F8 - F1;
      F1 = F1 + F0;
      F2 = CLIP F1 BY F2;
      R0 = 0x3daaaaaa;
      F8 = F2 * F0;
      R4 = 0x40000000;
      CJUMP 0x1c0c76 (DB);
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x0; // return address - 1: pitch_pow_return. - 1
.GLOBAL pitch_pow_return.;
pitch_pow_return.:
      // Native fixed48k sample and96k donor domain: pow *2^30 is Q31 step.
      R1 = 30;
      F4 = SCALB F0 BY R1;
      CJUMP 0x187ec0 (DB);
      DM(I7, M7) = R2;
      DM(I7, M7) = 0x0; // return address - 1: pitch_int_return. - 1
.GLOBAL pitch_int_return.;
pitch_int_return.:
      R4 = DM(0x30dc98);
      R3 = 0x1b8;
      R3 = R4 + R3;
      I4 = R3;
      R3 = DM(0, I4);
      R3 = LSHIFT R3 BY -24;
      R3 = PASS R3;
      IF EQ JUMP 0x0; // -> pitch_forward.
      // Negate64-bit pair R1:R0 using native complement/carry arithmetic.
      R0 = NOT R0;
      R1 = NOT R1;
      R2 = 1;
      R0 = R0 + R2;
      IF EQ R1 = R1 + R2;
.GLOBAL pitch_forward.;
pitch_forward.:
      R2 = 0x1a8;
      R4 = R4 + R2;
      I4 = R4;
      DM(0, I4) = R0;
      DM(1, I4) = R1;
'''
 s+='''      R0 = DM(0x30de50);
      MR0F = R0;
      R0 = DM(0x30de54);
      MR1F = R0;
      R0 = DM(0x30de58);
      MR2F = R0;
'''
 for i,r in reversed(list(enumerate(regs))):s+=f'      {r} = DM({SAVE_DM+4*i:#x});\n'
 s+=f'      R12 = DM(0x30dc34);\n      JUMP {RESUME:#x};\n'
 return s

def assemble(s):
 path=HERE/'pitch.asm';path.write_text(s)
 be,offsets=m3._selas(path,HERE)
 syms=O.symbols((HERE/'pitch.doj').read_bytes())
 labels={k:CODE_SW+v for k,v in syms.items() if k.startswith('pitch_')}
 def br(m):return m[1]+hex(labels[m[3]])+m[2]
 s=re.sub(r'((?:JUMP|CALL)\s+)0x[0-9a-f]+(;\s*// -> (pitch_\w+\.))',br,s)
 def ret(m):return m[1]+hex(labels[m[3]]-1)+m[2]
 s=re.sub(r'(DM\(I7, M7\) = )0x[0-9a-f]+(;\s*// return address - 1: (pitch_\w+\.) - 1)',ret,s)
 path.write_text(s);be2,offsets2=m3._selas(path,HERE)
 assert offsets==offsets2
 return O.load_bytes(be2),offsets,labels

def main():
 base=(HERE/'baseline-section7.bin').read_bytes();assert sha(base)==BASE_SHA
 code,offsets,labels=assemble(source());assert CODE_DM+len(code)<=0x30b000,(len(code),hex(CODE_DM+len(code)))
 helper=(HERE/'float-to-int64.bin').read_bytes();assert len(helper)==212
 live_path=ROOT/'output/dn2-research/oneshot-live-controls-20261008/controls.bin'
 live=live_path.read_bytes();assert sha(live)=='27a92746523ed3450868e864b34244446bfebb45a7814a32e140a67a19c66734'
 level_path=ROOT/'output/dn2-research/oneshot-live-level-20261008/level.bin'
 level=level_path.read_bytes();assert sha(level)=='7d73a600baed4091a546e0260ce92696a48fd09f87dd7e4cb95a23b47cb27819'
 level_state=(level_path.parent/'state-and-save-zero.bin').read_bytes();assert level_state==bytes(104)
 placements=[('pitch shim',CODE_DM,code),('pitch scratch',SAVE_DM,bytes(4*len(regs)+12)),('native float-to-int64 helper',HELPER_DM,helper),('live bounds and play mode',0x2de700,live),('live sample level',0x2de980,level),('per-voice sample level state and saves',0x30de60,level_state)]
 for name,at,data in placements:
  assert not any(a<0x28000000+at+len(data) and 0x28000000+at<a+len(b) for a,b in B.load_regions(base)),name
 patch_be,_=m3._selas_line(f'JUMP {CODE_SW:#x};',HERE);patch=O.load_bytes(patch_be);assert len(patch)==6
 before=B.read_span(base,0x28000000+HOOK*2,6)
 expected,_=m3._selas_line('R12 = DM(0x30dc34);',HERE);assert before==O.load_bytes(expected)
 out=bytearray(base);B.write_span(out,0x28000000+HOOK*2,patch)
 level_before=B.read_span(base,0x28000000+0x185d0a*2,6)
 expected_level,_=m3._selas_line('R0 = DM(0x30dcd8);',HERE);assert level_before==O.load_bytes(expected_level)
 level_jump,_=m3._selas_line('JUMP 0x16f4c0;',HERE);level_patch=O.load_bytes(level_jump);assert len(level_patch)==6
 B.write_span(out,0x28000000+0x185d0a*2,level_patch)
 out=B.insert_before_final(bytes(out),b''.join(B.block(0x28000000+at,data) for _,at,data in placements));assert B.walk(out).complete
 (HERE/'section_7.bin').write_bytes(out);(HERE/'pitch.bin').write_bytes(code)
 receipt={'schema':'dn2-oneshot-keyboard-dsp-v1','baseline_sha256':sha(base),'section7_sha256':sha(out),'bytes':len(out),'pitch_sha256':sha(code),'pitch_bytes':len(code),'source_sha256':sha((HERE/'pitch.asm').read_bytes()),'builder_sha256':sha(Path(__file__).read_bytes()),'labels':{k:hex(v) for k,v in labels.items()},'instruction_offsets':offsets,'hook':{'sw':hex(HOOK),'before':before.hex(),'after':patch.hex(),'resume':hex(RESUME)},'placements':[{'name':name,'address':hex(at),'bytes':len(data),'sha256':sha(data)} for name,at,data in placements],'level_hook':{'sw':'0x185d0a','before':level_before.hex(),'after':level_patch.hex(),'resume':'0x185d0d'},'scratch_registers':{r:hex(SAVE_DM+4*i) for i,r in enumerate(regs)},'claims':['Two existing6-byte instructions replaced; active/pointer guards unchanged.','Pitch, STRT/LEN/LOOP bounds and PLAY mode recomputed each active block; phase/seed/envelopes unchanged.','Nativepow and relocatedpureintegerconversion, no interpolatedpitchtable.','Per-voice sample LEVEL squared gain with32-point block ramp before unchanged native AMP.'],'limits':['Hardware keyboard/glide/chords still require instrument test.','Combined note+TUNE clipped ±64 semitones exactly as nativeDT2.']}
 (HERE/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
if __name__=='__main__':main()
