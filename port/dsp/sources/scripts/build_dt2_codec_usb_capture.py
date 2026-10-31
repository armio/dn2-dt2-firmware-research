#!/usr/bin/env python3
"""Diagnostic: export preceding completed codec PCM through USB MAIN only."""
from pathlib import Path
import argparse,json,re
import build_dt2_dsp_output_deadline as P
T,C,B,A,O=P.T,P.C,P.B,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-output-deadline-20261012/section_7.bin'
BASE_SHA='5a19c1a1c316bc2a3c451bf5962181288d80ed6e818753a8566d58dffeab9816'
CODE,STATE=0xbf1280,0x200e3800
SNAPSHOT=STATE
SAVE={n:STATE+0x100+4*i for i,n in enumerate((*P.SAVE_NAMES,'i4','l4'))}
LAST=STATE+0x124
USB_SAVE=STATE+0x128
STATE_BYTES=0x12c
HOOKS=((0xbf0b84,0x100100268a38,'snapshot',0x1c9e57),
       (0x1c265b,0x1596ffffff82,'usb_main',0x1c265e))


def source():
 s='.SECTION/PM seg_pmco;\n'+T.label('snapshot_entry.')
 s+=f'      DM({SAVE["i0"]:#x}) = I0;\n'+P.mode_save(SAVE,'snapshot')
 s+=f'''      DM({SAVE['i4']:#x}) = I4;
      DM({SAVE['l4']:#x}) = L4;
      R0 = DM({P.FIELDS['valid_completions']:#x});
      R1 = DM({LAST:#x});
      COMP(R0, R1);
'''+T.jump('snapshot_restore.','IF EQ')
 s+='      L4 = 0;\n      R0 = DM(0x268a38);\n      R0 = LSHIFT R0 BY 8;\n      R1 = 0x2c0478;\n      R0 = R1 + R0;\n      I4 = R0;\n      R2 = -31;\n'
 # No hardware loop or index modification: the native completed loops have
 # ended, and all64 read addresses stay within the selected codec page.
 for frame in range(32):
  for lane in range(2):
   s+=f'      R0 = DM({2*frame+lane}, I4);\n      F0 = FLOAT R0 BY R2;\n      DM({SNAPSHOT+4*(32*lane+frame):#x}) = R0;\n'
 s+=f'      R0 = DM({P.FIELDS["valid_completions"]:#x});\n      DM({LAST:#x}) = R0;\n'
 s+=T.label('snapshot_restore.')+f'      L4 = DM({SAVE["l4"]:#x});\n      I4 = DM({SAVE["i4"]:#x});\n'+P.P.restore(SAVE)
 s+=T.label('snapshot_replay.')+'      I0 = 0x12345678;\n      JUMP 0x1c9e57;\n'
 # Replace only the two MAIN triplets in the native local export table.
 # Native right-source stores at265E/2661 consume the deliberately replacedR8.
 s+=T.label('usb_main_entry.')+f'''      DM({USB_SAVE:#x}) = I0;
      I0 = {SNAPSHOT:#x};
      DM(-128, I6) = I0;
      DM(-127, I6) = I0;
      R8 = {SNAPSHOT+128:#x};
      I0 = 0x3f800000;
      DM(-126, I6) = I0;
      DM(-123, I6) = I0;
      I0 = DM({USB_SAVE:#x});
'''+T.label('usb_main_replay.')+'      I0 = 0x12345678;\n      JUMP 0x1c265e;\n'
 return s


def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 assert int(doc['output_deadline']['labels']['done_replay.'],16)==HOOKS[0][0]
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 for pc,before,_,_ in HOOKS:
  ins=k.st.decode_at(m,None,pc);assert ins.raw==before and ins.length_bytes==6
 out.mkdir(parents=True,exist_ok=False)
 asm=out/'codec-usb-capture.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
 labels={n:CODE+v for n,v in O.symbols((out/'codec-usb-capture.doj').read_bytes()).items()}
 s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
 asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
 code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
 for off in offsets:
  if widths[off]!=6:continue
  v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
  if v>>40 in(0x10,0x11) and reg in(0x70,0x73,0x74):
   code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
 off=2*(labels['snapshot_mode.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
 image=bytearray(raw);hooks=[]
 for pc,before,name,resume in HOOKS:
  off=2*(labels[name+'_replay.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(before)
  after=C.S.to_bytes(0x063e00000000|labels[name+'_entry.']);C.B.write_span(image,C.S.code_address(pc,window='l2' if name=='snapshot' else 'l1'),after)
  hooks.append(dict(name=name,site=hex(pc),entry=hex(labels[name+'_entry.']),replay=hex(labels[name+'_replay.']),resume=hex(resume),before=m.read_sw(pc,6).hex(),after=after.hex()))
 physical=C.S.code_address(CODE,window='l2');assert physical==0x200e2500 and physical+len(code)<=0x200e3000
 blocks=[(physical,bytes(code)),(STATE,bytes(STATE_BYTES))];regions=C.B.load_regions(raw)
 for at,data in blocks:
  assert not any(at<a+len(v) and a<at+len(data) for a,v in regions);regions.append((at,data))
 result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['codec_usb_capture']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,hooks=hooks,code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),state=hex(STATE),state_bytes=STATE_BYTES,snapshot=hex(SNAPSHOT),last_copied_completion=hex(LAST),labels={n:hex(v) for n,v in labels.items()},instruction_offsets=offsets,system_register_fixes=fixes,
  contract='Diagnostic only: USB MAIN exports preceding completed codec PCM at unity gain. Native physical output, other USB streams, existing native export call and timing counters are retained.',
  ownership='Same serialized audio task copies after completed sign adjustment and T1DP timing bookkeeping, before software page toggle; next render exports snapshot before next completion replaces it. DMA pages are read-only here. A completion-count guard excludes unarmed/common-tail calls.',
  format='Signed codec Q31 including native final polarity -> FLOAT BY -31 -> planar float32 -> native unity-gain USB conversion/packing. This preserves the waveform to float32/USB24 precision, not all low Q31 bits.',
  latency='One preceding normal completed32-frame block, approximately0.667ms at48kHz. Zero-initialized startup; no stale mainmix fallback.',
  timing='Unrolled64-word snapshot plus small descriptor hook; no extra MMIO, wait, interrupt mask or hardware loop. Existing PCM deadline observer latches before copy, so copy overhead is excluded from same-block DC14 and may affect next-start timing.',
  limits=['Records committed PCM memory, not actual DAC pins/DMA page ownership/analog gain.', 'A DMA ownership or physical-output-only fault may remain absent from USB.', 'Recorder24-bit packing and float32 conversion quantize low PCM bits.', 'Diagnostic overhead must be checked with retained callback/timing observations on hardware.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hooks=hooks),indent=2))


if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
