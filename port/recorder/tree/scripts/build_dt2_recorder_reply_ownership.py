#!/usr/bin/env python3
"""Keep final timing publication from replacing an active Recorder's reply."""
from pathlib import Path
import argparse,json
import build_dt2_dsp_block_timing as T
import build_dt2_recording_input as R
C,B,A,O=T.C,T.B,T.A,T.O
SITE,CODE=0xbf02a1,0xbfae00


def build(parent,out):
 raw=(parent/'section_7.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
 assert C.SHA(raw)==doc['section7_sha256']
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
 memory=B.decode_view(k,raw);before=memory.read_sw(SITE,6)
 assert before==C.S.to_bytes(0x023e7800f600) # R0=LSHIFT(completed,-10), after counter update.
 restore=int(doc['block_timing_diagnostic']['labels']['exit_restore.'],16)
 assert restore==0xbf0302
 out.mkdir(parents=True,exist_ok=False)
 source=f'''.SECTION/PM seg_pmco;
.GLOBAL recorder_reply_guard.
recorder_reply_guard.:
      R2 = DM({R.WIRE+24:#x});
      R2 = LSHIFT R2 BY -16;
      R1 = 0x5243;
      COMP(R2, R1);
      IF EQ JUMP {restore:#x};
      R1 = 1;
.GLOBAL recorder_reply_replay.
recorder_reply_replay.:
      I0 = 0x12345678;
      JUMP {SITE+3:#x};
'''
 asm=out/'recorder-reply-ownership.asm';asm.write_text(source)
 obj,offsets=A._selas(asm,out);code=bytearray(O.load_bytes(obj))
 labels={name:CODE+value for name,value in O.symbols((out/'recorder-reply-ownership.doj').read_bytes()).items()}
 replay=2*(labels['recorder_reply_replay.']-CODE);assert replay in offsets
 code[replay:replay+6]=before
 physical=C.S.code_address(CODE,window='l2')
 assert physical==0x200f5c00 and physical+len(code)<=0x200f6000
 assert not any(a<physical+len(code) and physical<a+len(data) for a,data in C.B.load_regions(raw))
 image=bytearray(raw);hook=C.S.to_bytes(0x063e00000000|CODE)
 C.B.write_span(image,C.S.code_address(SITE,window='l2'),hook)
 result=C.B.insert_before_final(bytes(image),C.B.block(physical,bytes(code)))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=C.SHA(raw),section7_sha256=C.SHA(result),flash_ready=False)
 doc['recorder_reply_ownership']=dict(base=str(parent.resolve()/'section_7.bin'),base_sha256=C.SHA(raw),
     code=hex(CODE),physical=hex(physical),bytes=len(code),instruction_offsets=offsets,
     labels={name:hex(value) for name,value in labels.items()},
     hook=dict(site=hex(SITE),resume=hex(SITE+3),before=before.hex(),after=hook.hex()),
     enabled_cookie_address=hex(R.WIRE+26),enabled_cookie='0x5243',restore=hex(restore),
     fields_preserved={'4':'recorded frame count','8':'audition position','12..19':'L/R level and peak','20':'recording state'},
     contract='Record timing counters/maxima as before. While Recorder controls are enabled, skip only final render-exit diagnostic reply writes that share Recorder count/meters. When closed, unchanged diagnostic serialization resumes.',
     unchanged=['Capture/threshold/length/monitor/audition','Source buffers and audio math','USB42 packing and AC4 frame length','Timing counter accumulation'],
     limits=['Native earlier render diagnostics may use both header pages; Recorder publishes current page later in the same render.',
             'Physical capture/trim hardware validation remains required.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=doc['section7_sha256'],code_bytes=len(code),hook=doc['recorder_reply_ownership']['hook']),indent=2))


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('parent',type=Path);p.add_argument('--out',type=Path,required=True)
 a=p.parse_args();build(a.parent,a.out)
