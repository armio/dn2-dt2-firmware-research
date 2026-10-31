#!/usr/bin/env python3
"""Render codec PCM privately; commit the previous block early on native TX phase."""
from pathlib import Path
import argparse,json,re
import build_dt2_codec_delivery as P
D,T,C,B,A,O=P.D,P.T,P.C,P.B,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-codec-delivery-20261012/section_7.bin'
BASE_SHA='e5aa75585f1fe65d22fff3ba905b50766df5ec033f04d39e173b9bb427a38f9d'
CODE,STAGE,ZERO,STATE=0xbf2a80,0x200e6200,0x200e6300,0x200e6400
CODE_LIMIT=0x200e5f00
STATE_BYTES=0x200
SAVES={n:{r:STATE+off+4*i for i,r in enumerate(D.SAVE_NAMES)} for n,off in [('early',0),('sign',0x60),('tail',0xa0),('scheduler',0xe0)]}
EARLY_EXTRA={r:STATE+0x20+4*i for i,r in enumerate(('r4','r8','i4','l0','l4'))}
FIELDS={n:STATE+0x140+4*i for i,n in enumerate(('ready','normal_active','commits','zero_commits','staged_blocks','discarded_on_skip','discarded_on_special'))}
HOOKS=((0x1c9f12,0x0f02002c0678,'early',0x1c9f15),
 (0x1c9d3f,0x063e00bf2177,'converter',0x1c9d42),
 (0x1c9e2b,0x1604002c0478,'sign',0x1c9e2e),
 (0x1c9e54,0x063e00bf2245,'tail',0xbf0afa),
 (0x1c9fee,0x063e00bf0400,'scheduler',0xbf0400),
 (0xbf223f,0x1587fffffffe,'before_replay',None),
 (0xbf234a,0x063e00bf0afa,'after_replay',None))
NATIVE_PROLOGUE=0x1587fffffffe


def save(name):
 p=SAVES[name];return f'      DM({p["i0"]:#x}) = I0;\n'+D.mode_save(p,name)


def restore(name):return D.P.restore(SAVES[name])


def inc(n):
 return f'      R0 = DM({FIELDS[n]:#x});\n      R1 = 1;\n      R1 = R0 + R1;\n      DM({FIELDS[n]:#x}) = R1;\n'


def source():
 s='.SECTION/PM seg_pmco;\n'+T.label('early_entry.')+save('early')
 for reg,n in(('R4','r4'),('R8','r8'),('I4','i4'),('L0','l0'),('L4','l4')):s+=f'      DM({EARLY_EXTRA[n]:#x}) = {reg};\n'
 s+=f'''      R0 = 1;
      DM({FIELDS['normal_active']:#x}) = R0;
      R0 = DM({FIELDS['ready']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('early_zero.','IF EQ')+f'      I4 = {STAGE:#x};\n'+T.jump('early_source_ready.')
 s+=T.label('early_zero.')+inc('zero_commits')+f'      I4 = {ZERO:#x};\n'
 s+=T.label('early_source_ready.')+f'''      L0 = 0;
      L4 = 0;
      R0 = DM(0x268a38);
      R0 = LSHIFT R0 BY 8;
      R1 = 0x2c0478;
      R0 = R1 + R0;
      I0 = R0;
      R4 = R0;
      R2 = 4;
      R8 = R4 + R2;
      JUMP 0xbf2177; // unchanged T1DS before observation
'''
 s+=T.label('copy_entry.')
 for i in range(64):s+=f'      R0 = DM({i}, I4);\n      DM({i}, I0) = R0;\n'
 s+='      JUMP 0xbf2245; // unchanged T1DS after observation\n'
 s+=T.label('commit_complete.')+inc('commits')+f'      R0 = 0;\n      DM({FIELDS["ready"]:#x}) = R0;\n'
 for reg,n in(('R4','r4'),('R8','r8'),('L0','l0'),('L4','l4'),('I4','i4')):s+=f'      {reg} = DM({EARLY_EXTRA[n]:#x});\n'
 s+=restore('early')+T.label('early_replay.')+'      I0 = 0x12345678;\n      JUMP 0x1c9f15;\n'
 # Native delayed CALL and argument-delay stores are left unchanged. Redirect
 # its actual arguments only on entry, then execute the native stack prologue.
 s+=T.label('converter_entry.')+f'      R4 = {STAGE:#x};\n      R8 = {STAGE+4:#x};\n'+T.label('converter_replay.')+'      I0 = 0x12345678;\n      JUMP 0x1c9d42;\n'
 s+=T.label('sign_entry.')+save('sign')+f'      R0 = DM({FIELDS["normal_active"]:#x});\n      R1 = 0;\n      COMP(R0, R1);\n'+T.jump('sign_native.','IF EQ')
 s+=restore('sign')+f'      I4 = {STAGE:#x};\n      JUMP 0x1c9e2e;\n'
 s+=T.label('sign_native.')+restore('sign')+T.label('sign_replay.')+'      I0 = 0x12345678;\n      JUMP 0x1c9e2e;\n'
 s+=T.label('tail_entry.')+save('tail')+f'''      R0 = DM({FIELDS['normal_active']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('tail_special.','IF EQ')+inc('staged_blocks')+'      R0 = 1;\n'+T.jump('tail_ready.')
 s+=T.label('tail_special.')+f'      R0 = DM({FIELDS["ready"]:#x});\n      R1 = 0;\n      COMP(R0, R1);\n'+T.jump('tail_zero.','IF EQ')+inc('discarded_on_special')
 s+=T.label('tail_zero.')+'      R0 = 0;\n'+T.label('tail_ready.')+f'''      DM({FIELDS['ready']:#x}) = R0;
      R0 = 0;
      DM({FIELDS['normal_active']:#x}) = R0;
'''+restore('tail')+'      JUMP 0xbf0afa; // original T1DP completion and T1DR mirror\n'
 s+=T.label('scheduler_entry.')+save('scheduler')+'      R1 = 1;\n      COMP(R0, R1);\n'+T.jump('scheduler_restore.','IF EQ')
 s+=f'      R0 = DM({FIELDS["ready"]:#x});\n      R1 = 0;\n      COMP(R0, R1);\n'+T.jump('scheduler_clear.','IF EQ')+inc('discarded_on_skip')
 s+=T.label('scheduler_clear.')+f'      R0 = 0;\n      DM({FIELDS["ready"]:#x}) = R0;\n      DM({FIELDS["normal_active"]:#x}) = R0;\n'
 s+=T.label('scheduler_restore.')+restore('scheduler')+'      JUMP 0xbf0400; // original scheduler observer and exact branch\n'
 return s


def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text());k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 for pc,before,_,_ in HOOKS:
  ins=k.st.decode_at(m,None,pc);assert ins.raw==before and ins.length_bytes==6,(hex(pc),hex(ins.raw))
 out.mkdir(parents=True,exist_ok=False);asm=out/'codec-stage-commit.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
 labels={n:CODE+v for n,v in O.symbols((out/'codec-stage-commit.doj').read_bytes()).items()}
 s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s);asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
 code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
 for off in offsets:
  if widths[off]!=6:continue
  v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
  if v>>40 in(0x10,0x11) and reg in(0x70,0x73,0x74):
   code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
 for name in SAVES:
  off=2*(labels[name+'_mode.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
 for name,value in(('early',HOOKS[0][1]),('converter',NATIVE_PROLOGUE),('sign',HOOKS[2][1])):
  off=2*(labels[name+'_replay.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(value)
 image=bytearray(raw);hooks=[]
 for pc,before,name,resume in HOOKS:
  target=labels[{'before_replay':'copy_entry.','after_replay':'commit_complete.'}.get(name,name+'_entry.')]
  after=C.S.to_bytes(0x063e00000000|target);C.B.write_span(image,C.S.code_address(pc,window='l2' if name.endswith('_replay') else 'l1'),after)
  hooks.append(dict(name=name,site=hex(pc),entry=hex(target),resume=hex(resume) if resume else None,before=m.read_sw(pc,6).hex(),after=after.hex()))
 physical=C.S.code_address(CODE,window='l2');assert physical==0x200e5500 and physical+len(code)<=CODE_LIMIT,(len(code),hex(physical+len(code)))
 blocks=[(physical,bytes(code)),(STAGE,bytes(512)),(STATE,bytes(STATE_BYTES))];regions=C.B.load_regions(raw)
 for at,data in blocks:
  assert not any(at<a+len(v) and a<at+len(data) for a,v in regions),hex(at)
  regions.append((at,data))
 result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks));walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:];assert C.B.walk(result).complete
 doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['codec_stage_commit']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,hooks=hooks,code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),stage=hex(STAGE),zero=hex(ZERO),state=hex(STATE),state_bytes=STATE_BYTES,fields={n:hex(v) for n,v in FIELDS.items()},scratch={n:{r:hex(a) for r,a in v.items()} for n,v in SAVES.items()},early_extra={n:hex(v) for n,v in EARLY_EXTRA.items()},labels={n:hex(v) for n,v in labels.items()},instruction_offsets=offsets,system_register_fixes=fixes,
  contract='Commit previous completed private32-frame stereo Q31 stage to native selected TX PCM page immediately after native normal-start timing; convert/sign current block privately. Native2-page TX/RX rings and268A38 phase remain unchanged.',
  latency='One additional32-frame block, approximately0.667ms at48kHz. First normal block and every invalid pending stage commit zeros.',
  lifecycle='Entering1C9F12 covers normal path and storage transport rejoining it. Common-tail marksready only if normal_active; all other paths invalidate pendingstage. Any scheduler notification count otherthan1 invalidates pendingstage before unchanged native dispatch test. No special-mode routing change.',
  delivery_observer='Same T1DS before/after bodies now surround the early actualDMA-page copy, with only their exact6-byte replay destinations retargeted. Raw MMIO is observational: no page selection, veto, polling, DMA reconfiguration or interrupt masking.',
  mirror='T1DR mirror remains byte-identical and reads native268A38 page at late completion, which now contains the block committed early. Thus USB MAIN still mirrors committed physical PCM content, with existing snapshot latency.',
  timing='T1DP start timestamp/busy precede earlycopy. Its common completion now follows private conversion/sign and includes render+stage cost; DC14 is no longer the actual DMA-page copy deadline. T1DS windows/candidates surround the actual earlycopy.',
  unchanged=['Native delayed converter CALL and delay slots','Native converter loop and SIMD sign loop','Native RX input buffers and2-page phase toggle','SPORT/DMA descriptors/configuration/serial format','T1DS raw SPORT errors and phase publication','AllotherUSBstreams'],
  limits=['The earlier copy targets the native phase, without treating DMA address reads as synchronization.', 'A long interrupt or scheduler delay can still cause missed delivery; retained diagnostics measure residual conflicts.', 'Adds latency and clears invalidstage tozero afterstartup/specialmode/backlog; hardware recovery must be confirmed.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),hooks=hooks),indent=2))


if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
