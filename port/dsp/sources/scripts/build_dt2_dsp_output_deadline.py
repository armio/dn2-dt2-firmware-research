#!/usr/bin/env python3
"""Observe codec callback, normal work start and completed PCM; change no audio logic."""
from pathlib import Path
import argparse,json,re
import build_dt2_dsp_scheduler_backlog as P
T,C,B,A,O=P.T,P.C,P.B,P.A,P.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-scheduler-backlog-20261011/section_7.bin'
BASE_SHA='c6ea18b38338f157b5ddf177f9a15ccfc54b2aab0923c04279b720ed7d82409f'
CODE,STATE=0xbf0a00,0x200e2200
SAVE_NAMES=P.SAVE_NAMES
ISR={n:STATE+4*i for i,n in enumerate(SAVE_NAMES)}
TASK={n:STATE+0x40+4*i for i,n in enumerate(SAVE_NAMES)}
PUB={n:STATE+0x80+4*i for i,n in enumerate(SAVE_NAMES)}
ISR_CLOCK=STATE+0x1c
FIELDS={n:STATE+0x100+4*i for i,n in enumerate((
 'callback_seen','callback_generation','callback_stamp','busy','crossed','armed',
 'active_generation','active_callback_stamp','start_stamp','done_stamp',
 'start_last','start_max','done_last','done_max','busy_callbacks','crossed_completions',
 'valid_completions','invalid_starts','invalid_completions'))}
STATE_BYTES=0x14c
HOOKS=((0x1ca14c,0x100400268a84,'callback'),
       (0x1c9f0f,0x04bff8000000,'start'),
       (0x1c9e54,0x100100268a38,'done'))
PUB_SITE,PUB_RESUME=P.PUB_SITE,P.PUB_RESUME


def mode_save(fields,name):
 s=T.label(name+'_mode.')+'      I0 = 0x12345678; // MODE1 scalar copy\n'
 s+=f'      DM({fields["mode"]:#x}) = I0;\n      BIT CLR MODE1 0x200000;\n      NOP;\n      NOP;\n'
 for r,n in (('R0','r0'),('R1','r1'),('R2','r2'),('ASTATX','asx'),('ASTATY','asy')):
  s+=f'      DM({fields[n]:#x}) = {r};\n'
 return s


def clock(name,dest):
 return T.label(name+'_clock.')+f'      I0 = 0x12345678; // EMUCLK scalar copy\n      DM({dest:#x}) = I0;\n'


def increment(field):
 return f'      R0 = DM({FIELDS[field]:#x});\n      R1 = 1;\n      R1 = R0 + R1;\n      DM({FIELDS[field]:#x}) = R1;\n'


def maximum(last,maximum,label):
 return f'''      DM({FIELDS[last]:#x}) = R0;
      R1 = DM({FIELDS[maximum]:#x});
      COMPU(R0, R1);
'''+T.jump(label,'IF LE')+f'      DM({FIELDS[maximum]:#x}) = R0;\n'+T.label(label)


def restore(fields,name,resume,replay=True):
 s=T.label(name+'_restore.')+P.restore(fields)
 if replay:s+=T.label(name+'_replay.')+'      I0 = 0x12345678; // exact native displaced instruction\n'
 return s+f'      JUMP {resume:#x};\n'


def source():
 s='.SECTION/PM seg_pmco;\n'+T.label('callback_entry.')
 s+=f'      DM({ISR["i0"]:#x}) = I0;\n'+clock('callback',ISR_CLOCK)+mode_save(ISR,'callback')
 s+=f'''      R0 = DM({ISR_CLOCK:#x});
      DM({FIELDS['callback_stamp']:#x}) = R0;
      R0 = 1;
      DM({FIELDS['callback_seen']:#x}) = R0;
      R0 = DM({FIELDS['busy']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('callback_publish_generation.','IF EQ')
 s+=increment('busy_callbacks')+f'      R0 = 1;\n      DM({FIELDS["crossed"]:#x}) = R0;\n'
 # Generation is the last public callback field written. The task cannot run
 # midway through this ISR; gen/stamp/gen brackets detect a completed interrupt.
 s+=T.label('callback_publish_generation.')+increment('callback_generation')
 s+=restore(ISR,'callback',HOOKS[0][0]+3)
 s+=T.label('start_entry.')+f'''      DM({TASK['i0']:#x}) = I0;
      I0 = 0;
      DM({FIELDS['crossed']:#x}) = I0;
      DM({FIELDS['armed']:#x}) = I0;
      I0 = 1;
'''+T.label('start_set_busy.')+f'      DM({FIELDS["busy"]:#x}) = I0;\n'+mode_save(TASK,'start')
 s+=f'''      R0 = DM({FIELDS['callback_seen']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('start_invalid.','IF EQ')
 s+=T.label('start_generation_first.')+f'      R0 = DM({FIELDS["callback_generation"]:#x});\n'
 s+=T.label('start_callback_stamp.')+f'      R1 = DM({FIELDS["callback_stamp"]:#x});\n'
 s+=T.label('start_generation_second.')+f'''      R2 = DM({FIELDS['callback_generation']:#x});
      COMP(R0, R2);
'''+T.jump('start_invalid.','IF NE')
 s+=f'''      DM({FIELDS['active_generation']:#x}) = R0;
      DM({FIELDS['active_callback_stamp']:#x}) = R1;
'''+clock('start',FIELDS['start_stamp'])
 s+=f'''      R0 = DM({FIELDS['start_stamp']:#x});
      R0 = R0 - R1;
'''+maximum('start_last','start_max','start_max_done.')
 s+=f'      R0 = 1;\n      DM({FIELDS["armed"]:#x}) = R0;\n'+T.jump('start_restore.')
 s+=T.label('start_invalid.')+increment('invalid_starts')
 s+=restore(TASK,'start',HOOKS[1][0]+3)
 s+=T.label('done_entry.')+f'      DM({TASK["i0"]:#x}) = I0;\n'+clock('done',FIELDS['done_stamp'])
 s+='      I0 = 0;\n'+T.label('done_clear_busy.')+f'      DM({FIELDS["busy"]:#x}) = I0;\n'+mode_save(TASK,'done')
 s+=f'''      R0 = DM({FIELDS['armed']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('done_invalid.','IF EQ')
 s+=f'''      DM({FIELDS['armed']:#x}) = R1;
      R0 = DM({FIELDS['done_stamp']:#x});
      R1 = DM({FIELDS['active_callback_stamp']:#x});
      R0 = R0 - R1;
'''+maximum('done_last','done_max','done_max_done.')
 s+=increment('valid_completions')
 s+=f'''      R0 = DM({FIELDS['crossed']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('done_restore.','IF EQ')
 s+=increment('crossed_completions')+T.jump('done_restore.')
 s+=T.label('done_invalid.')+increment('invalid_completions')
 s+=restore(TASK,'done',HOOKS[2][0]+3)
 # Retain the original legacy publisher's native store before replacing only
 # the diagnostic words with the expanded eight-phase schema.
 s+=T.label('publication_entry.')+'      DM(0x2c59d4) = R0;\n'
 s+=f'      DM({PUB["i0"]:#x}) = I0;\n'+mode_save(PUB,'publication')
 s+=f'''      R0 = DM({P.P.HEARTBEAT:#x});
      R0 = LSHIFT R0 BY -10;
      R1 = 7;
      R0 = R0 AND R1;
'''
 for phase in range(6):
  s+=f'      R1 = {phase};\n      COMP(R0, R1);\n'+T.jump(f'publication_phase{phase}.','IF EQ')
 s+=T.jump('publication_phase6.')
 pairs=((T.FIELDS['last'],T.FIELDS['max']),
        (T.FIELDS['completed'],T.FIELDS['overbudget']),
        (P.FIELDS['backlog_skips'],P.FIELDS['max_notification_count']),
        (FIELDS['start_last'],FIELDS['start_max']),
        (FIELDS['done_last'],FIELDS['done_max']),
        (FIELDS['busy_callbacks'],FIELDS['crossed_completions']),
        (FIELDS['callback_generation'],FIELDS['valid_completions']))
 for phase,(left,right) in enumerate(pairs):
  s+=T.label(f'publication_phase{phase}.')+P.publish(left,12)+P.publish(right,16)
  s+=f'      I0 = {((0xdc10+phase)<<16)|0x4f53:#x};\n'+T.jump('publication_marker.')
 s+=T.label('publication_marker.')+''.join(f'      DM({p+4:#x}) = I0;\n' for p in T.PAGES)
 s+=restore(PUB,'publication',PUB_RESUME,replay=False)
 return s


def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
 out.mkdir(parents=True,exist_ok=False)
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 for pc,before,_ in HOOKS:
  ins=k.st.decode_at(m,None,pc);assert ins.raw==before and ins.length_bytes==6
 oldpub=int(doc['scheduler_backlog']['labels']['publication_entry.'],16)
 assert m.read_sw(PUB_SITE,6)==C.S.to_bytes(0x063e00000000|oldpub)
 asm=out/'output-deadline.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
 labels={n:CODE+v for n,v in O.symbols((out/'output-deadline.doj').read_bytes()).items()}
 s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
 asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
 code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
 for off in offsets:
  if widths[off]!=6:continue
  v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
  if v>>40 in(0x10,0x11) and reg in(0x70,0x73,0x74):
   code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
 for name in ('callback','start','done','publication'):
  off=2*(labels[name+'_mode.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
 for name in ('callback','start','done'):
  off=2*(labels[name+'_clock.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['EMUCLK']))
 image=bytearray(raw);hooks=[]
 for pc,before,name in HOOKS:
  off=2*(labels[name+'_replay.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(before)
  after=C.S.to_bytes(0x063e00000000|labels[name+'_entry.']);C.B.write_span(image,C.S.code_address(pc,window='l1'),after)
  hooks.append(dict(site=hex(pc),entry=hex(labels[name+'_entry.']),replay=hex(labels[name+'_replay.']),resume=hex(pc+3),before=C.S.to_bytes(before).hex(),after=after.hex(),name=name))
 after=C.S.to_bytes(0x063e00000000|labels['publication_entry.'])
 C.B.write_span(image,C.S.code_address(PUB_SITE,window='l2'),after)
 hooks.append(dict(site=hex(PUB_SITE),entry=hex(labels['publication_entry.']),resume=hex(PUB_RESUME),before=m.read_sw(PUB_SITE,6).hex(),after=after.hex(),name='publication'))
 physical=C.S.code_address(CODE,window='l2');assert physical==0x200e1400 and physical+len(code)<=0x200e2000
 assert STATE+STATE_BYTES<=0x200e3000
 regions=C.B.load_regions(raw);blocks=[(physical,bytes(code)),(STATE,bytes(STATE_BYTES))]
 for at,data in blocks:
  assert not any(at<a+len(v) and a<at+len(data) for a,v in regions),hex(at)
  regions.append((at,data))
 result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
 names=(('last_render_cycles','max_render_cycles'),('completed_render_calls','above_nominal_budget_calls'),
 ('backlog_skips','max_notification_count'),('callback_to_start_last','callback_to_start_max'),
 ('callback_to_pcm_complete_last','callback_to_pcm_complete_max'),('callback_while_busy','completed_blocks_with_callback_overlap'),
 ('accepted_callback_generation','valid_normal_completions'))
 doc['output_deadline']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,hooks=hooks,
  code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),state=hex(STATE),state_bytes=STATE_BYTES,
  labels={n:hex(v) for n,v in labels.items()},instruction_offsets=offsets,system_register_fixes=fixes,
  fields={n:hex(v) for n,v in FIELDS.items()},scratch={name:{n:hex(v) for n,v in fields.items()} for name,fields in [('isr',ISR),('task',TASK),('publication',PUB)]},
  callback_clock_scratch=hex(ISR_CLOCK),phase=f'(DM({P.P.HEARTBEAT:#x}) >> 10) & 7',
  schema={hex(0x4f53dc10+i):{'heartbeat_phase':[i] if i<6 else [6,7],'3':a,'4':b} for i,(a,b) in enumerate(names)},
  byte_order='Canonical CF big-endian32 directly; DSP pre-halfswaps before native MSB-first16 transport.',
  untouched_cf_words=[0,2,5,6],measurement_hooks_unchanged=True,
  contract='Observe accepted codec callback100, normal task start and completed PCM before page toggle. Replay exact native instructions. No MMIO reads, interrupt masking, scheduling, audio or allocator changes.',
  snapshot='Start checks callback_seen then generation/stamp/generation. Callback writes generation last; task cannot execute midway through ISR. Unstable/startup snapshots do not arm valid completion. Completion uses the start-captured stamp, never the newest callback.',
  overlap='ISR counts each accepted callback while busy and sets a sticky crossed flag. Start clears crossed before setting busy. Completion clears busy before bookkeeping and counts one crossed block per valid completion. ISR after clear cannot change this block overlap status.',
  boundary_margin='Done latches EMUCLK at scalar instruction2 and clears busy at instruction5 after its branch entry; a callback in this small post-PCM interval may conservatively count as overlap. Start sets busy at instruction6 before native work; diagnostic overhead is included.',
  counters='All event counts and EMUCLK ages are uint32 modulo2^32; maxima retained since boot. Accepted callback generation increments once per event100, even if no normal render completes.',
  limits=['Callback overlap is not a proven DAC underrun or exact DMA ownership measurement. Interrupt delivery may itself be late.',
   'Startup and unstable start snapshots increment internal invalid counters; published zero requires advancing accepted-callback and valid-completion observations.',
   'Normal-completion guard suppresses unarmed/common-tail calls; missing publication or stale counters is unavailable evidence.',
   'The observer adds execution overhead; no timing bound is claimed by offline checks.',
   'Callback, task and publication use separate saves; the native accepted callback is assumed non-reentrant on the same core.',
   'Publication words are not atomic. Host phase/heartbeat and count consistency checks remain required.',
   'Existing DC10/DC11/DC12 fields are retained but now use phases0/1/2 of eight; original DC00/DC01 exit publication remains.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),state_bytes=STATE_BYTES,hooks=hooks),indent=2))

if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
