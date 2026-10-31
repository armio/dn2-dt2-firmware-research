#!/usr/bin/env python3
"""Retain codec SPORT errors and read-only TX DMA phase around native PCM writes."""
from pathlib import Path
import argparse,json,re
import build_dt2_dsp_output_deadline as D
T,C,B,A,O=D.T,D.C,D.B,D.A,D.O
BASE=C.ROOT/'output/dn2-research/dt2-dsp-codec-usb-capture-fix-20261012/section_7.bin'
BASE_SHA='599deffd6d8f5d31b391e414abe9428014bfb57c9fc98c9edda4dc54f6f85991'
CODE,STATE=0xbf2100,0x200e5200
CODE_LIMIT=0x200e4f00
STATE_BYTES=0x200
SAVES={n:{r:STATE+off+4*i for i,r in enumerate(D.SAVE_NAMES)} for n,off in [('isr',0),('task',0x40),('publication',0x80)]}
FIELDS={n:STATE+0x100+4*i for i,n in enumerate((
 'tx_errors','rx_errors','tx_raw_or','rx_raw_or','windows','candidates','armed','config_seen',
 'sport_ctl','dma_cfg','cpu_base','before_start','before_cur','before_stat','before_end',
 'after_start','after_cur','after_stat','after_end','flags','record_id_flags','record_cpu_base',
 'record_before_start','record_before_cur','record_before_stat','record_after_start','record_after_cur','record_after_stat'))}
HOOKS=((0x1c9d3f,0x1587fffffffe,'before',0x1c9d42),
       (0x1c9e54,0x063e00bf0afa,'after',0xbf0afa),
       (0x1cc9a0,0x160400000020,'error',0x1cc9a3))
PUB_SITE,PUB_RESUME=D.PUB_SITE,D.PUB_RESUME
DMA,SPORT=0x31023000,0x31002400
MMIO=(SPORT,DMA+8,DMA+4,DMA+0x2c,DMA+0x30)


def save(name,group):
 p=SAVES[group]
 return f'      DM({p["i0"]:#x}) = I0;\n'+D.mode_save(p,name)


def restore(name,group,resume,replay=True):
 s=T.label(name+'_restore.')+D.P.restore(SAVES[group])
 if replay:s+=T.label(name+'_replay.')+'      I0 = 0x12345678; // exact displaced native instruction\n'
 return s+f'      JUMP {resume:#x};\n'


def inc(name):
 return f'      R0 = DM({FIELDS[name]:#x});\n      R1 = 1;\n      R1 = R0 + R1;\n      DM({FIELDS[name]:#x}) = R1;\n'


def flag(bits):
 return f'      R0 = DM({FIELDS["flags"]:#x});\n      R1 = {bits};\n      R0 = R0 OR R1;\n      DM({FIELDS["flags"]:#x}) = R0;\n'


def snapshot(name):
 s=''
 for key,off in (('start',4),('cur',0x2c),('stat',0x30),('end',4)):
  s+=T.label(name+'_read_'+key+'.')+f'      R0 = DM({DMA+off:#x});\n      DM({FIELDS[name+"_"+key]:#x}) = R0;\n'
 s+=f'      R1 = DM({FIELDS[name+"_start"]:#x});\n      COMP(R0, R1);\n'+T.jump(name+'_observed.','IF NE')
 s+=flag(2 if name=='before' else 4)
 s+=f'''      R0 = DM({FIELDS[name+'_start']:#x});
      R1 = DM({FIELDS['cpu_base']:#x});
      R2 = 0x28000000;
      R1 = R1 + R2;
      COMP(R0, R1);
'''+T.jump(name+'_observed.','IF NE')
 s+=f'''      R0 = DM({FIELDS[name+'_cur']:#x});
      COMPU(R0, R1);
'''+T.jump(name+'_observed.','IF LT')
 s+='      R2 = 256;\n      R1 = R1 + R2;\n      COMPU(R0, R1);\n'+T.jump(name+'_observed.','IF GE')
 s+=flag(8 if name=='before' else 16)+T.label(name+'_observed.')
 return s


def source():
 s='.SECTION/PM seg_pmco;\n'+T.label('error_entry.')+save('error','isr')
 s+='      R0 = I4;\n      R1 = 0x31002400;\n      COMP(R0, R1);\n'+T.jump('error_tx.','IF EQ')
 s+='      R1 = 0x31002480;\n      COMP(R0, R1);\n'+T.jump('error_rx.','IF EQ')+T.jump('error_restore.')
 for n in ('tx','rx'):
  s+=T.label('error_'+n+'.')+inc(n+'_errors')
  s+=f'      R0 = DM({FIELDS[n+"_raw_or"]:#x});\n      R1 = R15;\n      R0 = R0 OR R1;\n      DM({FIELDS[n+"_raw_or"]:#x}) = R0;\n'+T.jump('error_restore.')
 s+=restore('error','isr',0x1cc9a3)
 s+=T.label('before_entry.')+save('before','task')
 s+=f'      R0 = 0;\n      DM({FIELDS["armed"]:#x}) = R0;\n      R0 = R4;\n      R1 = 0x2c0478;\n      COMP(R0, R1);\n'+T.jump('before_known.','IF EQ')
 s+='      R1 = 0x2c0578;\n      COMP(R0, R1);\n'+T.jump('before_restore.','IF NE')
 s+=T.label('before_known.')+'      R1 = R4;\n      R2 = 4;\n      R1 = R1 + R2;\n      R0 = R8;\n      COMP(R0, R1);\n'+T.jump('before_restore.','IF NE')+f'''      R0 = R4;
      DM({FIELDS['cpu_base']:#x}) = R0;
      R0 = 65;
      DM({FIELDS['flags']:#x}) = R0;
      R0 = DM({FIELDS['config_seen']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('before_config_done.','IF NE')
 s+=f'''      R0 = DM({SPORT:#x});
      DM({FIELDS['sport_ctl']:#x}) = R0;
      R0 = DM({DMA+8:#x});
      DM({FIELDS['dma_cfg']:#x}) = R0;
      R0 = 1;
      DM({FIELDS['config_seen']:#x}) = R0;
'''+T.label('before_config_done.')+snapshot('before')
 s+=f'      R0 = 1;\n      DM({FIELDS["armed"]:#x}) = R0;\n'+restore('before','task',0x1c9d42)
 s+=T.label('after_entry.')+save('after','task')
 s+=f'''      R0 = DM({FIELDS['armed']:#x});
      R1 = 0;
      COMP(R0, R1);
'''+T.jump('after_restore.','IF EQ')
 s+=f'      DM({FIELDS["armed"]:#x}) = R1;\n'+snapshot('after')+inc('windows')
 s+=f'      R0 = DM({FIELDS["flags"]:#x});\n      R1 = 24;\n      R0 = R0 AND R1;\n      R1 = 0;\n      COMP(R0, R1);\n'+T.jump('after_baseline.','IF EQ')
 s+=inc('candidates')+flag(32)
 s+=f'      R0 = DM({FIELDS["record_id_flags"]:#x});\n      R0 = LSHIFT R0 BY -8;\n      R1 = 2;\n      COMP(R0, R1);\n'+T.jump('after_restore.','IF EQ')
 s+='      R2 = 0x200;\n'+T.jump('after_freeze.')
 s+=T.label('after_baseline.')+f'      R0 = DM({FIELDS["record_id_flags"]:#x});\n      R1 = 0;\n      COMP(R0, R1);\n'+T.jump('after_restore.','IF NE')+'      R2 = 0x100;\n'
 s+=T.label('after_freeze.')
 for n in ('cpu_base','before_start','before_cur','before_stat','after_start','after_cur','after_stat'):
  s+=f'      R0 = DM({FIELDS[n]:#x});\n      DM({FIELDS["record_"+n]:#x}) = R0;\n'
 s+=f'      R0 = DM({FIELDS["flags"]:#x});\n      R0 = R0 OR R2;\n'+T.label('after_publish_record.')+f'      DM({FIELDS["record_id_flags"]:#x}) = R0;\n'
 s+=restore('after','task',0xbf0afa)
 s+=T.label('publication_entry.')+'      DM(0x2c59d4) = R0;\n'+save('publication','publication')
 s+=f'      R0 = DM({D.P.P.HEARTBEAT:#x});\n      R0 = LSHIFT R0 BY -10;\n      R1 = 15;\n      R0 = R0 AND R1;\n'
 for phase in range(15):
  s+=f'      R1 = {phase};\n      COMP(R0, R1);\n'+T.jump(f'publication_phase{phase}.','IF EQ')
 s+=T.jump('publication_phase15.')
 oldpairs=((T.FIELDS['last'],T.FIELDS['max']),(T.FIELDS['completed'],T.FIELDS['overbudget']),
           (D.P.FIELDS['backlog_skips'],D.P.FIELDS['max_notification_count']),
           (D.FIELDS['start_last'],D.FIELDS['start_max']),(D.FIELDS['done_last'],D.FIELDS['done_max']),
           (D.FIELDS['busy_callbacks'],D.FIELDS['crossed_completions']),
           (D.FIELDS['callback_generation'],D.FIELDS['valid_completions']))
 oldpairs+=oldpairs[-1:]
 pairs=oldpairs+tuple((FIELDS[x],FIELDS[y]) for x,y in (
  ('tx_errors','rx_errors'),('tx_raw_or','rx_raw_or'),('windows','candidates'),
  ('record_before_cur','record_after_cur'),('record_before_start','record_after_start'),
  ('record_before_stat','record_after_stat'),('record_cpu_base','record_id_flags'),('sport_ctl','dma_cfg')))
 tags=list(range(0xdc10,0xdc17))+[0xdc16]+list(range(0xdc17,0xdc1f))
 for phase,((left,right),tag) in enumerate(zip(pairs,tags)):
  s+=T.label(f'publication_phase{phase}.')+D.P.publish(left,12)+D.P.publish(right,16)
  s+=f'      I0 = {(tag<<16)|0x4f53:#x};\n'+T.jump('publication_marker.')
 s+=T.label('publication_marker.')+''.join(f'      DM({p+4:#x}) = I0;\n' for p in T.PAGES)
 s+=restore('publication','publication',PUB_RESUME,replay=False)
 return s


def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=B.decode_view(k,raw)
 for pc,before,_,_ in HOOKS:
  ins=k.st.decode_at(m,None,pc);assert ins.raw==before and ins.length_bytes==6
 oldpub=int(doc['output_deadline']['labels']['publication_entry.'],16)
 assert m.read_sw(PUB_SITE,6)==C.S.to_bytes(0x063e00000000|oldpub)
 out.mkdir(parents=True,exist_ok=False)
 asm=out/'codec-delivery.asm';s=source();asm.write_text(s);be,offsets=A._selas(asm,out)
 labels={n:CODE+v for n,v in O.symbols((out/'codec-delivery.doj').read_bytes()).items()}
 s=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda x:x[1]+hex(labels[x[3]])+x[2],s)
 asm.write_text(s);be,again=A._selas(asm,out);assert again==offsets
 code=bytearray(O.load_bytes(be));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])};fixes=[]
 for off in offsets:
  if widths[off]!=6:continue
  v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
  if v>>40 in(0x10,0x11) and reg in(0x70,0x73,0x74):
   code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x70:0x72,0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(hex(CODE+off//2))
 for name in ('error','before','after','publication'):
  off=2*(labels[name+'_mode.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(T.D.ureg_copy(k.st.UREG_CODES['MODE1']))
 image=bytearray(raw);hooks=[]
 for pc,before,name,resume in HOOKS:
  off=2*(labels[name+'_replay.']-CODE);assert widths[off]==6;code[off:off+6]=C.S.to_bytes(before)
  after=C.S.to_bytes(0x063e00000000|labels[name+'_entry.']);C.B.write_span(image,C.S.code_address(pc,window='l1'),after)
  hooks.append(dict(name=name,site=hex(pc),entry=hex(labels[name+'_entry.']),replay=hex(labels[name+'_replay.']),resume=hex(resume),before=m.read_sw(pc,6).hex(),after=after.hex()))
 after=C.S.to_bytes(0x063e00000000|labels['publication_entry.']);C.B.write_span(image,C.S.code_address(PUB_SITE,window='l2'),after)
 hooks.append(dict(name='publication',site=hex(PUB_SITE),entry=hex(labels['publication_entry.']),resume=hex(PUB_RESUME),before=m.read_sw(PUB_SITE,6).hex(),after=after.hex()))
 physical=C.S.code_address(CODE,window='l2');assert physical==0x200e4200 and physical+len(code)<=CODE_LIMIT,(hex(physical),len(code))
 assert max(FIELDS.values())+4<=STATE+STATE_BYTES<=0x200e5800
 blocks=[(physical,bytes(code)),(STATE,bytes(STATE_BYTES))]
 # Includes payload and fill spans, in their full inherited load order.
 regions=C.B.load_regions(raw)
 for at,data in blocks:
  assert not any(at<a+len(v) and a<at+len(data) for a,v in regions),hex(at)
  regions.append((at,data))
 result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,b) for a,b in blocks))
 walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
 result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
 assert C.B.walk(result).complete
 doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
 names=(('tx_sport_error_callbacks','rx_sport_error_callbacks'),('tx_sport_err_raw_or','rx_sport_err_raw_or'),
 ('completed_pcm_windows','candidate_same_page_windows'),('record_before_addr_cur','record_after_addr_cur'),
 ('record_before_addr_start','record_after_addr_start'),('record_before_dma_stat','record_after_dma_stat'),
 ('record_cpu_write_base','record_identity_flags'),('initial_sport4a_ctl','initial_dma10_cfg'))
 doc['codec_delivery']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,hooks=hooks,code=hex(CODE),code_physical=hex(physical),code_bytes=len(code),state=hex(STATE),state_bytes=STATE_BYTES,labels={n:hex(v) for n,v in labels.items()},fields={n:hex(v) for n,v in FIELDS.items()},scratch={n:{r:hex(a) for r,a in p.items()} for n,p in SAVES.items()},instruction_offsets=offsets,system_register_fixes=fixes,
  schema={hex(0x4f53dc17+i):dict(phase=8+i,**{'3':a,'4':b}) for i,(a,b) in enumerate(names)},phase=f'(DM({D.P.P.HEARTBEAT:#x}) >> 10) & 15',old_phases_0_through_7_unchanged=True,
  record_flags={'0':'valid completed converter window','1':'before START bracket equal','2':'after START bracket equal','3':'before coherent START==CPU+28000000 and CUR in [CPU+28000000,CPU+28000100)','4':'after coherent START==CPU+28000000 and CUR in [CPU+28000000,CPU+28000100)','5':'candidate: bit3 or bit4','6':'recognized CPU base','8..31':'record identity:1 first baseline,2 first candidate'},
  record_contract='Freeze first recognized completed converter window; replace at most once with first candidate window. Identity published last. Host requires matching identity/flags bracketing raw record pages; fields are phase evidence, not an atomic live register snapshot.',
  candidate='Either boundary START reads agree, equal recognized CPU write page plus physical alias0x28000000, and unsigned ADDR_CUR falls inside that256-byte physical page. Hardware pointer/FIFO progress can lead physical output, so candidate is not a demonstrated underrun or corrupt transfer.',
  mmio_reads={'per_before':['DMA10_ADDRSTART','DMA10_ADDR_CUR','DMA10_STAT','DMA10_ADDRSTART'],'per_after':['DMA10_ADDRSTART','DMA10_ADDR_CUR','DMA10_STAT','DMA10_ADDRSTART'],'first_before_only':['SPORT4A_CTL','DMA10_CFG'],'addresses':[hex(a) for a in MMIO]},
  error_contract='Capture existing R15 raw SPORT_ERR before exact native W1C ack. Classify I4 channel base as codec TX31002400 orRX31002480; other channels ignored. No new error reads, clears, interrupt enables or MMIO writes.',
  source_reference='Local Analog Devices ADSP-2156x HWR:23-43/44,23-82/83 SPORT errors;27-39/40 pointer synchronization;27-44/45 current addresses;27-58..63 descriptor/status semantics. Native startup1CCDE4..1CCDF6 OR7 enables error interrupt masks.',
  timing='Eight read-only MMIO reads per normal converter window, plus2 initial config reads. Post-sign observer precedes existing T1DP clock/busy-clear and therefore increases its boundary margin by observer cost. No cycle bound inferred from instruction count.',
  retained='T1DR preceding-completed-codec USB MAIN mirror, native physical output, all other USB streams, scheduler/render/deadline observer state and native scheduling remain intact.',
  limits=['DMA current address and START are phase evidence, not DAC pin state; no precise per-word ownership guarantee.', 'Equal START brackets can miss a full ring ABA if preemption spans an entire cycle; no interrupt masking or polling added.', 'Error counters count callback invocations and sticky bits, not number of lost words; zero means no observed callback, not underrun-free output.', 'One-time configuration may become stale if native code later reconfigures hardware.', 'uint32 counters wrap; host must reject decreasing windows for delta interpretation.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),code_bytes=len(code),state_bytes=STATE_BYTES,hooks=hooks),indent=2))


if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
