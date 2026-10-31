#!/usr/bin/env python3
"""Bound the DN2 PCM transport and propagate its failure through DT2 loading."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-dsp-boot-capacity-20261010'
SHA='25a8d8b8528d25eac803702045a1333c782c5f6a7dab2a15813f574125b9f610'

def build(out):
 raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
 doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
 payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
 def mapped(old):
  for cfg in doc.values():
   if not isinstance(cfg,dict):continue
   for sp in cfg.get('spans',[]):
    if not all(k in sp for k in ('donor','end','runtime')):continue
    lo,hi=int(sp['donor'],16),int(sp['end'],16)
    if lo<=old<hi:return int(sp['runtime'],16)+old-lo
  for cfg in doc.values():
   if not isinstance(cfg,dict):continue
   for edit in cfg.get('edits',[]):
    if edit.get('target')==hex(old) and 'binding' in edit:return int(edit['binding'],16)
  raise AssertionError(hex(old))
 m=doc['sample_restore_lifecycle']['methods'];loader=doc['sample_loader']['methods']
 eq={'LOAD_ERROR':mapped(0x401547ca),'UNLOAD':int(loader['unload'],16),'FILE_CLOSE':mapped(0x401585e4),'BUFFER_DESTROY':int(doc['pcm_pages']['methods']['owned_buffer_destroy'],16),
     'RESTORE_DONE':int(m['sample_restore_done'],16),'RESTORE_REQUESTED':int(m['sample_restore_requested'],16)}
 source='.text\n'+''.join(f'.equ {k},{v:#x}\n' for k,v in eq.items())
 source+=(B.T.ROOT/'scripts/asm/dn2_dsp_transfer_wait.S').read_text()
 # Retain the exact native byte ordering and output strobes; replace only its wait.
 for name,entry in [('control',0x400cf178),('pcm',0x400cf204)]:
  prefix=raw[entry-B.BASE:entry-B.BASE+0x44]
  suffix=bytearray(raw[entry+0x52-B.BASE:entry+0x8c-B.BASE])
  assert suffix[-2:]==bytes.fromhex('4e75')
  source+=f'\n.global transfer_{name}\ntransfer_{name}:\n .byte '+','.join(hex(x) for x in prefix)+'\n'
  source+=' lea -16(%sp),%sp\n movem.l %d0-%d1/%a0-%a1,(%sp)\n bsr.w transfer_ready\n tst.l %d0\n movem.l (%sp),%d0-%d1/%a0-%a1\n lea 16(%sp),%sp\n bne.w transfer_word_fail\n'
  # Keep original register restoration/output bytes; return explicit status.
  source+=' .byte '+','.join(hex(x) for x in suffix[:-2])+'\n moveq #0,%d0\n rts\n'
 # Existing wrappers serialize all mutations with a recursive lock. The load
 # delegate rejects a previously failed session before allocating or unloading.
 delegate=next(e for e in doc['sample_pool_lock']['entries'] if e['method']=='load')
 de=int(delegate['delegate'],16);before=bytes.fromhex(delegate['before'])
 source+='\n.global transfer_load_gate\ntransfer_load_gate:\n tst.l transfer_fault\n beq.s load_gate_ok\n moveq #-1,%d0\n rts\nload_gate_ok:\n move.l #0x80,%d0\n move.w %d0,0x8c00000a\n bsr.w transfer_ready\n tst.l %d0\n bne.s load_gate_reject\n .byte '+','.join(hex(x) for x in before)+f'\n jmp {int(loader["load"],16)+len(before):#x}\nload_gate_reject:\n moveq #-1,%d0\n rts\n'
 patches=[]
 for label,old,size,fail in [('after_unload',0x4015461c,10,'transfer_unload_failed'),('reuse',0x40154750,6,'transfer_reuse_failed'),('pcm',0x40154bd2,8,'transfer_load_failed'),('descriptor',0x40154c22,6,'transfer_load_failed')]:
  at=mapped(old);blob=bytes(payload[at-base:at-base+size]);assert len(blob)==size
  source+=f'\n.global transfer_check_{label}\ntransfer_check_{label}:\n tst.l transfer_fault\n bne.w {fail}\n .byte '+','.join(hex(x) for x in blob)+f'\n jmp {at+size:#x}\n'
  patches.append(dict(address=hex(at),before=blob.hex(),symbol='transfer_check_'+label,kind='load failure propagation'))
 # A transport failure leaves restore incomplete, but suppresses immediate
 # retries until reboot. This avoids hiding the failure or spinning the queue.
 poll=int(m['sample_restore_poll'],16);blob=bytes(payload[poll-base:poll-base+6]);assert blob[:2]==b'\x4e\xb9'
 source+='\n.global transfer_restore_gate\ntransfer_restore_gate:\n tst.l transfer_fault\n bne.s restore_gate_failed\n .byte '+','.join(hex(x) for x in blob)+f'\n jmp {poll+6:#x}\nrestore_gate_failed:\n rts\n'
 patches.append(dict(address=hex(poll),before=blob.hex(),symbol='transfer_restore_gate',kind='suppress retries after fault'))
 job=int(m['sample_restore_job'],16)
 needle=b'\x20\x39'+B.BE(eq['RESTORE_REQUESTED'])+b'\x23\xc0'+B.BE(eq['RESTORE_DONE'])
 ji=payload.find(needle,job-base,job-base+180);assert ji>=0
 source+='\n.global transfer_restore_finish\ntransfer_restore_finish:\n tst.l transfer_fault\n bne.s restore_finish_failed\n .byte '+','.join(hex(x) for x in needle)+f'\nrestore_finish_failed:\n jmp {base+ji+len(needle):#x}\n.balign 4\n'
 patches.append(dict(address=hex(base+ji),before=needle.hex(),symbol='transfer_restore_finish',kind='do not mark failed restore done'))
 out.mkdir(parents=True,exist_ok=False);payload.extend(B.R.assemble(source,start,out,'dsp-transfer-wait'))
 symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'dsp-transfer-wait.elf']))}
 patches.append(dict(address=hex(de),before=before.hex(),symbol='transfer_load_gate',kind='reject later loads before mutation'))
 for e in patches:
  at=int(e['address'],16);n=len(bytes.fromhex(e['before']));assert payload[at-base:at-base+n]==bytes.fromhex(e['before'])
  patch=b'\x4e\xf9'+B.BE(symbols[e['symbol']])+b'\x4e\x71'*((n-6)//2)
  payload[at-base:at-base+n]=patch;e['after']=patch.hex()
 assert base+len(payload)<=int(doc['runtime_limit'],16)
 image=bytearray(raw[:src-B.BASE])+payload
 for at,symbol in [(0x400cf178,'transfer_control'),(0x400cf204,'transfer_pcm'),(0x400cf9aa,'transfer_page')]:
  before=bytes(image[at-B.BASE:at-B.BASE+8]);assert before[:2]==b'\x4f\xef'
  after=b'\x4e\xf9'+B.BE(symbols[symbol])+b'\x4e\x71';image[at-B.BASE:at-B.BASE+8]=after
  patches.append(dict(address=hex(at),before=before.hex(),after=after.hex(),symbol=symbol,kind='bounded native transport'))
 boot=B.BASE+len(image);asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
 image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
 doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
 doc['dsp_transfer_wait']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('transfer_')},patches=patches,
  page_delay_budget=1000,delay_argument=1000,delay_native='0x4013464c',fault_lifetime='Until reboot; partial pages cannot safely resume',
  semantics='Shared finite delay budget per page, native timer wait yields; first fault releases transport lock; loader closes file, releases buffers, unloads its failed record, returns -1 before loaded metadata or notifications. Restore remains incomplete and automatic retries stop.',
  limits=['No hardware confirmation. Timer service is assumed operational; the fault being bounded is DSP readiness.',
          'Void unload/reset APIs retain local cleanup when DSP transport fails; subsequent loads remain prohibited until reboot.'])
 for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
 (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
 print(json.dumps({'main_sha256':doc['main_sha256'],'runtime_bytes':len(payload),'transfer':doc['dsp_transfer_wait']['methods']},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
