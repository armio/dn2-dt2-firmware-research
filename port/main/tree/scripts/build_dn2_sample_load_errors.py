#!/usr/bin/env python3
"""Report a latched DSP transport failure in both native DT2 disk pickers."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_directory_model as L
B=L.B


def build(folder,out):
    raw=(folder/'main-os.bin').read_bytes()
    doc=json.loads((folder/'build-receipt.json').read_text())
    assert B.T.SHA(raw)==doc['main_sha256']
    copy=doc['runtime_copy'];src=int(copy['source'],16);base=int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    assert len(payload)%4==0
    def mapped(old):
        for cfg in doc.values():
            if not isinstance(cfg,dict):continue
            for s in cfg.get('spans',[]):
                if not all(k in s for k in ('donor','end','runtime')):continue
                lo,hi=int(s['donor'],16),int(s['end'],16)
                if lo<=old<hi:return int(s['runtime'],16)+old-lo
        for e in doc['sample_manager']['edits']:
            if e['target']==hex(old):return int(e['binding'],16)
        raise AssertionError(hex(old))
    tm=doc['dsp_transfer_wait']['methods']
    manager_site=mapped(0x400294be);picker_site=mapped(0x4001dc40)
    manager_before=bytes(payload[manager_site-base:manager_site-base+6])
    picker_before=bytes(payload[picker_site-base:picker_site-base+10])
    old_message=mapped(0x40229a6a);project_load=int(doc['project_sample_load']['methods']['project_load'],16)
    assert manager_before==b'\x48\x79'+B.BE(old_message)
    assert picker_before==b'\x4e\xb9'+B.BE(project_load)+bytes.fromhex('4fef0010')
    # Reuse the linked manager's native dialog sequence, including its exact
    # local layout, ownership releases, presentation call and invalidation.
    # Every relative branch in this tail is internal to the copied tail.
    tail_start,tail_end=mapped(0x40029522),mapped(0x400295b6)
    tail=bytes(payload[tail_start-base:tail_end-base])
    assert tail[-10:]==bytes.fromhex('4cee1c0cffb44e5e4e75')
    eq=dict(TRANSFER_FAULT=int(tm['transfer_fault'],16),OLD_MESSAGE=old_message,
            MANAGER_RESUME=manager_site+6,PICKER_RESUME=picker_site+10,
            PROJECT_LOAD=project_load,CONTROLLER_GET=mapped(0x40198948),FORMAT=mapped(0x40000e82))
    asm='.text\n'+''.join(f'.equ {k},{v:#x}\n' for k,v in eq.items())+'''
.global sample_load_manager_message
sample_load_manager_message:
 tst.l TRANSFER_FAULT
 beq.s manager_original_error
 pea sample_load_transfer_error
 jmp MANAGER_RESUME
manager_original_error:
 pea OLD_MESSAGE
 jmp MANAGER_RESUME

.global sample_load_picker_result
sample_load_picker_result:
 jsr PROJECT_LOAD
 lea 16(%sp),%sp
 tst.b %d0
 bne.s picker_continue
 tst.l TRANSFER_FAULT
 beq.s picker_continue
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 bsr.w sample_load_error_dialog
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 16(%sp),%sp
picker_continue:
 jmp PICKER_RESUME

.global sample_load_error_dialog
sample_load_error_dialog:
 link.w %a6,#-76
 movem.l %d2-%d3/%a2-%a4,(%sp)
 lea CONTROLLER_GET,%a3
 move.l %a6,%d3
 addi.l #-40,%d3
 pea sample_load_transfer_error
 move.l %d3,-(%sp)
 jsr FORMAT
 addq.l #8,%sp
'''
    asm+=' .byte '+','.join(hex(x) for x in tail)+'\n'
    asm+='\n.global sample_load_transfer_error\nsample_load_transfer_error:\n .asciz "DSP TRANSFER FAILED"\n.balign 4\n'
    out.mkdir(parents=True,exist_ok=False)
    payload.extend(B.R.assemble(asm,base+len(payload),out,'sample-load-errors'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
             B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-load-errors.elf']))}
    patches=[]
    for at,before,symbol in [(manager_site,manager_before,'sample_load_manager_message'),
                             (picker_site,picker_before,'sample_load_picker_result')]:
        after=b'\x4e\xf9'+B.BE(symbols[symbol])+b'\x4e\x71'*((len(before)-6)//2)
        payload[at-base:at-base+len(before)]=after
        patches.append(dict(address=hex(at),before=before.hex(),after=after.hex(),symbol=symbol))
    marker=int(tm['transfer_identity'],16)
    assert struct.unpack_from('>I',payload,marker-base)[0]==0x54314437
    struct.pack_into('>I',payload,marker-base,0x54314438)
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload
    boot=B.BASE+len(image)
    bootstrap=(folder/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(folder/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
               runtime_copy={**copy,'bytes':len(payload)},bootstrap=hex(boot),
               bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_load_error_fix']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('sample_load_')},
        patches=patches,transfer_fault=hex(eq['TRANSFER_FAULT']),
        identity=dict(address=hex(marker),before='0x54314437',after='0x54314438'),
        donor_callbacks=dict(manager='0x40029466',picker='0x4001db7c'),
        runtime_callbacks=dict(manager=hex(mapped(0x40029466)),picker=hex(mapped(0x4001db7c))),
        copied_dialog_tail=dict(donor_start='0x40029522',donor_end='0x400295b6',runtime_start=hex(tail_start),bytes=len(tail),sha256=B.T.SHA(tail)),
        semantics='Manager zero-success message changes only for sticky DSP failure. Disk assignment picker shows the same native dialog only if project load returns false and DSP failure is latched. All prior picker cleanup and project identity decisions remain intact.',
        unchanged=['Nonfault manager messages','Successful assignment','Ordinary SYN RAM-slot selection','DSP transport and startup'])
    for name,data in [('main-os.bin',image),('runtime.bin',payload)]:(out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((folder/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],sample_load_error_fix=doc['sample_load_error_fix']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.folder,a.out)
