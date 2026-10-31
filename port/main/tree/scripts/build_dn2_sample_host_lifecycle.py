#!/usr/bin/env python3
"""Install the DT2 sample request handler beside DN2's stock data handler."""
from pathlib import Path
import argparse,json,re,struct,tempfile
import build_dt2_directory_model as L
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-host-20261010'
SHA='5909017e1bd159a8d160ad6ab12572edfdb61f1ce834ee1582d761a556517dc6'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_host_enumerator';L.LIMIT=0x47ab0000
    L.CODE=[('enumerator',0x40127b74,0x40127be8),
        ('upload_callback_invokers',0x40032c36,0x40032c58),
        ('upload_callback_managers',0x40032ff2,0x40033096)]
    L.DATA=[('upload_callback_types',0x401f1020,0x401f1030)]
    L.EXTRA_DATA={};L.EXTRA_CODE=[];L.EXTRA_STATE=[];L.EXTRA_TYPED_DATA=[]
    L.EXTRA_SPANS=[];bindings={}
    for part in doc.values():
        if not isinstance(part,dict) or 'spans' not in part:continue
        L.EXTRA_SPANS[0:0]=part['spans']
        for e in part.get('edits',[]):
            if 'target' in e and 'binding' in e:bindings[int(e['target'],16)]=int(e['binding'],16)
    # Full progress-control body and adjacent redraw setter/getter pair match
    # native. The pair disambiguates an unrelated, byte-identical USB setter.
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes();proof=[]
    globals={0x409664f8:0x4058e550,0x409664f0:0x4058e548,0x409664f4:0x4058e54c,0x44f395e0:0x4464a590}
    for lo,hi,new in [(0x4002dcb2,0x4002dce2,0x40027bdc),(0x400d8dfa,0x400d8e14,0x400dac90)]:
        blob=bytearray(donor[lo-B.BASE:hi-B.BASE])
        for operand,target,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,lo,hi)):
            struct.pack_into('>I',blob,operand-lo,globals[target])
        assert blob==native[new-B.BASE:new-B.BASE+len(blob)],hex(lo)
        bindings[lo]=new;proof.append(dict(donor=hex(lo),native=hex(new),bytes=hi-lo))
    registration='''.text
 link.w %a6,#-16
 tst.l 0x44f2bc60
 bne.w callbacks_done
'''
    for dest,manager,invoke in [(0x44f2bc58,0x40032ff2,0x40032c36),(0x44f2bc48,0x40033044,0x40032c42)]:
        registration+=f'''
 pea 1.w
 jsr 0x4011e8f0
 addq.l #4,%sp
 move.l %d0,-16(%a6)
 clr.l -12(%a6)
 move.l #{manager:#x},%d0
 move.l %d0,-8(%a6)
 move.l #{invoke:#x},%d0
 move.l %d0,-4(%a6)
 pea -16(%a6)
 pea {dest:#x}
 jsr 0x4019f3b2
 pea -16(%a6)
 jsr 0x40197a04
 lea 12(%sp),%sp
'''
    registration+='callbacks_done:\n unlk %a6\n rts\n .balign 4\n'
    with tempfile.TemporaryDirectory(prefix='host-callbacks-') as tmp:
        L.EXTRA_CODE=[('callbacks_register',0x47f02000,B.R.assemble(registration,0x47f02000,Path(tmp),'register'))]
    L.EXTRA_BINDINGS=bindings;L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True
    L.INFER_NATIVE_LIBRARY_OPERANDS=False;L.METHODS={'constructor':0x40127b94,'callbacks_init':0x47f02000}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text());raw=(out/'main-os.bin').read_bytes()
    def at(old):
        for component in ('sample_host','directory_model'):
            for s in doc[component]['spans']:
                lo,hi=int(s['donor'],16),int(s['end'],16)
                if lo<=old<hi:return int(s['runtime'],16)+old-lo
        raise ValueError(hex(old))
    copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);start=base+len(payload)
    constants={'WRITER_INIT':at(0x40127a56),'WRITER_DESTROY':at(0x40127d5c),
        'ENUM_INIT':int(doc['sample_host_enumerator']['methods']['constructor'],16),
        'DIRECTORY_INIT':at(0x40159ca0),'DIRECTORY_DESTROY':at(0x40159ee0),
        'SAMPLE_DISPATCH':int(doc['sample_host']['methods']['dispatch'],16),
        'CALLBACKS_INIT':int(doc['sample_host_enumerator']['methods']['callbacks_init'],16),
        'FS_STATUS':int(doc['sample_fs_startup']['methods']['sample_fs_status'],16)}
    source=''.join(f'.equ {k},{v:#x}\n' for k,v in constants.items())
    source+=(B.T.ROOT/'scripts/asm/dn2_sample_host_lifecycle_initial.S').read_text()
    payload.extend(B.R.assemble(source,start,out,'sample-host-lifecycle'))
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-host-lifecycle.elf']))}
    assert base+len(payload)<=L.LIMIT
    image=bytearray(raw[:src-B.BASE])+payload
    assert image[0x4012693e-B.BASE:0x40126944-B.BASE]==bytes.fromhex('4eb940128a9a')
    image[0x4012693e-B.BASE:0x40126944-B.BASE]=b'\x4e\xb9'+B.BE(symbols['sample_host_route'])
    assert image[0x4012549a-B.BASE:0x401254a2-B.BASE]==bytes.fromhex('2f0b2f0a246f000c')
    image[0x4012549a-B.BASE:0x401254a2-B.BASE]=b'\x4e\xf9'+B.BE(symbols['sample_host_native_destroy'])+b'\x4e\x71'
    boot=B.BASE+len(image)
    asm=(out/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},
        runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_host']['live_hook_installed']=True
    doc['file_output_stream']['application_callbacks_registered']=True
    doc['file_output_stream']['transfer_dispatch_connected']=True
    doc['sample_file']['transfer_dispatch_connected']=True
    doc['sample_host_lifecycle']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('sample_host_')},
        native_dispatch_call='0x4012693e',native_data_handler='0x40128a9a',native_destroy='0x4012549a',
        state_bytes=0x19c,entry_bytes=0x1a4,constants={k:hex(v) for k,v in constants.items()},
        callback_native_evidence=proof,upload_callbacks_registered=True,
        limits=['Native RPC-worker serialization assumed; pending asynchronous jobs and owner teardown need composition.',
                'Wire parsing/capability advertisement, pool assignment and hardware remain untested.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),lifecycle=doc['sample_host_lifecycle']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
