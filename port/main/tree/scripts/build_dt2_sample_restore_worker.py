#!/usr/bin/env python3
"""Port DT2 restore worker with private flags and native project access."""
from pathlib import Path
import argparse,json,re,struct,tempfile
import build_dt2_directory_model as L
import build_dt2_waveform_events as W
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-restore-order-20261009'
SHA='69b6229d51fca681d6acd9da883c379fcc6717a2e93b40f2387ce4486c81f89f'
PROXY,VT,RAW,INIT=0x47f11200,0x47f11000,0x47f10000,0x47f10100

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    bindings={};spans=[]
    for key in ('sample_loader','sample_allocator','pcm_pages','waveform_events','sample_restore_order','sample_reset'):
        spans[0:0]=doc[key]['spans']
        for e in doc[key]['edits']:bindings[int(e['target'],16)]=int(e['binding'],16)
    bindings.update(W.BINDINGS)
    bindings.update({0x400f0d30:0x400f270c,0x43176e8c:0x42c6d278,0x43176e38:0x42c6d224,
        0x40215de0:0x401ff7b4,0x40215df0:0x401ff7c4,0x400f085e:0x400f223a,
        0x40001354:0x40001354,0x40046f30:0x40046f30})
    evidence=[]
    for lo,hi,to in ((0x400f0d30,0x400f0d6e,0x400f270c),(0x400f085e,0x400f0868,0x400f223a)):
        blob=bytearray(donor[lo-B.BASE:hi-B.BASE])
        for operand,target,_,_ in B.M.operands(B.M.S.disasm(donor,B.BASE,lo,hi)):
            struct.pack_into('>I',blob,operand-lo,bindings[target])
        assert blob==native[to-B.BASE:to+hi-lo-B.BASE]
        evidence.append(dict(donor=hex(lo),native=hex(to),bytes=hi-lo))
    # Find the dedicated priority3 executor factory, constrained by its fully
    # verified constructor and the previously verified allocation/RAII APIs.
    lo,hi=0x4019e380,0x4019e41c;blob=donor[lo-B.BASE:hi-B.BASE]
    refs=list(B.M.operands(B.M.S.disasm(donor,B.BASE,lo,hi)));mask=bytearray(b'\1'*len(blob))
    for at,_,_,_ in refs:mask[at-lo:at-lo+4]=bytes(4)
    pattern=b''.join(re.escape(bytes([b])) if keep else b'.' for b,keep in zip(blob,mask))
    matches=[]
    for m in re.finditer(pattern,native,re.S):
        at=B.BASE+m.start()
        if at%2==0 and all(target not in bindings or struct.unpack_from('>I',native,m.start()+p-lo)[0]==bindings[target] for p,target,_,_ in refs):matches.append(at)
    assert len(matches)==1,matches
    factory=matches[0];bindings[lo]=factory
    for operand,target,_,_ in refs:bindings[target]=struct.unpack_from('>I',native,factory-B.BASE+operand-lo)[0]
    evidence.append(dict(donor=hex(lo),native=hex(factory),bytes=hi-lo))
    raw_get=int(doc['project_sample_active']['methods']['sample_project_settings_raw'],16)
    collect=int(doc['sample_restore_order']['methods']['collect'],16)
    bindings[raw_get]=raw_get;bindings[collect]=collect
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='sample_restore_worker';L.LIMIT=0x47aa0000
    L.CODE=[('worker',0x4004e8be,0x4004eafa),('capture_manager',0x4004a8fe,0x4004a95a)]
    L.DATA=[('capture_type',0x401f4708,0x401f4710)]
    L.EXTRA_TYPED_DATA=[('proxy_vtable',VT,bytes(40)+B.BE(RAW))]
    L.EXTRA_STATE=[('proxy',PROXY,PROXY+0xb0)]
    L.EXTRA_DATA={};L.EXTRA_SPANS=spans;L.EXTRA_BINDINGS=bindings
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    raw_source=f'.equ settings_raw,{raw_get:#x}\n'+(B.T.ROOT/'scripts/asm/dn2_sample_restore_proxy.S').read_text()
    pattern_source='''.text
 movea.l 4(%sp),%a0
 move.l 0xac(%a0),4(%sp)
 jmp 0x40046f30
'''
    collect_source=f'''.text
 lea -8(%sp),%sp
 movem.l %a2-%a3,(%sp)
 movea.l 12(%sp),%a2
 movea.l 8(%a2),%a3
 move.l 0xac(%a3),8(%a2)
 move.l %a2,-(%sp)
 jsr {collect:#x}
 addq.l #4,%sp
 move.l %a3,8(%a2)
 movem.l (%sp),%a2-%a3
 addq.l #8,%sp
 rts
'''
    init_source=f'''.text
 lea {PROXY:#x},%a0
 tst.b 0xa9(%a0)
 bne.s busy
 move.l #{VT:#x},(%a0)
 move.l 4(%sp),0xac(%a0)
 move.l %a0,%d0
 rts
busy:
 moveq #0,%d0
 rts
 .balign 4
'''
    with tempfile.TemporaryDirectory(prefix='sample-restore-worker-') as temp:
        t=Path(temp)
        L.EXTRA_CODE=[(name,at,B.R.assemble(source,at,t,name)) for name,at,source in
            [('proxy_raw',RAW,raw_source),('proxy_pattern',0x4004aeea,pattern_source),
             ('proxy_collect',0x4004e598,collect_source),('proxy_init',INIT,init_source)]]
    L.METHODS={'restore':0x4004e8be,'job':0x4004eae4,'proxy_raw':RAW,
        'proxy_init':INIT,'proxy_pattern':0x4004aeea,'proxy_collect':0x4004e598}
    L.build(out)
    receipt=json.loads((out/'build-receipt.json').read_text());cfg=receipt['sample_restore_worker']
    cfg.update(native_executor=hex(factory),native_constructor='0x400f270c',native_enqueue='0x400f2494',
        native_worker='0x400f2334',native_twins=evidence,
        proxy=next(s['runtime'] for s in cfg['spans'] if s['name']=='proxy'),
        connected_to_lifecycle=False,
        limits=['Boot/project switching must request restore and cancel previous work at valid lifecycle boundaries.',
                'Private proxy supports one active restore; no physical scheduler validation yet.'])
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=receipt['main_sha256'],methods=cfg['methods'],native_executor=cfg['native_executor'],proxy=cfg['proxy']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);build(p.parse_args().out)
