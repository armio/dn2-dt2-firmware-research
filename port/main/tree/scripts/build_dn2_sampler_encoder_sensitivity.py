#!/usr/bin/env python3
"""Restore DT2 sampler encoder modes and slow normal discrete selections."""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_sample_preview as P

B = P.B
INPUT = B.T.ROOT/'output/dn2-research/dn2-preview-audio-identity-20261010'
SHA = '820db492ee661e66124e362156cbacfef916d404bc1a99e16f2a2a37a3ca98c8'
GETTER = 0x400c2418
ROW_BYTES = 100  # 68-byte borrowed companion, 28-byte config, initialized word
CONFIGS = {
    0x44d2e670: (0x401112b8,0x40112c2c,60,(0x01000100,18,1,1,2,3,1)),
    0x44d2e654: (0x401112f4,0x40112c68,50,(0x01010100,2,3,1,2,3,4)),
    0x44d2e61c: (0x40111354,0x40112cc8,44,(0x00010100,0,6,1,0,6,4)),
}


def donor_headers(donor):
    """Read the donor's straight-line companion initializer, not slot aliases."""
    regs, source, result = {}, None, {}
    for at,hx,mn,ops in B.M.S.disasm(donor,B.BASE,0x401bdee2,0x401c33c0):
        args = ops.split(', ')
        if len(args)==2 and args[1] in ('d0','d1','d2','d3','d4','d5','d6','d7','a0','a1','a2','a3','a4','a5','a6'):
            src,dest=args
            if mn in ('move.l','movea.l'):
                if src.startswith('#$'):
                    regs[dest]=int(src[2:],16)
                elif src in regs:
                    regs[dest]=regs[src]
            elif mn=='lea.l' and re.fullmatch(r'\$[0-9a-f]+\.l',src):
                regs[dest]=int(src[1:-2],16)
        if mn=='move.l' and ops.endswith(', -(a7)'):
            source=regs.get(args[0])
        if mn=='pea.l' and re.fullmatch(r'\$429[0-9a-f]+\.l',ops):
            dest=int(ops[1:-2],16)
            index=(dest-0x4293c044)//68
            if dest==0x4293c044+68*index and 200<=index<=254:
                assert source in range(0x40209f38,0x40209fa8,16),(index,source)
                words=struct.unpack_from('>4I',donor,source-B.BASE)
                result[index]=dict(initializer=hex(at),source=hex(source),words=list(words))
    assert set(result)==set(range(200,255))
    assert result[203]['words']==[1,8,0,0x44d2e61c],result[203]
    assert result[252]['words']==[1,8,0,0x44d2e61c]
    assert result[251]['words']==[1,4,0,0x429409f4]
    return result


def parameter_rows(doc,donor):
    headers=donor_headers(donor)
    controls=json.loads((B.T.ROOT/'output/dn2-research/dt2-sampler-table-complete-records-20261009/controls.json').read_text())
    rows=[]
    for machine in controls['machines']:
        for rec in machine['records']:
            if rec['visible'] and rec['short']!='SAMP':
                rows.append(dict(machine=machine['machine'],donor_id=rec['donor_id'],native_id=rec['entry'],name=rec['short']))
    for old in range(202,210):
        if old==205:
            continue
        names={202:'TUNE',203:'PLAY',204:'BR',206:'STRT',207:'LEN',208:'LOOP',209:'LEV'}
        rows.append(dict(machine='ONESHOT',donor_id=old,native_id=doc['source_parameters']['records'][str(old)]['native'],name=names[old]))
    assert len({r['native_id'] for r in rows})==len(rows)
    for r in rows:
        old=r['donor_id'];h=headers[old]
        ptr=h['words'][3]
        assert ptr in CONFIGS,(old,hex(ptr))
        values=list(CONFIGS[ptr][3])
        scale=1
        if r['name']=='PLAY':
            scale=4
        elif r['name'] in ('SEG','MODE','BARS','GRID'):
            scale=2
        elif r['name']=='LEN' and r['machine'] in ('ONESHOT','STRETCH','REPITCH'):
            scale=2
        changed=values.copy();changed[2]*=scale
        r.update(donor_header=h,donor_config=hex(ptr),donor_generator=hex(CONFIGS[ptr][0]),
                 native_generator=hex(CONFIGS[ptr][1]),original_config=values,config=changed,
                 normal_divisor_factor=scale,normal_event_multiplier=h['words'][0],pressed_event_multiplier=h['words'][1],
                 normal_divisor=changed[2],pressed_divisor=changed[5])
    return sorted(rows,key=lambda r:r['native_id']),headers


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    donor,native=B.M.S.DONOR.read_bytes(),B.M.RECIPIENT.read_bytes()
    for old,new,size,values in CONFIGS.values():
        assert donor[old-B.BASE:old-B.BASE+size]==native[new-B.BASE:new-B.BASE+size]
    rows,headers=parameter_rows(doc,donor)
    copy=doc['runtime_copy'];src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray((INPUT/'runtime.bin').read_bytes())
    previous=struct.unpack_from('>I',raw,GETTER+2-B.BASE)[0]
    assert raw[GETTER-B.BASE:GETTER-B.BASE+2]==b'\x4e\xf9'
    row_base=base+len(payload)
    for i,r in enumerate(rows):
        at=row_base+i*ROW_BYTES
        r.update(companion=hex(at),config_address=hex(at+68))
        payload.extend(bytes(68)+struct.pack('>7I',*r['config'])+bytes(4))
    lookup=base+len(payload);indices={r['native_id']:i+1 for i,r in enumerate(rows)}
    payload.extend(b''.join(struct.pack('>H',indices.get(n,0)) for n in range(368)))
    numeric=base+len(payload)
    for r in rows:
        payload.extend(struct.pack('>4I',*r['donor_header']['words'][:3],int(r['config_address'],16)))
    entry=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    asm=f'''.text
.global sampler_encoder_companion
sampler_encoder_companion:
 move.l 4(%sp),%d0
 cmpi.l #367,%d0
 bhi.w stock_companion
 lea {lookup:#x},%a0
 mvz.w (%a0,%d0.l*2),%d1
 tst.l %d1
 beq.w stock_companion
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 subq.l #1,%d1
 move.l %d1,%d2
 move.l #100,%d0
 mulu.l %d0,%d1
 lea {row_base:#x},%a2
 adda.l %d1,%a2
 tst.l 96(%a2)
 bne.s initialized
 move.l 16(%sp),-(%sp)
 jsr {previous:#x}
 addq.l #4,%sp
 movea.l %d0,%a0
 movea.l %a2,%a1
 moveq #17,%d0
copy_companion:
 move.l (%a0)+,(%a1)+
 subq.l #1,%d0
 bne.s copy_companion
 lsl.l #4,%d2
 lea {numeric:#x},%a0
 adda.l %d2,%a0
 move.l (%a0)+,4(%a2)
 move.l (%a0)+,8(%a2)
 move.l (%a0)+,12(%a2)
 move.l (%a0)+,16(%a2)
 moveq #1,%d0
 move.l %d0,96(%a2)
initialized:
 move.l %a2,%d0
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
stock_companion:
 jmp {previous:#x}
.balign 4
'''
    payload.extend(B.R.assemble(asm,entry,out,'sampler-encoder-companion'))
    assert len(payload)%4==0 and base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload
    before=bytes(image[GETTER-B.BASE:GETTER-B.BASE+6]);after=b'\x4e\xf9'+B.BE(entry)
    image[GETTER-B.BASE:GETTER-B.BASE+6]=after
    boot=B.BASE+len(image)
    source=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(source,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),runtime_copy={**copy,'bytes':len(payload)},
               runtime_sha256=B.T.SHA(payload),bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['encoder_sensitivity']=dict(base=str((INPUT/'main-os.bin').resolve()),base_sha256=SHA,
        entry=hex(entry),previous_getter=hex(previous),hook=dict(site=hex(GETTER),before=before.hex(),after=after.hex()),
        row_base=hex(row_base),row_stride=ROW_BYTES,lookup=hex(lookup),numeric=hex(numeric),rows=rows,
        donor_headers=headers,native_engine='0x4011336e',native_event_scaler='0x4011313e',
        semantics='Borrow persistent native companion callbacks into isolated per-parameter rows; restore DT2 numeric defaults/configs. Scale normal divisor only; exact donor pressed multiplier/triple and native FUNC dispatch retained.',
        unchanged=['Stock Machine companions','SAMP browser control','Hidden SLOT/BANK/CFADE/REPITCH TUNE','Parameter values/ranges/locks','DSP/audio'],
        limits=['Hardware encoder feel remains to be confirmed.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),parameters=len(rows),
        tuning=[{k:r[k] for k in ('machine','name','native_id','normal_divisor','normal_divisor_factor')} for r in rows]),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
