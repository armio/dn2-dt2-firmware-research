#!/usr/bin/env python3
"""Connect DT2 SLICES trig mode to DN2's native keyboard and note producer."""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_directory_model as L
B = L.B
INPUT = B.T.ROOT/'output/dn2-research/dn2-usb-capture-efficient-20261013'
SHA = '5f6c2dbdd6db75ceca1d728a2e062754d5bbb0b893641e1c2ad8b092c532a6ea'
DONOR = B.T.ROOT/'firmware/dt2-1.16/section_3_MAIN_OS.bin'


def led_clone(changes):
    start,end=0x4005da1c,0x4005dbe6
    dump=B.T.run([B.T.BIN/'binutils/objdump','-D','-b','binary','-m','m68k:cfv4e',
        '--adjust-vma=0x40000400',f'--start-address={start:#x}',f'--stop-address={end:#x}',DONOR])
    binds={0x40035cca:0x40030e66,0x40041d18:0x4003e40e,0x4004d958:0x400490e6,
        0x40041d24:0x4003e41a,0x4003618c:0x40031274,0x4005063e:'slice_donor_machine',
        0x4005c8e0:'slice_trig_count',0x4005b168:0x40056214,0x40030a26:0x4002c45e}
    lines=[]
    for line in dump.splitlines():
        m=re.match(r'^([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+(\S+)\s*(.*)$',line)
        if not m:continue
        at,op,args=int(m[1],16),m[3],m[4]
        lines.append(f'led_{at:x}:')
        if at in changes:lines.append(changes[at]);continue
        args=re.sub(r'%pc@\((0x[0-9a-f]+)\)',r'\1',args)
        if op.startswith('b') and re.fullmatch('0x[0-9a-f]+',args):
            dest=int(args,16);assert start<=dest<=end
            op=op[:-1]+'.w';args=f'led_{dest:x}'
        elif op=='jsr' and re.fullmatch('0x[0-9a-f]+',args):
            target=int(args,16);assert target in binds,(hex(at),args)
            to=binds[target];args=to if isinstance(to,str) else hex(to)
        elif op=='lea' and args.startswith('0x40030a26,'):args=args.replace('0x40030a26','0x4002c45e')
        lines.append(f' {op} {args}')
    lines.append(f'led_{end:x}:')
    return '\n'.join(lines)+'\n'


def build(out, parent=INPUT):
    raw=(parent/'main-os.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
    assert B.T.SHA(raw)==doc['main_sha256']
    if parent.resolve()==INPUT.resolve():assert B.T.SHA(raw)==SHA
    assert 'slice_trig_mode' not in doc and 'usb_capture_efficient' in doc
    c=doc['runtime_copy'];src,base=int(c['source'],16),int(c['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']]);payload.extend(bytes(-len(payload)%4))
    entry=base+len(payload)
    # Original DT2 LED branch retains its color, active-key, and bank logic.
    # Native Sound starts controls at20; shared slice selector is slot31.
    leds=led_clone({0x4005db24:'',0x4005db2a:'',0x4005db30:' addq.l #4,%sp',
        0x4005db32:' mvs.b 82(%a2),%d1'})
    asm=f'''.text
.global slice_trig_count,slice_trig_press,slice_trig_page,slice_trig_led,slice_trig_apply,slice_donor_machine,slice_trig_refresh
slice_trig_count:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 movea.l 16(%sp),%a2
 move.l 160(%a2),-(%sp)
 jsr 0x40046c2e
 move.l %d0,-(%sp)
 move.l 164(%a2),-(%sp)
 jsr 0x40030e66
 lea 12(%sp),%sp
 movea.l %d0,%a3
 movea.l (%a3),%a0
 move.l %a3,-(%sp)
 movea.l 40(%a0),%a0
 jsr (%a0)
 addq.l #4,%sp
 movea.l %d0,%a0
 mvz.b 222(%a0),%d0
 cmpi.l #9,%d0
 bne.s count_manual
 mvz.b 86(%a0),%d1
 cmpi.l #4,%d1
 bhi.s count_one
 moveq #4,%d0
 lsl.l %d1,%d0
 bra.s count_done
count_manual:
 cmpi.l #10,%d0
 bne.s count_one
 move.l 375(%a0),%d0
 ble.s count_one
 cmpi.l #64,%d0
 bls.s count_done
 moveq #64,%d0
 bra.s count_done
count_one:
 moveq #1,%d0
count_done:
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 rts
slice_donor_machine:
 movea.l 4(%sp),%a0
 move.l (%a0),%a1
 move.l %a0,-(%sp)
 movea.l 40(%a1),%a1
 jsr (%a1)
 addq.l #4,%sp
 movea.l %d0,%a0
 mvz.b 222(%a0),%d0
 cmpi.l #9,%d0
 beq.s donor_grid
 cmpi.l #10,%d0
 beq.s donor_slice
 moveq #0,%d0
 rts
donor_grid:
 moveq #4,%d0
 rts
donor_slice:
 moveq #6,%d0
 rts
/* Original DT2 KeyboardView model callback4005c958 clamps obsolete pages
 * when current Sound/grid changes, then delegates to native redraw. */
slice_trig_refresh:
 lea -12(%sp),%sp
 movem.l %d2/%a2-%a3,(%sp)
 movea.l 16(%sp),%a0
 movea.l (%a0),%a0
 movea.l (%a0),%a2
 move.l 148(%a2),-(%sp)
 jsr 0x4003e40e
 movea.l %d0,%a3
 move.l %d0,-(%sp)
 jsr 0x40049068
 addq.l #8,%sp
 cmpi.l #4,%d0
 bne.s refresh_done
 move.l %a3,-(%sp)
 jsr 0x400490e6
 move.l %a2,-(%sp)
 move.l %d0,%d2
 bsr.w slice_trig_count
 addq.l #8,%sp
 addi.l #15,%d0
 lsr.l #4,%d0
 cmp.l %d2,%d0
 bhi.s refresh_done
 tst.l %d2
 beq.s refresh_done
 clr.l -(%sp)
 move.l %a3,-(%sp)
 jsr 0x40049116
 addq.l #8,%sp
refresh_done:
 move.l %a2,16(%sp)
 movem.l (%sp),%d2/%a2-%a3
 lea 12(%sp),%sp
 jmp 0x4011c7f2
slice_trig_press:
 move.l %a2,-(%sp)
 bsr.w slice_trig_count
 addq.l #4,%sp
 cmp.l %a4,%d0
 blt.s press_reject
 jmp 0x400583da
press_reject:
 jmp 0x4005859e
slice_trig_page:
 move.l 148(%a2),-(%sp)
 jsr 0x4003e40e
 move.l %d0,-(%sp)
 jsr 0x400490e6
 move.l %d0,-(%sp)
 move.l %a2,-(%sp)
 bsr.w slice_trig_count
 move.l %d0,%d1
 addi.l #15,%d1
 lsr.l #4,%d1
 move.l 4(%sp),%d0
 addq.l #1,%d0
 cmp.l %d1,%d0
 bcs.s page_valid
 moveq #0,%d0
page_valid:
 lea 16(%sp),%sp
 move.l %d0,-(%sp)
 move.l 148(%a2),-(%sp)
 jsr 0x4003e40e
 addq.l #4,%sp
 move.l %d0,-(%sp)
 jsr 0x40049116
 addq.l #8,%sp
 jmp 0x40058750
slice_trig_led:
 cmpi.l #4,%d4
 beq.s led_slices
 moveq #1,%d0
 cmp.l %d4,%d0
 beq.s led_velocity
 jmp 0x4005909c
led_velocity:
 jmp 0x4005911a
led_slices:
 move.l -144(%fp),-(%sp)
 lea -60(%sp),%sp
 movem.l %d0-%d7/%a0-%a6,(%sp)
 lea 0x4002c42e,%a4
 lea 0x4002c318,%a3
 /* Donor expects active track in D3 until its first sound lookup. */
 move.l %d6,%d3
''' + leds + '''
 movem.l (%sp),%d0-%d7/%a0-%a6
 lea 60(%sp),%sp
 move.l (%sp)+,-144(%fp)
 jmp 0x4005920a
/* DT2 native producer4002e5dc..4002e644 applies Note::slice after
 * ordinary locks and invalidates the cached Sound for the next note.
 * DN2 carries Note::slice into scheduler+100 but omitted this consumer. */
slice_trig_apply:
 lea -20(%sp),%sp
 movem.l %d0-%d2/%a0-%a1,(%sp)
 movea.l -36(%fp),%a0
 move.l 100(%a0),%d1
 ble.s apply_done
 cmpi.l #64,%d1
 bhi.s apply_done
 move.l #153,%d0
 mulu.l %d2,%d0
 lea 0x8000487c,%a1
 mvz.b (%a1,%d0.l),%d0
 cmpi.l #9,%d0
 beq.s apply_slice
 cmpi.l #10,%d0
 bne.s apply_done
apply_slice:
 lsl.l #8,%d1
 move.l #202,%d0
 mulu.l %d2,%d0
 lea 0x80003b50,%a1
 move.w %d1,(%a1,%d0.l)
 pea 31
 move.l %d1,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x400daf16
 lea 12(%sp),%sp
 lea 0x800052a8,%a0
 clr.l (%a0,%d2.l*4)
apply_done:
 movem.l (%sp),%d0-%d2/%a0-%a1
 lea 20(%sp),%sp
 clr.l 0x4058e550
 jmp 0x40026c44
.balign 4
.global slice_trig_modes
slice_trig_modes:
 .long 0,1,2,3,4
'''
    out.mkdir(parents=True,exist_ok=True)
    code=B.R.assemble(asm,entry,out,'slice-trig-mode');payload.extend(code)
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'slice-trig-mode.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload;patches=[]
    def patch(at,before,after):
        assert image[at-B.BASE:at-B.BASE+len(before)]==before,hex(at)
        assert len(before)==len(after)
        image[at-B.BASE:at-B.BASE+len(before)]=after
        patches.append(dict(address=hex(at),before=before.hex(),after=after.hex()))
    for at in (0x400582fa,0x40058a7e,0x4007332e,0x400734fa):patch(at,B.BE(1024),B.BE(4))
    patch(0x4004909a,b'\x70\x03',b'\x70\x04')
    for at in (0x400739e4,0x400739ea):patch(at,b'\x00\x10',b'\x00\x14')
    patch(0x400739ee,B.BE(0x401e2a08),B.BE(symbols['slice_trig_modes']))
    patch(0x40073a2a,b'\x70\x04',b'\x70\x05')
    for at,hx,name in (
        (0x400574b8,'206f00042050','slice_trig_refresh'),
        (0x400574c8,'206f00042050','slice_trig_refresh'),
        (0x400583cc,'7001b08c6d0001cc','slice_trig_press'),
        (0x40058a86,'2f2a00944e93','slice_trig_page'),
        (0x40059096,'7001b084677e','slice_trig_led'),
        (0x40026c3e,'42b94058e550','slice_trig_apply')):
        before=bytes.fromhex(hx);after=b'\x4e\xf9'+B.BE(symbols[name])+b'\x4e\x71'*((len(before)-6)//2)
        patch(at,before,after)
    boot=B.BASE+len(image)
    bootstrap=(parent/'bootstrap.S').read_text().replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap!=(parent/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**c,'bytes':len(payload)},bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['slice_trig_mode']=dict(parent=str(parent),parent_sha256=B.T.SHA(raw),code=hex(entry),code_bytes=len(code),
        methods={k:hex(v) for k,v in symbols.items() if k.startswith('slice_')},patches=patches,
        mode=4,donor_leds=['0x4005da1c','0x4005dbe6'],donor_apply=['0x4002e5dc','0x4002e644'],
        preserves='Native DN2 pool, keyboard polyphony, source64 note ABI, note off and existing live-record path.',
        limits=['Hardware key/LED/paging/live-record validation pending.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for n in ['fn_new_map.txt','ram_map.txt']:(out/n).write_bytes((parent/n).read_bytes())
    print(json.dumps({'main_sha256':doc['main_sha256'],'slice_trig_mode':doc['slice_trig_mode']},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,default=INPUT);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.out,a.input)
