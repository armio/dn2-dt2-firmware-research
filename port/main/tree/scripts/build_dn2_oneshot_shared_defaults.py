#!/usr/bin/env python3
"""Reset shared sound pages only after an explicit UI change to ONESHOT.

The native Machine setter and saved Sound/project loaders are untouched. The
two existing UI commits retain their original model call, then apply the native
page-default routine to FLTR, AMP, track FX and the three LFO pages.
"""
from pathlib import Path
import argparse
import json
import re
import shutil

import build_dn2_usb_fullmix as P

B = P.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-usb-fullmix-20261013'
SHA = '27b9f5e9acfbbc4b18d7e7088679d91a79989cdd9332481efae4d8276878f01f'
SLOTS = [*range(1, 25), *range(66, 93), *range(95, 100)]
SITES = (0x4005BBA0, 0x40059658)


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT/'build-receipt.json').read_text())
    c = doc['runtime_copy']
    src, base = int(c['source'], 16), int(c['destination'], 16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']])
    previous_end = base+len(payload)
    payload.extend(bytes(-len(payload) % 4))
    entry = base+len(payload)
    # a6 frame: saved registers -300..-273; parameter vector -260..-37;
    # vector header -36..-25. No heap, global scratch or DSP work is introduced.
    asm = f'''.text
.global oneshot_ui_assign
oneshot_ui_assign:
 link %a6,#-300
 movem.l %d2-%d6/%a2-%a3,(%sp)
 moveq #-1,%d3
 suba.l %a2,%a2
 move.l 16(%a6),%d0
 cmpi.l #5,%d0
 bne.w assign_native
 move.l 20(%a6),%d0
 cmpi.l #1,%d0
 bne.w assign_native
 move.l 24(%a6),%d0
 cmpi.l #1,%d0
 bne.w assign_native
 move.l 12(%a6),%d0
 cmpi.l #15,%d0
 bhi.w assign_native
 move.l %d0,-(%sp)
 move.l 8(%a6),-(%sp)
 jsr 0x40030e66
 addq.l #8,%sp
 movea.l %d0,%a2
 tst.l %d0
 beq.w assign_native
 movea.l (%a2),%a0
 tst.l %a0
 beq.w assign_native
 movea.l 40(%a0),%a0
 tst.l %a0
 beq.w assign_native
 move.l %a2,-(%sp)
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.w assign_native
 movea.l %d0,%a0
 mvz.b 222(%a0),%d3
assign_native:
 move.l 24(%a6),-(%sp)
 move.l 20(%a6),-(%sp)
 move.l 16(%a6),-(%sp)
 move.l 12(%a6),-(%sp)
 move.l 8(%a6),-(%sp)
 jsr 0x40031880
 lea 20(%sp),%sp
 move.l %d0,%d5
 tst.b %d0
 beq.w assign_done
 cmpi.l #-1,%d3
 beq.w assign_done
 cmpi.l #5,%d3
 beq.w assign_done
 movea.l (%a2),%a0
 move.l %a2,-(%sp)
 movea.l 40(%a0),%a0
 jsr (%a0)
 addq.l #4,%sp
 tst.l %d0
 beq.w assign_done
 movea.l %d0,%a0
 mvz.b 222(%a0),%d0
 cmpi.l #5,%d0
 bne.w assign_done
 mvz.b 223(%a0),%d4
 lea -260(%a6),%a3
 move.l %a3,-36(%a6)
 lea shared_slots,%a0
 move.l %a0,%d2
 moveq #{len(SLOTS)},%d6
assign_collect:
 movea.l %d2,%a0
 mvz.b (%a0),%d0
 addq.l #1,%d2
 move.l %d4,-(%sp)
 pea 5
 move.l %d0,-(%sp)
 jsr 0x400dc02a
 lea 12(%sp),%sp
 tst.l %d0
 beq.s assign_next
 move.l %d0,(%a3)+
assign_next:
 subq.l #1,%d6
 bne.s assign_collect
 move.l %a3,-32(%a6)
 move.l %a3,-28(%a6)
 pea -36(%a6)
 move.l %a2,-(%sp)
 jsr 0x4004c3ce
 addq.l #8,%sp
assign_done:
 move.l %d5,%d0
 movem.l (%sp),%d2-%d6/%a2-%a3
 unlk %a6
 rts
.balign 4
shared_slots:
 .byte {','.join(map(str, SLOTS))}
.balign 4
'''
    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(asm, entry, out, 'oneshot-shared-defaults')
    payload.extend(code)
    methods = {m[2]:int(m[1],16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new', '-n', out/'oneshot-shared-defaults.elf']))}
    assert base+len(payload) <= int(doc['runtime_limit'],16)
    image = bytearray(raw[:src-B.BASE])+payload
    patches = []
    for at in SITES:
        before = bytes.fromhex('4eb940031880')
        after = b'\x4e\xb9'+B.BE(methods['oneshot_ui_assign'])
        assert image[at-B.BASE:at-B.BASE+6] == before
        image[at-B.BASE:at-B.BASE+6] = after
        patches.append(dict(address=hex(at), before=before.hex(), after=after.hex()))
    boot = B.BASE+len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text().replace(
        f'#{c["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    assert bootstrap != (INPUT/'bootstrap.S').read_text()
    image.extend(B.R.assemble(bootstrap, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+B.BE(boot)
    cfg = dict(base=str(INPUT/'main-os.bin'), base_sha256=SHA,
        code=hex(entry), code_bytes=len(code), previous_runtime_end=hex(previous_end),
        runtime_end=hex(base+len(payload)), methods={k:hex(v) for k,v in methods.items()},
        patches=patches, ui_sites=[hex(x) for x in SITES],
        native_model_assign='0x40031880', native_default_mapper='0x400dc02a',
        native_page_reset='0x4004c3ce', slots=SLOTS,
        reset_ranges={'MOD LFO1-3':[1,24], 'FLTR AMP track sends':[66,92], 'Track FX':[95,99]},
        selection_guard='Both explicit UI commit flags=1, valid track, old Machine !=5, successful model call, resulting Machine=5.',
        preserves='Chosen filter Machine; names; controller mappings; ARP; portamento; voices; trigs and locks; other Machine switches; already-ONESHOT selections; saved Sound/project loading; USB42; DSP.',
        defaults='Native defaults for selected filter Machine; AMP attack remains its native value8.',
        limits=['No hardware or flash performed.', 'Existing per-step locks can still override reset track-level values.'])
    doc.update(main_sha256=B.T.SHA(image), runtime_sha256=B.T.SHA(payload), bytes=len(image),
        runtime_copy={**c,'bytes':len(payload)}, bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    doc['oneshot_shared_defaults'] = cfg
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(INPUT/name,out/name)
    print(json.dumps(dict(main_sha256=doc['main_sha256'],oneshot_shared_defaults=cfg),indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    build(ap.parse_args().out)
