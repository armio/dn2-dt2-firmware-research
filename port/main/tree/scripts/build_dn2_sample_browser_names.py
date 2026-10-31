#!/usr/bin/env python3
"""Bound native sample-pool name readers to their 16-byte storage records.

The loader deliberately publishes fixed-width fields, not C strings. Keep that
storage ABI and all writers intact; create an owned string from a per-call,
terminated stack copy. This removes scans into neighbouring sample names.
"""
from pathlib import Path
import argparse
import json
import re
import shutil

import build_dn2_usb_fullmix as P

B = P.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-oneshot-init-t1e0-20261013'
# Exact released T1E0, including its ONESHOT shared-page defaults and USB42.
SHA = '28fa87afd36ee119c3183822920773761a2f611356ecc9a1757125a495f10eae'
NAME_GETTER = 0x47A60230
NAME_CALLBACK = 0x47A60104
EMPTY_STRLEN = 0x47A60022
RAW_CALLERS = (0x47A6001A, 0x47A6015E)


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT/'build-receipt.json').read_text())
    c = doc['runtime_copy']
    src, base = int(c['source'],16), int(c['destination'],16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']])
    getter_call = b'\x4e\xb9'+B.BE(NAME_GETTER)
    callers = tuple(base+n for n in range(len(payload)) if payload[n:n+6] == getter_call)
    assert callers == RAW_CALLERS, callers
    previous_end = base+len(payload)
    payload.extend(bytes(-len(payload)%4))
    entry = base+len(payload)
    asm = '''.text
.global sample_name_nonempty
.global sample_name_string
sample_name_nonempty:
 movea.l 4(%sp),%a0
 moveq #0,%d0
 tst.l %a0
 beq.s nonempty_done
 mvz.b (%a0),%d0
nonempty_done:
 rts

sample_name_string:
 link %a6,#-44
 movem.l %d2-%d4/%a2,(%sp)
 move.l %a0,%d2
 move.l 12(%a6),%d4
 cmpi.l #1023,%d4
 bhi.w name_invalid
 move.l %d4,%d0
 andi.l #127,%d0
 beq.w name_off
 move.l %d4,-(%sp)
 jsr 0x47a60230
 addq.l #4,%sp
 tst.l %d0
 beq.w name_empty
 movea.l %d0,%a0
 tst.b (%a0)
 beq.w name_empty
 lea -24(%a6),%a1
 moveq #16,%d1
name_copy:
 move.b (%a0)+,%d0
 move.b %d0,(%a1)+
 beq.s name_copied
 subq.l #1,%d1
 bne.s name_copy
 clr.b (%a1)
name_copied:
 lea -24(%a6),%a0
 bra.s name_construct
name_invalid:
 lea 0x47a624ec,%a0
 bra.s name_construct
name_off:
 lea 0x47a624b0,%a0
 bra.s name_construct
name_empty:
 lea 0x47a624b4,%a0
name_construct:
 pea -1(%a6)
 move.l %a0,-(%sp)
 move.l %d2,-(%sp)
 jsr 0x401ce69e
 lea 12(%sp),%sp
 move.l %d2,%d0
 movem.l (%sp),%d2-%d4/%a2
 unlk %a6
 rts
.balign 4
'''
    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(asm, entry, out, 'sample-browser-names')
    methods = {m[2]:int(m[1],16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'sample-browser-names.elf']))}
    payload.extend(code)
    patches=[]
    for at,before,after in (
        (EMPTY_STRLEN, bytes.fromhex('4eb94017ed4c'),
         b'\x4e\xb9'+B.BE(methods['sample_name_nonempty'])),
        (NAME_CALLBACK, bytes.fromhex('4fefffec48d7041c'),
         b'\x4e\xf9'+B.BE(methods['sample_name_string'])+b'\x4e\x71')):
        off=at-base
        assert payload[off:off+len(before)] == before
        payload[off:off+len(after)] = after
        patches.append(dict(address=hex(at), before=before.hex(), after=after.hex(),
                            file_offset=hex(src-B.BASE+off)))
    assert base+len(payload) <= int(doc['runtime_limit'],16)
    image=bytearray(raw[:src-B.BASE])+payload
    boot=B.BASE+len(image)
    old_bootstrap=(INPUT/'bootstrap.S').read_text()
    bootstrap=old_bootstrap.replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap != old_bootstrap
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    cfg=dict(base=str(INPUT/'main-os.bin'),base_sha256=SHA,
        code=hex(entry),code_bytes=len(code),previous_runtime_end=hex(previous_end),
        runtime_end=hex(base+len(payload)),methods={k:hex(v) for k,v in methods.items()},
        patches=patches,raw_name_getter=hex(NAME_GETTER),
        original_raw_getter_calls=[hex(x) for x in callers],
        name_pointer_table='0x47a604a0',name_records='0x47a7c100',record_bytes=16,
        string_callback=hex(NAME_CALLBACK),empty_callback='0x47a5ffea',
        native_string_constructor='0x401ce69e',local_buffer_bytes=17,
        ownership='Native basic_string constructor copies a maximum16-byte name from per-call stack storage.',
        preserves='All16 original name bytes, OFF/empty/invalid labels, pool storage/publication/clear/reuse, file formats, sample data, DSP, USB42 and ONESHOT defaults.',
        limits=['No device I/O or hardware timing test.'])
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**c,'bytes':len(payload)},bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_browser_names']=cfg
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(INPUT/name,out/name)
    print(json.dumps(dict(main_sha256=doc['main_sha256'],sample_browser_names=cfg),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    build(ap.parse_args().out)
