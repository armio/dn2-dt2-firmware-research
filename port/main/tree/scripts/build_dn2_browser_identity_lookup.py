#!/usr/bin/env python3
"""Avoid repeated virtual/project lookups for native pool identity annotations.

The native pool uses a fixed1024-entry active identity table. Resolve that table
once per lookup, then compare exactly the two words used by the donor comparator.
Other directory implementations and invalid project state retain the original.
"""
from pathlib import Path
import argparse
import json
import re
import shutil

import build_dn2_usb_fullmix as P
B = P.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-sample-browser-names-20261013'
SHA = '5a5f986ffc23ea3346fe3c8b4af2cd5f3f4661b0494c17066b726c6374bc383d'
ENTRY = 0x47A70794
BEFORE = bytes.fromhex('4fefffd448d73c1c')
POOL_VTABLE = 0x47A6026C


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT/'build-receipt.json').read_text())
    c = doc['runtime_copy']
    src, base = int(c['source'],16), int(c['destination'],16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+c['bytes']])
    assert payload[ENTRY-base:ENTRY-base+len(BEFORE)] == BEFORE
    previous_end = base+len(payload)
    payload.extend(bytes(-len(payload)%4))
    code_start = base+len(payload)
    asm = '''.text
.global browser_identity_lookup
.global browser_identity_original
browser_identity_lookup:
 movea.l 4(%sp),%a0
 tst.l %a0
 beq.w browser_identity_original
 move.l (%a0),%d0
 cmpi.l #0x47a6026c,%d0
 bne.w browser_identity_original
 link %a6,#-16
 movem.l %d2-%d4/%a2,(%sp)
 /* Preserve the native current-Project getter and active-owner validation. */
 jsr 0x4018a97a
 addi.l #0x30,%d0
 move.l %d0,-(%sp)
 jsr 0x47a75a02
 addq.l #4,%sp
 tst.l %d0
 beq.w identity_invalid_state
 movea.l %d0,%a2
 adda.l #0x1d2,%a2
 /* Original ABI: directory followed by four by-value identity words.
    The native comparator ignores words0/3; words1/2 determine equality. */
 move.l 16(%a6),%d3
 move.l 20(%a6),%d4
 moveq #0,%d2
identity_scan:
 cmp.l 4(%a2),%d3
 bne.s identity_next
 cmp.l 8(%a2),%d4
 beq.s identity_done
identity_next:
 lea 16(%a2),%a2
 addq.l #1,%d2
 cmpi.l #1024,%d2
 bcs.s identity_scan
 moveq #-1,%d2
identity_done:
 move.l %d2,%d0
 movem.l (%sp),%d2-%d4/%a2
 unlk %a6
 rts
identity_invalid_state:
 movem.l (%sp),%d2-%d4/%a2
 unlk %a6
browser_identity_original:
 lea -44(%sp),%sp
 movem.l %d2-%d4/%a2-%a5,(%sp)
 jmp 0x47a7079c
.balign 4
'''
    out.mkdir(parents=True,exist_ok=False)
    code = B.R.assemble(asm,code_start,out,'browser-identity-lookup')
    methods = {m[2]:int(m[1],16) for m in re.finditer(
        r'(?m)^([0-9a-f]+) [Tt] (\w+)$',
        B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'browser-identity-lookup.elf']))}
    payload.extend(code)
    after = b'\x4e\xf9'+B.BE(methods['browser_identity_lookup'])+b'\x4e\x71'
    payload[ENTRY-base:ENTRY-base+len(after)] = after
    assert base+len(payload) <= int(doc['runtime_limit'],16)
    image = bytearray(raw[:src-B.BASE])+payload
    boot = B.BASE+len(image)
    old_bootstrap = (INPUT/'bootstrap.S').read_text()
    bootstrap = old_bootstrap.replace(f'#{c["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    assert bootstrap != old_bootstrap
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+B.BE(boot)
    cfg = dict(base=str(INPUT/'main-os.bin'),base_sha256=SHA,
        code=hex(code_start),code_bytes=len(code),previous_runtime_end=hex(previous_end),
        runtime_end=hex(base+len(payload)),methods={k:hex(v) for k,v in methods.items()},
        patches=[dict(address=hex(ENTRY),before=BEFORE.hex(),after=after.hex(),
                      file_offset=hex(src-B.BASE+ENTRY-base))],
        original_entry=hex(ENTRY),pool_vtable=hex(POOL_VTABLE),slots=1024,
        current_project_getter='0x4018a97a',active_settings_resolver='0x47a75a02',
        identity_table_offset=528,identity_stride=16,compared_word_offsets=[4,8],
        abi='directory pointer followed by four32-bit identity words by value; signed slot index or-1.',
        semantics='First match, including OFF/sentinel entries, using native words1/2 equality; words0/3 ignored.',
        fallback='Other directory vtables and invalid active project state execute original lookup body.',
        cost='Native pool resolves current Project and active table once per lookup; no per-slot virtual calls or copies.',
        preserves='No cached state or table mutations. Bounded names, sample metadata/storage, ONESHOT defaults, DSP and USB42 unchanged.',
        limits=['Offline focused equivalence and instruction-count checks required; hardware responsiveness remains untested.'])
    doc.update(main_sha256=B.T.SHA(image),runtime_sha256=B.T.SHA(payload),bytes=len(image),
        runtime_copy={**c,'bytes':len(payload)},bootstrap=hex(boot),
        bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['browser_identity_lookup'] = cfg
    (out/'main-os.bin').write_bytes(image)
    (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    # Preserve component evidence sources; checks are rerun against final hash.
    for p in INPUT.iterdir():
        if p.is_file() and p.name not in ('main-os.bin','runtime.bin','bootstrap.S','bootstrap.asm','bootstrap.elf') and p.suffix in ('.S','.asm','.txt','.elf','.bin'):
            shutil.copyfile(p,out/p.name)
    print(json.dumps(dict(main_sha256=doc['main_sha256'],browser_identity_lookup=cfg),indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
