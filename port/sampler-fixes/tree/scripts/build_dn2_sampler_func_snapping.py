#!/usr/bin/env python3
"""Restore DT2 TUNE FUNC callbacks on the exact expanded R013 image."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct

import build_dn2_sampler_encoder_sensitivity as E

A = E.B.R
BASE = E.B.BASE
GETTER = 0x400c2418
TEMPLATE = 0x42431e98
MANAGER = 0x400bfc22
INVOKER = 0x400cb78a
PARENT_SHA = 'c928d2b30522dbd5c4bb385d883ac3149d44d0decb4ab64f5b455a1c1e36b684'
TUNES = {1: 202, 323: 239, 341: 248, 350: 212, 359: 221}
BE = lambda value: struct.pack('>I', value)
SHA = lambda data: hashlib.sha256(data).hexdigest()


def evidence():
    donor, native = E.B.M.S.DONOR.read_bytes(), E.B.M.RECIPIENT.read_bytes()
    # Same complete callback, apart from verified native address bindings and
    # the native compiler's absolute call replacing the donor's PC-relative call.
    entry, end = 0x400c9122, 0x400c91c4
    blob = bytearray(donor[entry-BASE:end-BASE])
    bindings = {
        0x429409d4: 0x42438828, 0x401e2e8a: 0x401c9ac4,
        0x40209f0c: 0x401f2be8, 0x4293b3fc: 0x42432570,
        0x401bddc6: 0x401adbc2, 0x401e2ee6: 0x401c9b20,
        0x40187e3c: 0x4017cf30, 0x4019a842: 0x401adc1e,
        0x4019a714: 0x4018c2a8,
    }
    _, rows = E.B.M.function(donor, entry)
    for at, target, _, _ in E.B.M.operands(rows):
        assert target in bindings, hex(target)
        blob[at-entry:at-entry+4] = BE(bindings[target])
    offset = 0x400c919c-entry
    assert blob[offset:offset+4] == bytes.fromhex('4ebaf5f8')
    blob[offset:offset+4] = bytes.fromhex('4eb9')+BE(0x400c23e4)
    assert blob == native[INVOKER-BASE:INVOKER-BASE+len(blob)]
    assert donor[0x400c8796-BASE:0x400c87ca-BASE] == native[0x400c23e4-BASE:0x400c2418-BASE]
    table = donor[0x40209f0c-BASE:0x40209f38-BASE]
    assert table == native[0x401f2be8-BASE:0x401f2c14-BASE]
    values = list(struct.unpack('>11i', table))
    assert values == list(range(-60, 61, 12))
    # Actual donor initializer binds each visible TUNE to this callback template.
    for donor_id in TUNES.values():
        row = 0x4293c040+68*donor_id
        sequence = bytes.fromhex('4879')+BE(0x4293ac74)+bytes.fromhex('4879')+BE(row+52)
        sequence += bytes.fromhex('42b9')+BE(row+44)+bytes.fromhex('4e93')
        assert donor.count(sequence) == 1, donor_id
    # The native startup installs this exact manager/invoker pair into TEMPLATE.
    initializer = bytes.fromhex('223c')+BE(INVOKER)+bytes.fromhex('23c0')+BE(TEMPLATE)
    initializer += bytes.fromhex('203c')+BE(MANAGER)+bytes.fromhex('23c1')+BE(TEMPLATE+12)
    initializer += bytes.fromhex('23c0')+BE(TEMPLATE+8)
    assert native[0x400c3c84-BASE:0x400c3ca2-BASE] == initializer
    return dict(donor_callback=hex(entry), native_callback=hex(INVOKER),
                native_manager=hex(MANAGER), native_template=hex(TEMPLATE),
                callback_bytes=len(blob), octave_semitones=values,
                donor_sha256=SHA(donor), native_sha256=SHA(native),
                bindings={hex(k):hex(v) for k,v in bindings.items()},
                native_directional_lookup='0x400c23e4')


def build(parent, out):
    raw = (parent/'main-os.bin').read_bytes()
    doc = json.loads((parent/'build-receipt.json').read_text())
    assert SHA(raw) == doc['main_sha256'] == PARENT_SHA, 'Requires exact expanded R013 parent'
    proof = evidence()
    region = doc['runtime_copy']
    src, base = int(region['source'],16), int(region['destination'],16)
    runtime = bytearray((parent/'runtime.bin').read_bytes())
    assert SHA(runtime) == doc['runtime_sha256']
    assert len(runtime) == region['bytes'] and raw[src-BASE:src-BASE+len(runtime)] == runtime
    previous = int(doc['sampler_widgets']['entry'],16)
    assert raw[GETTER-BASE:GETTER-BASE+6] == b'\x4e\xf9'+BE(previous)
    rows = [r for r in doc['encoder_sensitivity']['rows'] if r['name']=='TUNE']
    assert {r['native_id']:r['donor_id'] for r in rows} == TUNES
    out.mkdir(parents=True, exist_ok=False)
    entry = base+len(runtime)
    branches = '\n'.join(f' cmpi.l #{n},%d1\n beq.s tune_callback' for n in TUNES)
    source = f'''.text
.global sampler_func_companion
sampler_func_companion:
 move.l 4(%sp),-(%sp)
 jsr {previous:#x}
 addq.l #4,%sp
 move.l 4(%sp),%d1
{branches}
 rts
tune_callback:
 movea.l %d0,%a0
 lea {TEMPLATE:#x},%a1
 move.l (%a1)+,52(%a0)
 move.l (%a1)+,56(%a0)
 move.l (%a1)+,60(%a0)
 move.l (%a1),64(%a0)
 rts
.balign 4
'''
    runtime.extend(A.assemble(source, entry, out, 'sampler-func-snapping'))
    assert len(runtime)%4 == 0 and base+len(runtime) <= int(doc['runtime_limit'],16)
    image = bytearray(raw[:src-BASE])+runtime
    before = image[GETTER-BASE:GETTER-BASE+6]
    after = b'\x4e\xf9'+BE(entry)
    image[GETTER-BASE:GETTER-BASE+6] = after
    boot = BASE+len(image)
    bootstrap = (parent/'bootstrap.S').read_text()
    old_count = f'#{region["bytes"]//4},%d1'
    assert bootstrap.count(old_count) == 1
    bootstrap = bootstrap.replace(old_count, f'#{len(runtime)//4},%d1')
    image.extend(A.assemble(bootstrap, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+BE(boot)
    doc.update(main_sha256=SHA(image), bytes=len(image), runtime_sha256=SHA(runtime),
               runtime_copy={**region,'bytes':len(runtime)}, bootstrap=hex(boot),
               bootstrap_bytes=len(image)-(boot-BASE), flash_ready=False)
    doc['sampler_func_snapping'] = dict(parent=str(parent.resolve()), parent_sha256=PARENT_SHA,
        entry=hex(entry), previous_getter=hex(previous), evidence=proof,
        hook=dict(address=hex(GETTER),before=before.hex(),after=after.hex()),
        rows=[{k:r[k] for k in ('machine','native_id','donor_id','companion')} for r in rows],
        semantics='Borrow persistent native octave callback into private sampler TUNE companions only.',
        unchanged=['Stock companions','Other sampler controls','Normal/pressed encoder scaling','DSP'],
        hardware_validated=False)
    for name, data in [('main-os.bin',image),('runtime.bin',runtime)]:
        (out/name).write_bytes(data)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(parent/name,out/name)
    print(json.dumps(dict(main_sha256=doc['main_sha256'],output=str(out),
        added_runtime_bytes=len(runtime)-region['bytes'],parameters=len(rows)),indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    build(args.parent,args.out)
