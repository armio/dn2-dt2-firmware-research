#!/usr/bin/env python3
"""Use retained-take length when reopening Recorder before the first DSP reply."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[4]
PARENT = ROOT/'output/dn2-research/recorder-stable-backport-20261031/main-build/result'
PARENT_SHA = 'be26fb2a1355b6c1a8efcb7f9b596a0e66c59967bed8e874f2424937e172b7a1'
BASE = 0x40000400
sys.path.insert(0,str(ROOT/'scripts'))
import build_dt2_directory_model as L


def build(out):
    doc = json.loads((PARENT/'build-receipt.json').read_text())
    raw = bytearray((PARENT/'main-os.bin').read_bytes())
    runtime = bytearray((PARENT/'runtime.bin').read_bytes())
    sha = lambda value: hashlib.sha256(value).hexdigest()
    assert sha(raw) == PARENT_SHA == doc['main_sha256']
    assert sha(runtime) == doc['runtime_sha256']
    copy = doc['runtime_copy']
    source, destination = int(copy['source'],16)-BASE, int(copy['destination'],16)
    out.mkdir(parents=True, exist_ok=False)
    wrapper=destination+len(runtime)
    asm='''/* Live recording uses DSP replies; retained trim uses finalized take metadata. */
.text
.global recorder_ui_frame_count
recorder_ui_frame_count:
 move.l %a0,-(%sp)
 move.l %a1,-(%sp)
 movea.l 0x47abcf48,%a0
 move.l %a0,%d0
 beq.s live
 movea.l 16(%a0),%a1
 moveq #4,%d0
 cmp.l 164(%a1),%d0
 bne.s live
 move.l 56(%a0),%d0
 movea.l (%sp)+,%a1
 movea.l (%sp)+,%a0
 rts
live:
 movea.l (%sp)+,%a1
 movea.l (%sp)+,%a0
 jmp 0x400cfa40
.balign 4
'''
    body=L.B.R.assemble(asm,wrapper,out,'recorder-ui-frame-count')
    span=next(s for s in doc['recorder_ui']['spans'] if s['name']=='sampler_view')
    begin=int(span['runtime'],16);end=begin+int(span['end'],16)-int(span['donor'],16)
    imports=[e for e in doc['recorder_ui']['edits']
        if begin<=int(e['runtime'],16)<end and e['binding']=='0x400cfa40']
    assert len(imports)==11
    changes=[(int(e['runtime'],16),bytes.fromhex('400cfa40'),wrapper.to_bytes(4,'big')) for e in imports]
    changes += [(0x47abc4b3, b'\x04', b'\x03'),
               (0x47aa5a0c, b'R001', b'R002')]
    assert runtime[0x47ab9c26-destination:0x47ab9c28-destination] == bytes.fromhex('4eb9')
    for address,before,after in changes:
        offset=address-destination
        assert runtime[offset:offset+len(before)] == before
        assert raw[source+offset:source+offset+len(before)] == before
        runtime[offset:offset+len(before)] = after
        raw[source+offset:source+offset+len(before)] = after
    for name in ('fn_new_map.txt','ram_map.txt'):
        shutil.copyfile(PARENT/name,out/name)
    runtime.extend(body)
    assert destination+len(runtime)<=int(doc['runtime_limit'],16)
    raw=bytearray(raw[:source])+runtime
    boot=BASE+len(raw)
    bootasm=(PARENT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(runtime)//4},%d1')
    raw.extend(L.B.R.assemble(bootasm,boot,out,'bootstrap'))
    raw[0xb2:0xb8]=b'\x4e\xf9'+boot.to_bytes(4,'big')
    doc.update(bytes=len(raw),runtime_copy={**copy,'bytes':len(runtime)},
        bootstrap=hex(boot),bootstrap_bytes=len(raw)-(boot-BASE))
    doc.update(build='R002',baseline_sha256=PARENT_SHA,main_sha256=sha(raw),runtime_sha256=sha(runtime))
    doc['recorder_reopen'] = dict(parent_build='R001',parent_main_sha256=PARENT_SHA,
        patches=[dict(address=hex(at),before=b.hex(),after=a.hex()) for at,b,a in changes],
        original_frames_getter='0x400cfa40',retained_frames_getter=hex(wrapper),
        wrapper=dict(start=hex(wrapper),end=hex(wrapper+len(body)),bytes=len(body),sha256=sha(body)),
        reason='Finished-take constructor runs before Recorder transport is enabled; shared DSP reply can still contain closed-mode diagnostics.',
        abi='No-argument SamplerView getter preserves A0/A1. State4 reads retained recorder+0x38; other states or absent singleton use native DSP getter.',
        finished_tick='State4 skips live count refresh; native normalization completion stores final count before state4. State3 ticks and active recording remain unchanged.',
        take_audio_and_saved_files_unchanged=True,usb_dsp_and_control_order_unchanged=True,
        hardware_tested=False)
    for edit in imports:edit['binding']=hex(wrapper)
    (out/'main-os.bin').write_bytes(raw)
    (out/'runtime.bin').write_bytes(runtime)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_sha256=doc['runtime_sha256'],runtime_copy=doc['runtime_copy'])))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
