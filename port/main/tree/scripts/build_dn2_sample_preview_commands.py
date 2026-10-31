#!/usr/bin/env python3
"""Connect native preview events to a dedicated DT2 audition DSP path."""
from pathlib import Path
import argparse, json, re
import build_dt2_sample_preview as P

B = P.B
INPUT = B.T.ROOT / 'output/dn2-research/dn2-cursor-stop-identity-20261010'
SHA = '07d32e529efa2ab7a07e05930f69aca7c2f93de89f83edf1282a64cb10c732a6'
WIRE = 0x80005e8a
FRAME_HOOK, EVENT_HOOK, STATUS = 0x40026098, 0x4002634a, 0x47a73908


def build(out):
    raw = (INPUT / 'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == SHA
    doc = json.loads((INPUT / 'build-receipt.json').read_text())
    copy = doc['runtime_copy']
    source, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray((INPUT / 'runtime.bin').read_bytes())
    out.mkdir(parents=True, exist_ok=False)
    # Native DN2 still queues event8 through the same start/stop producers as
    # DT2, but its dispatcher discards that event. Use a free request-header
    # word; donor offsets7F6/7F8/7FA overlap DN2 voice parameters.
    asm = f'''.text
.global preview_frame_clear
.global preview_event_dispatch
preview_frame_clear:
 move.l %d0,-(%sp)
 move.w {WIRE:#x},%d0
 andi.l #4,%d0
 move.w %d0,{WIRE:#x}
 move.l (%sp)+,%d0
 move.l %a6,%d2
 addi.l #-72,%d2
 jmp 0x400260a0
preview_event_dispatch:
 moveq #8,%d2
 cmp.l %d0,%d2
 bne.s preview_other_event
 move.l %d0,-(%sp)
 moveq #0,%d0
 tst.b 0x10(%a0)
 beq.s preview_no_start
 bset #0,%d0
preview_no_start:
 tst.b 0x11(%a0)
 beq.s preview_no_stop
 bset #1,%d0
preview_no_stop:
 tst.b 0x12(%a0)
 beq.s preview_mono
 bset #2,%d0
preview_mono:
 move.w %d0,{WIRE:#x}
 move.l (%sp)+,%d0
 jmp 0x40026e50
preview_other_event:
 jmp 0x40026352
.balign 4
'''
    at = base + len(payload)
    payload.extend(B.R.assemble(asm, at, out, 'preview-commands'))
    nm = B.T.run([B.T.BIN / 'binutils/nm-new', '-n', out / 'preview-commands.elf'])
    symbols = {m[2]: int(m[1], 16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$', nm)}
    image = bytearray(raw[:source - B.BASE])
    patches = []
    for site, expected, entry in (
        (FRAME_HOOK, '240e0682ffffffb8', 'preview_frame_clear'),
        (EVENT_HOOK, '7408b48067000b00', 'preview_event_dispatch'),
    ):
        before = bytes.fromhex(expected)
        assert image[site-B.BASE:site-B.BASE+len(before)] == before
        after = b'\x4e\xf9' + B.BE(symbols[entry]) + b'\x4e\x71'
        image[site-B.BASE:site-B.BASE+len(before)] = after
        patches.append(dict(site=hex(site), before=expected, after=after.hex(), helper=hex(symbols[entry])))
    assert payload[STATUS-base:STATUS-base+12] == bytes.fromhex('4a798000101856c044804e75')
    payload[STATUS-base+2:STATUS-base+6] = B.BE(0x80001a38)
    for component in doc.values():
        if not isinstance(component, dict):
            continue
        for edit in component.get('edits', []):
            if edit.get('runtime') == hex(STATUS+2):
                assert edit['binding'] == '0x80001018'
                edit['binding'] = '0x80001a38'
    assert len(payload) % 4 == 0 and base+len(payload) <= int(doc['runtime_limit'], 16)
    image.extend(payload)
    boot = B.BASE + len(image)
    bootstrap = (INPUT / 'bootstrap.S').read_text().replace(
        f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9' + B.BE(boot)
    doc.update(baseline_sha256=SHA, main_sha256=B.T.SHA(image), bytes=len(image),
               runtime_copy={**copy, 'bytes':len(payload)}, runtime_sha256=B.T.SHA(payload),
               bootstrap=hex(boot), bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    doc['preview_audio_fix'] = dict(
        base=str(INPUT.relative_to(B.T.ROOT)), base_sha256=SHA,
        methods={name:hex(symbols[name]) for name in ('preview_frame_clear','preview_event_dispatch')},
        patches=patches, request_word=hex(WIRE), request_offset='0x2a',
        flag_bits=dict(start=0,stop=1,stereo=2),
        status_getter=hex(STATUS), status_operand=hex(STATUS+2),
        old_reply_word='0x80001018', reply_word='0x80001a38', reply_offset='0x18',
        donor_event_dispatch='0x4002e190', native_start='0x40137f74', native_stop='0x40137faa',
        behavior='Retain the native DT2 event8 audition commands, independent of selected track or voice allocation. Clear one-frame start/stop pulses before dispatch and retain stereo mode.',
        limits=['Requires paired DSP dedicated preview renderer and reply status publisher.',
                'Static and bounded CF execution checks do not establish hardware audio.'])
    (out / 'main-os.bin').write_bytes(image)
    (out / 'runtime.bin').write_bytes(payload)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):
        (out / name).write_bytes((INPUT / name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),preview_audio_fix=doc['preview_audio_fix']),indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
