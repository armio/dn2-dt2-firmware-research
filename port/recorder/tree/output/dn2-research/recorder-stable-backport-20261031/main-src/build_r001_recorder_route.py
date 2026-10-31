#!/usr/bin/env python3
"""Connect or replace the three-page VOICE route with physical-key handling."""
from pathlib import Path
import argparse
import json
import re
import struct
import build_dt2_sample_manager as S
B = S.B


def build(parent, out, build_id='T1E3'):
    doc = json.loads((parent/'build-receipt.json').read_text())
    raw = (parent/'main-os.bin').read_bytes()
    assert B.T.SHA(raw) == doc['main_sha256']
    copy = doc['runtime_copy']
    src, base = int(copy['source'], 16), int(copy['destination'], 16)
    payload = bytearray((parent/'runtime.bin').read_bytes())
    assert raw[src-B.BASE:src-B.BASE+copy['bytes']] == payload
    assert len(payload) % 4 == 0
    ui = doc['recorder_ui']['methods']
    transport = doc['recording_transport']['methods']
    destroy = int(ui['destroy'], 16)
    previous = doc.get('recorder_route')
    prologue = bytes.fromhex(previous['destructor_original']) if previous else bytes(payload[destroy-base:destroy-base+8])
    assert prologue[:4] == bytes.fromhex('2f0a203c')
    if previous:
        assert payload[destroy-base:destroy-base+8] == b'\x4e\xf9'+B.BE(int(previous['methods']['recorder_destroy_hook'], 16))+b'\x4e\x71'
    symbols = dict(
        sample_manager_event=doc['sample_manager']['methods']['view_event'],
        voice_page_open=doc['voice_page_route']['methods']['voice_page_open'],
        recorder_factory=ui['factory'], recorder_event=ui['event'],
        recorder_transport_open=transport['open'],
        recorder_transport_close=transport['close'],
        recorder_secondary_vtable=hex(struct.unpack('>I', prologue[4:])[0]),
        recorder_destroy_resume=hex(destroy+8))
    source = ''.join(f'.equ {key},{value}\n' for key, value in symbols.items())
    source += (B.T.ROOT/'scripts/asm/dn2_recorder_route.S').read_text()
    out.mkdir(parents=True, exist_ok=False)
    code = B.R.assemble(source, base+len(payload), out, 'recorder-route')
    nm = B.T.run([B.T.BIN/'binutils/nm-new', '-n', out/'recorder-route.elf'])
    linked = {m[2]: int(m[1], 16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$', nm)}
    payload.extend(code)
    manager_slot = int(doc['voice_page_route']['sample_view_event_slot'], 16)
    expected_manager = previous['methods']['sample_to_recorder_event'] if previous else doc['voice_page_route']['methods']['sample_page_event']
    assert struct.unpack_from('>I', payload, manager_slot-base)[0] == int(expected_manager, 16)
    recorder_slot = next(int(e['runtime'], 16) for e in doc['recorder_ui']['edits'] if e['donor'] == '0x401eec5c')
    expected_recorder = previous['methods']['recorder_page_event'] if previous else ui['event']
    assert struct.unpack_from('>I', payload, recorder_slot-base)[0] == int(expected_recorder, 16)
    struct.pack_into('>I', payload, manager_slot-base, linked['sample_to_recorder_event'])
    struct.pack_into('>I', payload, recorder_slot-base, linked['recorder_page_event'])
    payload[destroy-base:destroy-base+8] = b'\x4e\xf9'+B.BE(linked['recorder_destroy_hook'])+b'\x4e\x71'
    identity = 0x47aa5a0c-base
    assert payload[identity:identity+4] == (b'T1F1' if build_id == 'T1F2' else b'T1E2')
    payload[identity:identity+4] = build_id.encode('ascii')
    assert base+len(payload) <= int(doc['runtime_limit'], 16)
    image = bytearray(raw[:src-B.BASE])+payload
    boot = B.BASE+len(image)
    old_count, new_count = f'#{copy["bytes"]//4},%d1', f'#{len(payload)//4},%d1'
    asm = (parent/'bootstrap.S').read_text()
    assert old_count in asm
    asm = asm.replace(old_count, new_count)
    image.extend(B.R.assemble(asm, boot, out, 'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+B.BE(boot)
    assert doc['recorder_runtime_reservation']['parent_main_sha256'] == '4f2cea43e6a70ae922dc58ac7c02cfb91f72fdeaa4b4146ba72e2007a2c39f96'
    doc['recorder_ui']['connected_to_navigation'] = True
    doc['recorder_route'] = dict(
        methods={key: hex(linked[key]) for key in ('sample_to_recorder_event', 'recorder_page_event', 'recorder_page_open', 'recorder_destroy_hook')},
        manager_event_slot=hex(manager_slot), recorder_event_slot=hex(recorder_slot),
        destructor=ui['destroy'], destructor_original=prologue.hex(),
        sequence=['Voice Allocation', 'Sample Manager', 'Recorder', 'Voice Allocation'],
        func_voice='Original DN2 unison handler',
        key_phases='Consume VOICE DOWN=1; advance on clicked UP=0x10; FUNC delegates native unison for both phases.',
        close='Request DSP STOP on full Recorder view destruction; transport retires enable cookie after stop acknowledgment.',
        code_bytes=len(code), code_sha256=B.T.SHA(code))
    doc.update(baseline_sha256=B.T.SHA(raw), main_sha256=B.T.SHA(image), bytes=len(image),
        runtime_copy={**copy, 'bytes': len(payload)}, runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot), bootstrap_bytes=len(image)-(boot-B.BASE), flash_ready=False)
    for name, contents in [('main-os.bin', image), ('runtime.bin', payload)]:
        (out/name).write_bytes(contents)
    for name in ('fn_new_map.txt', 'ram_map.txt'):
        (out/name).write_bytes((parent/name).read_bytes())
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'], runtime_bytes=len(payload), route=doc['recorder_route']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--build', choices=('R001',), default='R001')
    args = parser.parse_args()
    build(args.input, args.out, args.build)
