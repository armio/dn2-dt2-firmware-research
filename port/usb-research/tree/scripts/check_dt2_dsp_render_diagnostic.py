#!/usr/bin/env python3
"""Check inner render marker-only additions and displaced instruction equivalence.

This executes only the checkpoint wrappers. It does not run playback, interrupts,
physical cache accesses, or prove that the hardware fault is corrected.
"""
from pathlib import Path
import argparse
import copy
import json

import build_dt2_dsp_render_diagnostic as P
import sharc_dn2_fixups as fx

C = P.C
REGS = [*(f'{bank}{i}' for bank in ('R', 'S', 'I', 'M', 'B', 'L') for i in range(16)),
        'MODE1', 'ASTATX', 'ASTATY']


class MarkerFixups(fx.Fixups):
    def pre(self, runner, insn):
        # The core now implements scalar universal moves in SIMD mode.
        # The older general two-pass shim clears MODE1 while emulating PEx,
        # so it incorrectly snapshots MODE1 as zero for this register copy.
        if insn.type_name == '5a_move' and not (insn.raw & 0x7fffff):
            return None
        return super().pre(runner, insn)


def main(folder):
    raw = (folder / 'section_7.bin').read_bytes()
    doc = json.loads((folder / 'build-receipt.json').read_text())
    assert C.SHA(raw) == doc['section7_sha256']
    original = P.BASE.read_bytes()
    assert C.SHA(original) == P.BASE_SHA
    spec = doc['dsp_render_diagnostic']
    k = C.M.Digikit(C.SRC / 'toolchains/digikit')
    fx.bind(str(C.SRC / 'toolchains/digikit/tools'))
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    memory = P.B.decode_view(k, raw)
    base = P.B.decode_view(k, original)
    hooks = spec['hooks']

    # Existing loaded bodies differ only at the five declared six-byte sites.
    old_blocks, new_blocks = C.B.walk(original).blocks, C.B.walk(raw).blocks
    changed = []
    allowed_sites = []
    for h in hooks:
        pc = int(h['site'], 16)
        physical = C.S.code_address(pc, window='l2') if pc >= 0xb80000 else C.S.code_address(pc)
        allowed_sites.append((physical, physical + 6))
        assert C.S.to_value(base.read_sw(pc, 6)) == int(h['before_instruction'], 16)
        assert C.S.to_value(memory.read_sw(pc, 6)) == 0x063e00000000 | int(h['entry'], 16)
    for a, b in zip(old_blocks[:-1], new_blocks[:-3]):
        assert (a.target, a.count, a.flags) == (b.target, b.count, b.flags)
        if not a.has_payload:
            continue
        for offset, (before, after) in enumerate(zip(original[a.payload_at:a.end], raw[b.payload_at:b.end])):
            if before != after:
                address = a.target + offset
                assert any(lo <= address < hi for lo, hi in allowed_sites), hex(address)
                changed.append(address)
    assert len(new_blocks) == len(old_blocks) + 2
    assert new_blocks[-3].target == int(spec['code_physical'], 16)
    assert new_blocks[-2].target == int(spec['scratch'], 16)
    assert new_blocks[7].argument == new_blocks[-1].offset - new_blocks[7].offset
    owned = {int(spec['scratch'], 16) + i for i in range(4)}
    for page in P.PAGES:
        for off in (4, 12, 16, 24):
            owned.update(0x28000000 + page + off + i for i in range(4))

    def put(r, address, value):
        assert k.st._dm_write(r.state, address, 4, k.st.Const(value & 0xffffffff))

    def read(r, address):
        result = k.st._dm_read(r.state, address, 4)
        assert isinstance(result, k.st.Const), (hex(address), result)
        return result.value

    def runner(mem, pc, simd):
        regs = {name: (0x12345000 + 0x131 * index) & 0xffffffff
                for index, name in enumerate(REGS)}
        regs.update(MODE1=0x00200000 if simd else 0, ASTATX=0x004005a5, ASTATY=0x00200a5a)
        r = k.run.Runner(mem, pc, regs=regs, explicit_memory_model=True)
        for name in ('MRF', 'MRB', 'MSF', 'MSB'):
            r.state.special[name] = k.st.MR((1 << 80) - 1, 0x123456789abcdef01234)
        for index, address in enumerate((0x30dcf0, 0x200aa220, 0x200aa228, 0x30dc98, 0x30dd78)):
            put(r, address, (0x8422b9c8, 0x8422bdc8, 2708, 0x30e3b0, 0x19283)[index])
        for page in P.PAGES:
            for word in range(7):
                put(r, page + 4 * word, 0x70123400 + word)
        return r

    rows = []
    for h in hooks:
        site, replay = int(h['site'], 16), int(h['replay'], 16)
        for simd in (False, True):
            r = runner(memory, site, simd)
            before_regs, before_special = dict(r.state.uregs), copy.deepcopy(r.state.special)
            before_overlay = dict(r.state.overlay)
            status, stop, count = fx.run(r, 64, MarkerFixups(), stop_at=[replay])
            assert (status, stop) == ('stop', replay), (h, status, stop)
            assert r.state.uregs == before_regs, (h['checkpoint'], simd, 'register change')
            assert r.state.special == before_special, (h['checkpoint'], simd, 'MR change')
            assert not r.state.call_stack and not r.state.pending and not r.state.loops
            for address in set(before_overlay) | set(r.state.overlay):
                if before_overlay.get(address) != r.state.overlay.get(address):
                    assert address in owned, (h['checkpoint'], hex(address))
            for page in P.PAGES:
                assert read(r, page + 4) == int(h['raw_dsp_marker'], 16)
                actual_payload = [read(r, page + off) for off in (12, 16, 24)]
                expected_payload = [before_regs[k.st.UREG_CODES[p['register']]].value
                                    for p in h['payload']]
                assert actual_payload == expected_payload, (h['checkpoint'], simd,
                                                            actual_payload, expected_payload)
                assert [read(r, page + 4 * word) for word in (0, 2, 5)] == [0x70123400 + word for word in (0, 2, 5)]
            displaced = k.st.decode_at(base, None, site)
            assert displaced.type_name in ('14a', '19a', '19a_scaled')
            assert C.S.to_value(memory.read_sw(replay, 6)) == displaced.raw
            target = site + 3
            native = runner(base, site, simd)
            a = fx.run(native, 8, MarkerFixups(), stop_at=[target])
            b = fx.run(r, 8, MarkerFixups(), stop_at=[target])
            assert a[:2] == b[:2] == ('stop', target), (h, a, b)
            assert r.state.uregs == native.state.uregs and r.state.special == native.state.special
            for address in set(native.state.overlay) | set(r.state.overlay):
                if address not in owned:
                    assert native.state.overlay.get(address) == r.state.overlay.get(address), (h, hex(address))
            rows.append(dict(checkpoint=h['checkpoint'], simd_enabled=simd,
                             prefix_instructions=count, registers_preserved=len(REGS),
                             original_instruction_replayed=True, continuation=hex(target)))
    result = dict(ok=True, section7_sha256=C.SHA(raw), wrappers=rows,
                  original_payload_changed_bytes=len(changed), declared_hooks=len(hooks),
                  publication_only_writes=True, native_reply_words_preserved=[0, 2, 5],
                  limitations=['Only marker wrappers and displaced instructions execute in this check.',
                               'No playback, DMA, cache timing, interrupts, reentry, or hardware-fix claim.'])
    (folder / 'render-diagnostic-check.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(ok=True, cases=len(rows), section7_sha256=result['section7_sha256']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    main(parser.parse_args().folder)
