#!/usr/bin/env python3
"""Execute R004 phase recovery and compare its exact write/ABI scope to R003."""
from pathlib import Path
import argparse
import json

import build_dt2_buffer_phase_accounting as Q
import sharc_dn2_fixups as fx
import sharc_modify_units as units
from check_dt2_dsp_render_diagnostic import MarkerFixups, REGS

P, C = Q.P, Q.C


def check(folder):
    raw = (folder/'section_7.bin').read_bytes()
    oldraw = Q.BASE.read_bytes()
    doc = json.loads((folder/'build-receipt.json').read_text())
    assert C.SHA(oldraw) == Q.BASE_SHA and C.SHA(raw) == doc['section7_sha256']
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    k.ldr.L2_BYTE_LIMIT = 0x20100000
    fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    units.install()
    old, m = (P.B.decode_view(k, b) for b in (oldraw, raw))
    a, b = C.B.walk(oldraw).blocks, C.B.walk(raw).blocks
    assert len(b) == len(a)+1
    physical = C.S.code_address(Q.CODE, window='l2')
    assert (b[-2].target, b[-2].count) == (physical, 30)
    assert b[7].argument == b[-1].offset-b[7].offset
    hook = C.S.code_address(Q.SITE, window='l2')
    changed = []
    for x, y in zip(a[:-1], b[:-2]):
        assert (x.target, x.count, x.flags) == (y.target, y.count, y.flags)
        if not x.has_payload:
            continue
        for i, (u, v) in enumerate(zip(oldraw[x.payload_at:x.end], raw[y.payload_at:y.end])):
            if u != v:
                at = x.target+i
                assert hook <= at < hook+6, hex(at)
                changed.append(at)
    assert not any(physical < at+len(v) and at < physical+30
                   for at, v in C.B.load_regions(oldraw))
    for i, word in enumerate(Q.WORDS):
        ins = k.st.decode_at(m, None, Q.CODE+3*i)
        assert ins.raw == word and ins.length_bytes == 6

    def put(r, address, value):
        assert k.st._dm_write(r.state, address, 4, k.st.Const(value & 0xffffffff))

    def get(r, address):
        value = k.st._dm_read(r.state, address, 4)
        assert isinstance(value, k.st.Const), (hex(address), value)
        return value.value

    def reg(r, name, value):
        r.state.uregs[k.st.UREG_CODES[name]] = k.st.Const(value)

    def runner(mem, count=1, phase=0, simd=False, status=0):
        regs = {n: (0x12340000+0x131*i) & 0xffffffff for i, n in enumerate(REGS)}
        regs.update(R0=count, MODE1=0x01000000 | (0x200000 if simd else 0),
                    ASTATX=(0x4005a5 if status else 0x200a5a), ASTATY=0x005a5,
                    I6=0x2ff000, I7=0x2fef00, M5=0, M6=1, M7=0xffffffff,
                    M13=0, L6=0, L7=0)
        r = k.run.Runner(mem, 0x1c9fee, regs=regs, explicit_memory_model=True)
        for n in ('MRF','MRB','MSF','MSB'):
            r.state.special[n] = k.st.MR((1 << 80)-1, 0x123456789abcdef01234)
        put(r, Q.PHASE, phase)
        put(r, P.FIELDS['ready'], 1)
        put(r, P.FIELDS['normal_active'], 1)
        put(r, 0x2c0450, 1)  # SPI selector belongs to its existing callback.
        return r

    def run(r, stops, limit=1500):
        result = fx.run(r, limit, MarkerFixups(), stop_at=stops)
        assert result[0] == 'stop' and result[1] in stops, (result, r.state.stopped)
        return result

    def arch(a, b):
        assert a.state.uregs == b.state.uregs
        assert a.state.special == b.state.special
        assert not a.state.pending and not a.state.call_stack and not a.state.loops

    rows = []
    for simd in (False, True):
        for phase in (0, 1):
            for status in (0, 1):
                for count in (0, 1, 2, 3, 8, 0x80000000, 0xffffffff):
                    native = runner(old, count, phase, simd, status)
                    r = runner(m, count, phase, simd, status)
                    target = 0x1c9ff4 if count == 1 else 0x1c9ffb
                    run(native, [target]); run(r, [target])
                    arch(r, native)
                    assert get(r, Q.PHASE) == phase ^ int(count > 1)
                    assert get(r, P.FIELDS['ready']) == int(count == 1)
                    assert get(r, P.FIELDS['normal_active']) == int(count == 1)
                    assert get(r, 0x2c0450) == 1
                    # Outside the phase word, every runtime write equals R003,
                    # including staging lifecycle, counters, saves and control.
                    phase_bytes = set(range(0x28000000+Q.PHASE, 0x28000000+Q.PHASE+4))
                    for at in set(r.state.overlay) | set(native.state.overlay):
                        if at not in phase_bytes:
                            assert r.state.overlay.get(at) == native.state.overlay.get(at), hex(at)
                    rows.append(dict(simd=simd, phase=phase, status=status, count=count,
                                     next=hex(target), phase_after=get(r, Q.PHASE)))

    drains = []
    for phase in (0, 1):
        sequences = [(n, list(range(n, 0, -1))) for n in (1, 2, 3, 4, 8)]
        sequences.append((2, [2, 2, 1]))  # one callback arrives after first skip
        for pending, counts in sequences:
            r = runner(m, phase=phase)
            put(r, 0x2d0700, 0x2f8000)
            put(r, 0x2f8050, pending)
            for consumed, count in enumerate(counts, 1):
                r.state.pc_sw = 0xb89224
                run(r, [0xb89238])
                assert get(r, 0x2f8050) == count-1
                assert r.state.uregs[k.st.UREG_CODES['R15']] == k.st.Const(count)
                reg(r, 'R0', count)
                r.state.pc_sw = 0x1c9fee
                run(r, [0x1c9ff4 if count == 1 else 0x1c9ffb])
                if count > 1:
                    assert get(r, Q.PHASE) == phase ^ (consumed & 1)
                if counts == [2, 2, 1] and consumed == 1:
                    put(r, 0x2f8050, get(r, 0x2f8050)+1)
            # No stale completed stage survives a skip. The next normal commit
            # uses the corrected page and must leave the other DMA page intact.
            selected = phase ^ ((len(counts)-1) & 1)
            assert get(r, Q.PHASE) == selected
            for offset, value in ((4,0x282c0478+(1-selected)*256),
                                  (0x2c,0x282c04a0+(1-selected)*256),
                                  (0x30,0x10201),(8,0x144225)):
                put(r, P.P.DMA+offset, value)
            put(r, P.P.SPORT, 0x02100000)
            stage = [0x10203000+i for i in range(64)]
            for i in range(64):
                put(r, P.STAGE+4*i, stage[i])
                put(r, 0x2c0478+4*i, 0x55550000+i)
                put(r, 0x2c0578+4*i, 0x77770000+i)
            r.state.pc_sw = 0x1c9f12
            run(r, [0x1c9f15])
            assert [get(r,0x2c0478+256*selected+4*i) for i in range(64)] == (stage if pending == 1 else [0]*64)
            assert [get(r,0x2c0478+256*(1-selected)+4*i) for i in range(64)] == [(0x55550000 if selected else 0x77770000)+i for i in range(64)]
            assert get(r, Q.PHASE) == selected and get(r, 0x2c0450) == 1
            r.state.pc_sw = 0xbf0b84
            run(r, [0x1c9e62])
            assert get(r, Q.PHASE) == phase ^ (len(counts) & 1)
            drains.append(dict(initial_phase=phase, notifications=len(counts), wait_returns=counts,
                               copy_phase=selected, final_phase=get(r,Q.PHASE)))
    result = dict(ok=True, section7_sha256=C.SHA(raw), baseline_sha256=C.SHA(oldraw),
        scheduler_cases=rows, native_wait_drain_and_copy_cases=drains,
        architecture_and_nonphase_runtime_writes_equal=True,
        original_payload_changed_bytes=len(changed), only_original_hook_changed=True,
        new_code_bytes=30, new_data_bytes=0, native_dma_and_control_bytes_unchanged=True,
        limits=['Instruction and ownership-model execution, not physical DMA/IRQ timing validation.'])
    (folder/'phase-accounting-check.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(ok=True, scheduler_cases=len(rows), drain_cases=len(drains),
                          section7_sha256=C.SHA(raw)), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    check(p.parse_args().folder)
