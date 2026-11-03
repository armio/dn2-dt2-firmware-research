#!/usr/bin/env python3
"""Execute R011 SPI phase-change regressions; no hardware access."""
from pathlib import Path
import argparse
import copy
import itertools
import json

import build_dt2_usb_spi_publication as R
import check_dt2_usb_retained as X

Q, P, C = X.Q, X.P, X.C
CANARY = 0xa5a5a5a5


def field(f, r, name):
    return f.read(r, Q.FIELDS[name])


def putfield(f, r, name, value):
    f.put(r, Q.FIELDS[name], value)


def fill(f, r):
    for bus in P.BUS:
        for page in P.BUS[bus][1]:
            for off in range(0, 2048 if bus == 'tdm' else 4096, 4):
                f.put(r, page+off, CANARY)


def enqueue(f, r, generation, tp, sp):
    f.reg(r, 'I3', tp)
    f.reg(r, 'I13', sp)
    f.execute(r, 'before')
    slot = field(f, r, 'write_stage')
    assert slot in Q.SLOTS
    for off in range(0, Q.SLOT_BYTES, 4):
        f.put(r, slot+off, (generation << 20)+off)
    f.execute(r, 'after')
    return slot


def retry(f, r, changes=None):
    putfield(f, r, 'producer_valid', 0)
    putfield(f, r, 'cycle_published', 0)
    before = copy.deepcopy(r.state.mmrs)
    mmio = {a:v for a,v in r.state.overlay.items() if 0x31000000 <= a < 0x32000000}
    steps = f.execute(r, 'after', changes=changes)
    if not changes:
        assert r.state.mmrs == before, 'publication wrote MMIO'
        assert {a:v for a,v in r.state.overlay.items() if 0x31000000 <= a < 0x32000000} == mmio
    return steps


def assert_pair(f, r, slot, tp, sp):
    for bus, page, source, size in (('tdm', tp, slot, 2048), ('spi', sp, slot+Q.SPI_OFFSET, 2748)):
        for off in range(0, size, 4):
            audio = (off % 64 < 56) if bus == 'tdm' else 28 <= off < 2716
            want = f.read(r, source+off) if audio else CANARY
            assert f.read(r, page+off) == want, (bus, hex(page+off))


def live_snapshot(f, r):
    return {(page, off):f.read(r, page+off)
            for bus in P.BUS for page in P.BUS[bus][1]
            for off in range(0, 2048 if bus == 'tdm' else 4096, 4)}


def check(folder):
    # Reuse complete native exporter, ABI, queue/full, drained-freshness,
    # post-crossing and diagnostic checks against the unchanged R008 native
    # reference. This checks actual candidate instructions, not a queue model.
    regressions = X.check(folder)
    f = X.Fixture(folder)
    parent = R.BASE.read_bytes()
    assert C.SHA(parent) == R.BASE_SHA
    assert f.doc['baseline_sha256'] == R.BASE_SHA
    assert f.doc['usb_spi_publication']['native_export_parent_sha256'] == Q.BASE_SHA
    old = X.Fixture(R.BASE.parent)

    # Independently compare loaded regions; only replacement code and existing
    # hook destinations may differ from R010. State, slots, native code and
    # data are exact. There are no additional loaded regions.
    previous = dict(C.B.load_regions(parent))
    current = dict(C.B.load_regions(f.raw))
    assert current.keys() == previous.keys()
    for at, data in previous.items():
        actual = bytearray(f.memory.read(at, len(current[at])))
        if at == Q.PHYSICAL:
            assert at+len(actual) <= Q.CODE_END
            continue
        assert len(actual) == len(data)
        data = old.memory.read(at, len(data))
        for hook in f.hooks.values():
            site, size = int(hook['physical'], 16), len(bytes.fromhex(hook['after']))
            lo, hi = max(at, site)-at, min(at+len(data), site+size)-at
            if lo < hi:
                actual[lo:hi] = data[lo:hi]
        assert bytes(actual) == data, ('unrelated R010 region changed', hex(at))

    # Reproduce the original failure with the delivered R010 instructions.
    tp, sp = P.BUS['tdm'][1][0], P.BUS['spi'][1][0]
    r = old.runner(); fill(old, r)
    old.dma(r, 'tdm', tp ^ 0x1800, count=1)
    enqueue(old, r, 1, tp, sp)
    old.dma(r, 'tdm', tp)
    old.dma(r, 'spi', sp ^ 0x1000)
    retry(old, r)
    assert field(old, r, 'committed') == 0 and field(old, r, 'last_reason') == 17

    phases = []
    for tp, sp in itertools.product(P.BUS['tdm'][1], P.BUS['spi'][1]):
        r = f.runner(tdm=tp, spi=sp); fill(f, r)
        f.dma(r, 'tdm', tp ^ 0x1800, count=1)
        slots = [enqueue(f, r, g, tp, sp) for g in (1, 2)]
        assert field(f, r, 'read_cursor') == 0
        # Project phase now makes the originally selected successor active.
        f.dma(r, 'tdm', tp)
        f.dma(r, 'spi', sp ^ 0x1000)
        steps = retry(f, r)
        assert field(f, r, 'committed') == field(f, r, 'read_cursor') == 1
        assert field(f, r, 'last_sequence') == 1
        assert f.read(r, Q.G['tdm_target']) == tp ^ 0x1800
        assert f.read(r, Q.G['spi_target']) == sp
        assert_pair(f, r, slots[0], tp ^ 0x1800, sp)
        assert all(f.read(r, (sp ^ 0x1000)+off) == CANARY for off in range(0, 4096, 4))

        # Observe TDM consumption independently. With unchanged SPI START,
        # its previously published inactive page still cannot be overwritten.
        f.dma(r, 'tdm', tp ^ 0x1800, count=1)
        retry(f, r)
        assert field(f, r, 'seen_tdm') == 1 and field(f, r, 'seen_spi') == 0
        f.dma(r, 'tdm', tp)
        before = live_snapshot(f, r)
        deferred = field(f, r, 'freshness_deferred')
        retry(f, r)
        assert field(f, r, 'committed') == 1
        assert field(f, r, 'freshness_deferred') == deferred+1
        assert live_snapshot(f, r) == before

        # A real SPI page turnover admits the next oldest pair. The TDM
        # destination remains tied to its original FIFO metadata throughout.
        f.dma(r, 'spi', sp)
        retry(f, r)
        assert field(f, r, 'committed') == field(f, r, 'read_cursor') == 2
        assert field(f, r, 'last_sequence') == 2
        assert_pair(f, r, slots[1], tp ^ 0x1800, sp ^ 0x1000)
        phases.append(dict(tdm_original=hex(tp), spi_original=hex(sp),
                           original_successor_owned=True, first_destination=hex(sp),
                           later_destination=hex(sp ^ 0x1000), instructions=steps,
                           same_start_no_overwrite=True, ordered_sequences=[1, 2]))

    rejected = []
    for spi_page, kind in itertools.product(P.BUS['spi'][1], ('count1', 'unknown_start', 'bracket')):
        r = f.runner(); fill(f, r)
        tp, sp = P.BUS['tdm'][1][0], P.BUS['spi'][1][0]
        f.dma(r, 'tdm', tp ^ 0x1800, count=1)
        enqueue(f, r, 1, tp, sp)
        f.dma(r, 'tdm', tp)
        f.dma(r, 'spi', spi_page, count=1 if kind == 'count1' else None)
        changes = None
        if kind == 'unknown_start':
            f.put(r, P.BUS['spi'][0]+4, 0x12345678)
        elif kind == 'bracket':
            changes = {f.labels['before_spi_start_again.']:
                       lambda run, page=spi_page:f.dma(run, 'spi', page ^ 0x1000)}
        before = live_snapshot(f, r)
        retry(f, r, changes)
        assert field(f, r, 'committed') == field(f, r, 'read_cursor') == 0
        assert live_snapshot(f, r) == before
        assert field(f, r, 'last_reason') == {'count1':13, 'unknown_start':12, 'bracket':11}[kind]
        rejected.append(dict(page=hex(spi_page), case=kind, no_live_writes=True))

    result = dict(ok=True, section7_sha256=C.SHA(f.raw), parent_sha256=R.BASE_SHA,
                  native_export_parent_sha256=Q.BASE_SHA,
                  exact_r010_outside_code_and_hook_destinations=True,
                  native_r010_stall_reproduced=True, phase_change_cases=phases,
                  ownership_rejection_cases=rejected, no_dma_configuration_writes=True,
                  parent_regression_proof='usb-retained-check.json',
                  native_export_cases=len(regressions['native_export_cases']),
                  abi_cases=len(regressions['abi_cases']),
                  limits=['Fixture timing does not establish hardware deadlines or exact cross-bus generation alignment.',
                          'Original bounded queue, DMA ownership predicates and post-copy limitations remain.'])
    (folder/'usb-spi-publication-check.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('phase_change_cases','ownership_rejection_cases','limits')}, indent=2))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    check(p.parse_args().folder)
