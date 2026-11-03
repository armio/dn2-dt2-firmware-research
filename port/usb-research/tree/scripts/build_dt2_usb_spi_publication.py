#!/usr/bin/env python3
"""R011: select the oldest retained SPI audio's destination from live DMA ownership."""
from pathlib import Path
import argparse
import json

import build_dt2_usb_retained as Q

C, B = Q.C, Q.B
BASE = C.ROOT/'output/dn2-research/usb-retained-r010-20261102/dsp/section_7.bin'
BASE_SHA = '0153c5dad7378118d5fd7b99b751b7898cf57af5603546efedd517ebfad65db1'
PHYSICAL, CODE, CODE_END = Q.PHYSICAL, Q.CODE, Q.CODE_END
STATE, STATE_END = Q.STATE, Q.STATE_END
SLOTS, SLOT_BASE, SLOT_END, SLOT_BYTES = Q.SLOTS, Q.SLOT_BASE, Q.SLOT_END, Q.SLOT_BYTES
SPI_OFFSET, FIELDS, G, F, SAVES, HOOKS = Q.SPI_OFFSET, Q.FIELDS, Q.G, Q.F, Q.SAVES, Q.HOOKS


def source():
    s = Q.source()
    anchor = Q.snapshot('before','spi')
    assert s.count(anchor) == 1
    a,b = Q.P.BUS['spi'][1]
    choose = Q.load(F['before_spi_start'])
    choose += '      R1 = 0x28000000;\n      R2 = R0 - R1;\n'
    choose += f'      R1 = {a:#x};\n      COMP(R2, R1);\n'
    choose += Q.jump('select_spi_canonical','IF EQ')
    choose += f'      R1 = {b:#x};\n      COMP(R2, R1);\n'
    choose += Q.jump('select_spi_done','IF NE')+Q.label('select_spi_canonical')
    choose += Q.load(F['before_spi_count'])+'      R1 = 0;\n      COMP(R0, R1);\n'
    choose += Q.jump('select_spi_drained','IF EQ')
    choose += '      R1 = 0x1000;\n      R2 = R2 XOR R1;\n'
    choose += Q.label('select_spi_drained')+Q.store(G['spi_target'],'R2')
    choose += Q.label('select_spi_done')
    # START/COUNT only select a candidate. The unchanged full pre/post checks
    # still decide whether it may be written, including all transfer margins.
    return s.replace(anchor,anchor+choose)


def verify_parent(parent, candidate, doc):
    assert C.SHA(parent) == BASE_SHA
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    old,new = B.decode_view(k,parent),B.decode_view(k,candidate)
    hooks=[(int(h['physical'],16),len(bytes.fromhex(h['after']))) for h in doc['usb_retained']['hooks']]
    for at,data in C.B.load_regions(parent):
        if at==PHYSICAL:
            assert PHYSICAL+len(data)<=CODE_END
            continue
        actual=bytearray(new.read(at,len(data)))
        for site,size in hooks:
            lo,hi=max(at,site)-at,min(at+len(data),site+size)-at
            if lo<hi:actual[lo:hi]=old.read(at+lo,hi-lo)
        # Loader streams may overlay an earlier span; compare effective RAM.
        assert bytes(actual)==old.read(at,len(data)),('unrelated parent change',hex(at))
    before={at:len(data) for at,data in C.B.load_regions(parent)}
    for at,data in C.B.load_regions(candidate):
        assert at in before,('new loaded region',hex(at))
        assert len(data)==before[at] or at==PHYSICAL and at+len(data)<=CODE_END


def build(out):
    parent=BASE.read_bytes();assert C.SHA(parent)==BASE_SHA
    native_source=Q.source
    changed_source=source()
    try:
        Q.source=lambda:changed_source
        Q.build(out)
    finally:
        Q.source=native_source
    result=(out/'section_7.bin').read_bytes()
    doc=json.loads((out/'build-receipt.json').read_text())
    verify_parent(parent,result,doc)
    doc.update(baseline_sha256=BASE_SHA)
    doc['usb_retained']['base_sha256']=BASE_SHA
    doc['usb_retained']['queue']='R010 FIFO/paired storage and overflow policy unchanged. SPI audio destination is selected from current DMA START, independent of the render-time RX selector. Only oldest queued audio is copied; native SPI header/trailer remain untouched.'
    doc['usb_spi_publication']=dict(parent_build='R010',parent_sha256=BASE_SHA,
        native_export_parent_sha256=Q.BASE_SHA,
        selector='For canonical START, choose opposite SPI page while count is positive; count zero selects current drained page. All original canonical/bracket/current/count bounds and freshness/post-copy checks then apply.',
        scope='SPI destination selection only; TDM destination, task retry points, queue, storage, DMA configuration, completion callbacks and control-frame ordering unchanged.',
        reason='Render TX selection follows RX callback phase, not a grant of SPI TX ownership. A retained destination can remain the active TX page after project loading.',
        proof='usb-spi-publication-check.json',
        limits=['Hardware validation pending, including repeated project changes.',
                'Existing finite queue can overflow when no guarded window is available.',
                'Per-bus FIFO order does not establish exact TDM/SPI generation alignment on hardware.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=C.SHA(result),parent_sha256=BASE_SHA,code_bytes=doc['usb_retained']['code_bytes'])))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
