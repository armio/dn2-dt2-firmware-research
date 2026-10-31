#!/usr/bin/env python3
"""Link the original DT2 PCM receiver against DN2's native LP0 driver.

Dormant component: no startup hook, no SysEx and no host page transfer. Native
driver bodies are compared byte-for-byte after their known operand bindings.
"""
from pathlib import Path
import argparse, collections, json, struct
import build_dt2_sampler_dsp as C

BASE = C.ROOT/'output/dn2-research/dt2-werp-live-v3-20261009/dsp/section_7.bin'
BASE_SHA = '50e7581ba00998a24196a1454e05ce0ae1792d859a545c29b89e5d38e4f5710c'
SPANS = (
    ('slots', 0x1c3f78, 0x1c4075, 0x172800),
    ('receive', 0x1c7e1f, 0x1c7f16, 0x172900),
    ('submit-callback', 0x1c834a, 0x1c8429, 0x172a00),
    ('open', 0x1c8895, 0x1c8946, 0x172b00),
)
# The original specialized DT2 submit/open functions call these byte-equivalent
# DN2 driver/IRQ bodies. The generic native submit/open have extra arguments;
# do not redirect the original calls to those generic APIs without adaptation.
NATIVE_SPANS = (
    ('driver-head', 0x1c81ac, 0x1c834a, 0x1ca908),
    ('driver-irqs', 0x1c8429, 0x1c8895, 0x1cab8f),
    ('memset', 0x1c0cd0, 0x1c0d68, 0x1c0bde),
    ('address-alias', 0x1c0744, 0x1c075e, 0x1c0790),
)
KERNEL = {
    0xb87838:0xb89f6a, 0xb87871:0xb89fa3, 0xb8c38e:0xb8e210,
    0xb8b053:0xb8ced5, 0xb87f21:0xb8a633, 0xb8c76d:0xb8e5ef,
    0xb87f40:0xb8a652, 0xb8c33a:0xb8e1bc, 0xb87e25:0xb8a537,
    0xb8afa2:0xb8ce24,
}
STATE = 0x2f4000
DATA = (
    ('slots', 0x257810, 0x257810 + 1025*20, STATE),
    ('fallback', 0x25c914, 0x25c928, STATE+0x5030),
    ('driver-context', 0x261c20, 0x261ca0, STATE+0x5050),
    ('dma-descriptor', 0x268220, 0x268240, STATE+0x50d0),
    ('receive-buffer', 0x268240, 0x269244, STATE+0x50f0),
    ('handle', 0x269244, 0x269248, STATE+0x60f4),
)
POOL = 0x8422b9c8
LP0_OLD, LP0_NATIVE = 0x269468, 0x268ca8


def mapped(value, *, required=False):
    for _, lo, hi, dest in (*SPANS, *NATIVE_SPANS, *DATA):
        if lo <= value < hi:
            return dest + value - lo
    if LP0_OLD <= value < LP0_OLD+24:
        return LP0_NATIVE + value-LP0_OLD
    if value in KERNEL:
        return KERNEL[value]
    if required:
        raise ValueError(f'Unbound code target {value:#x}')
    return value


def relocate(k, memory, lo, hi, dest, *, mapper=mapped):
    import sharcinv, sharcfn
    result = bytearray(memory.read_sw(lo, 2*(hi-lo)))
    pc, changes, listing = lo, [], []
    while pc < hi:
        ins = k.st.decode_at(memory, None, pc)
        assert ins.kind != 'unknown' and pc+ins.length_bytes//2 <= hi, hex(pc)
        fields = sharcinv.merge_fields(ins.fields)
        form, field, value, required = ins.type_name, None, None, False
        if form in ('25a_direct', '8a_abs'):
            field, value, required = 'addr24', fields['addr'], True
        elif form in ('8a_rel', '25a_pcrel'):
            field, value, required = 'rel24', pc+C.S.get_field(ins.raw, 'rel24'), True
        elif form in ('17a', '16a', '19a'):
            field, value = 'data32', fields['data']
        elif form in ('14a', '14d'):
            # 14d is the absolute short-word load/store form. Its 32-bit
            # address needs the same relocation as the normal-word form.
            field, value = 'addr32', fields['addr']
        if field:
            target = mapper(value, required=required)
            # A relative branch to an unchanged external address still needs
            # a new displacement when its instruction moves.
            if target != value or (field == 'rel24' and dest != lo):
                assert ins.length_bytes == 6
                fixed = C.S.retarget(ins.raw, field, dest+pc-lo, target)
                off = 2*(pc-lo)
                result[off:off+6] = C.S.to_bytes(fixed)
                changes.append(dict(pc=hex(pc), form=form, field=field,
                                    before=hex(value), after=hex(target)))
        text = sharcfn.render_instruction(pc, ins, memory, set(), collections.Counter(), [])[0]
        listing.append(f'{pc:08x} -> {dest+pc-lo:08x} {text}')
        pc += ins.length_bytes//2
    assert pc == hi
    return bytes(result), changes, listing


def build(folder):
    folder.mkdir(parents=True, exist_ok=False)
    old, base = C.DONOR.read_bytes(), BASE.read_bytes()
    assert C.SHA(old) == C.DONOR_SHA and C.SHA(base) == BASE_SHA
    k = C.M.Digikit(C.SRC/'toolchains/digikit')
    donor = k.ldr.LoadedMemory.from_stream(old)
    native = k.ldr.LoadedMemory.from_stream(base)
    twins = []
    for name, lo, hi, dest in NATIVE_SPANS:
        code, changes, _ = relocate(k, donor, lo, hi, dest)
        actual = native.read_sw(dest, len(code))
        assert code == actual, (name, 'native body differs')
        twins.append(dict(name=name, donor=hex(lo), native=hex(dest),
                          bytes=len(code), sha256=C.SHA(code), bindings=changes))
    # Registers, DMA base and all three interrupt IDs match. The final mutable
    # context pointer is zero at boot in both images.
    lp_old = donor.read(C.S.data_address(LP0_OLD), 24)
    lp_new = native.read(C.S.data_address(LP0_NATIVE), 24)
    assert lp_old == lp_new == struct.pack('<6I', 0x30ffe000, 0x30fff000, 0x51, 0x52, 0xa8, 0)
    blocks, records = [], []
    for name, lo, hi, dest in SPANS:
        code, changes, listing = relocate(k, donor, lo, hi, dest)
        blocks.append((C.S.code_address(dest), code))
        (folder/(name+'.asm')).write_text('\n'.join(listing)+'\n')
        records.append(dict(name=name, donor=hex(lo), end=hex(hi), target=hex(dest),
                            bytes=len(code), sha256=C.SHA(code), bindings=changes))
    state = bytearray(0x6100)
    for name, lo, hi, dest in DATA:
        payload = donor.read(C.S.data_address(lo), hi-lo)
        assert payload is not None, name
        state[dest-STATE:dest-STATE+len(payload)] = payload
    blocks.append((C.S.data_address(STATE), bytes(state)))
    placed = []
    for addr, payload in blocks:
        assert 0x282e5000 <= addr < addr+len(payload) <= 0x28300000
        assert not any(a < addr+len(payload) and addr < a+len(b)
                       for a,b in (*C.B.load_regions(base), *placed)), hex(addr)
        placed.append((addr, payload))
    result = C.B.insert_before_final(base, b''.join(C.B.block(a,b) for a,b in blocks))
    (folder/'section_7.bin').write_bytes(result)
    receipt = dict(baseline_sha256=BASE_SHA, donor_sha256=C.DONOR_SHA,
                   section7_sha256=C.SHA(result), spans=records, native_twins=twins,
                   data=[dict(name=n, donor=hex(a), target=hex(d), bytes=b-a)
                         for n,a,b,d in DATA], pool=hex(POOL),
                   lp0_table=hex(LP0_NATIVE), entries={n:hex(mapped(a)) for n,a in {
                       'slot_get':0x1c3f78, 'slot_set':0x1c3fe5,
                       'guards':0x1c400f, 'page_copy':0x1c403c,
                       'callback':0x1c7e1f, 'initialize':0x1c7ec5,
                       'submit':0x1c834a, 'register_callback':0x1c83ff,
                       'open':0x1c8895}.items()}, startup_hook=False, flash_ready=False,
                   remaining=['Startup integration and LP0 ownership',
                              'DN2 DDR controller capacity and pool ownership',
                              'Original allocator/loader and voice slot binding',
                              'Hardware transfer and audio validation'])
    (folder/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ('section7_sha256','entries','startup_hook','flash_ready')},indent=2))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
