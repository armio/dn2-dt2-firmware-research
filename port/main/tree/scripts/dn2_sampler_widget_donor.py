#!/usr/bin/env python3
"""DT2 sampler draw companions and original bitmap assets for the DN2 port."""
import struct
import build_dn2_sampler_encoder_sensitivity as E

B = E.B
DONOR_SHA = '57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'
# Extracted from companion initializer 401BDEE2..401C33C0. Each tuple:
# donor ID, flags, draw invoker, flags-write address, draw-copy/callback address.
_DESCRIPTORS = (
    (200, 0x4, 0x400c8884, 0x401c255e, 0x401c2572),
    (201, 0x0, 0x400c6470, 0x401c25a0, 0x401c25b4),
    (202, 0x20, 0x400c2d52, 0x401c25e4, 0x401c25fe),
    (203, 0x20, 0x400c1edc, 0x401c2626, 0x401c263a),
    (204, 0x20, 0x400c6470, 0x401c2672, 0x401c2686),
    (205, 0x24, 0x400c7c32, 0x401c26b6, 0x401c26ca),
    (206, 0x40, 0x400c19be, 0x401c26fa, 0x401c270e),
    (207, 0x40, 0x400c19be, 0x401c273e, 0x401c2752),
    (208, 0x40, 0x400c674c, 0x401c2782, 0x401c27b8),
    (209, 0x20, 0x400c654a, 0x401c27e0, 0x401c27f4),
    (210, 0x4, 0x400c8884, 0x401c2818, 0x401c2830),
    (211, 0x0, 0x400c6470, 0x401c285a, 0x401c2872),
    (212, 0x20, 0x400c2d52, 0x401c289e, 0x401c28b6),
    (213, 0x20, 0x400c1edc, 0x401c28da, 0x401c28ee),
    (214, 0x24, 0x400c7c32, 0x401c291e, 0x401c2932),
    (215, 0x24, 0x400c7f36, 0x401c2962, 0x401c2976),
    (216, 0x20, 0x400c8032, 0x401c29a6, 0x401c29ba),
    (217, 0x24, 0x400c7d52, 0x401c29ea, 0x401c29fe),
    (218, 0x20, 0x400c654a, 0x401c2a2e, 0x401c2a42),
    (219, 0x4, 0x400c8884, 0x401c2a6a, 0x401c2a7e),
    (220, 0x0, 0x400c6470, 0x401c2aac, 0x401c2ac0),
    (221, 0x20, 0x400c2d52, 0x401c2af0, 0x401c2b04),
    (222, 0x20, 0x400c1edc, 0x401c2b2c, 0x401c2b40),
    (223, 0x24, 0x400c7c32, 0x401c2b70, 0x401c2b84),
    (224, 0x40, 0x400c19be, 0x401c2bb4, 0x401c2bc8),
    (225, 0x40, 0x400c19be, 0x401c2bf8, 0x401c2c0c),
    (226, 0x24, 0x400c7d52, 0x401c2c38, 0x401c2c52),
    (227, 0x20, 0x400c654a, 0x401c2c80, 0x401c2c94),
    (228, 0x4, 0x400c8884, 0x401c2cb8, 0x401c2cd0),
    (229, 0x0, 0x400c6470, 0x401c2d00, 0x401c2d18),
    (230, 0x20, 0x400c2d52, 0x401c2d3c, 0x401c2d5a),
    (231, 0x20, 0x400c1edc, 0x401c2d7c, 0x401c2d90),
    (232, 0x24, 0x400c7c32, 0x401c2dbe, 0x401c2dde),
    (233, 0x40, 0x400c19be, 0x401c2e10, 0x401c2e24),
    (234, 0x40, 0x400c19be, 0x401c2e58, 0x401c2e72),
    (235, 0x24, 0x400c7e44, 0x401c2ea2, 0x401c2eb6),
    (236, 0x20, 0x400c654a, 0x401c2ee6, 0x401c2efa),
    (237, 0x4, 0x400c8884, 0x401c2f22, 0x401c2f36),
    (238, 0x0, 0x400c6470, 0x401c2f64, 0x401c2f78),
    (239, 0x20, 0x400c2d52, 0x401c2fa8, 0x401c2fbc),
    (240, 0x20, 0x400c1edc, 0x401c2fe4, 0x401c2ff8),
    (241, 0x24, 0x400c7c32, 0x401c3028, 0x401c303c),
    (242, 0x44, 0x400c80de, 0x401c306c, 0x401c3080),
    (243, 0x44, 0x400c81aa, 0x401c30b0, 0x401c30c4),
    (244, 0x40, 0x400c824a, 0x401c30f4, 0x401c3108),
    (245, 0x20, 0x400c654a, 0x401c3132, 0x401c314c),
    (246, 0x4, 0x400c8884, 0x401c3170, 0x401c3188),
    (247, 0x0, 0x400c6470, 0x401c31b2, 0x401c31ca),
    (248, 0x20, 0x400c2d52, 0x401c31fc, 0x401c3214),
    (249, 0x20, 0x400c1edc, 0x401c3238, 0x401c324c),
    (250, 0x20, 0x400c6470, 0x401c327c, 0x401c3290),
    (251, 0x24, 0x400c7c32, 0x401c32c0, 0x401c32d4),
    (252, 0x44, 0x400c80de, 0x401c3304, 0x401c3318),
    (253, 0x44, 0x400c81aa, 0x401c3348, 0x401c335c),
    (254, 0x20, 0x400c654a, 0x401c338c, 0x401c33a0),
 )
# Bitmap constructor401121D6 arguments extracted from graphics initializer
# 4015C00C. Vector constructor401E29E8 copies these contiguous 28-byte objects.
# global -> (is_vector, height, width, first pixel plane, mask plane, count).
_ASSETS = {
    0x44f35e3c: (False, 17, 17, 0x402e25f8, 0x402e25b4, 1),
    0x44f35f94: (True, 17, 7, 0x402e3f24, 0x402e3ee0, 4),
    0x44f36304: (True, 17, 7, 0x402e983c, 0x402e97f8, 3),
    0x44f3655c: (True, 17, 5, 0x402ef9a8, 0x402ef964, 3),
    0x44f3664c: (True, 17, 17, 0x402f4270, 0x402f422c, 4),
    0x44f3669c: (False, 17, 17, 0x402f4830, 0x402f47ec, 1),
    0x44f36a50: (False, 17, 17, 0x402fed50, 0x402fed0c, 1),
    0x44f36a94: (True, 17, 5, 0x402fef58, 0x402fef14, 4),
    0x44f36c68: (True, 17, 17, 0x40305bc8, 0x40305b84, 5),
}
_SPECIAL = ((0x400c7d52, 0x400c7e44, 217), (0x400c7e44, 0x400c7f36, 235),
            (0x400c7f36, 0x400c8032, 215), (0x400c8032, 0x400c80de, 216),
            (0x400c80de, 0x400c81aa, 242), (0x400c81aa, 0x400c824a, 243),
            (0x400c824a, 0x400c82d0, 244))


def donor_descriptors(donor):
    assert B.T.SHA(donor) == DONOR_SHA
    return {pid: dict(flags=flags, callback=drawer, flags_at=hex(at), draw_init=hex(draw_at))
            for pid, flags, drawer, at, draw_at in _DESCRIPTORS}


def build_callbacks(doc, base, out):
    """Return (aligned bytes, donor->recipient callback map, audit evidence)."""
    donor, native = B.M.S.DONOR.read_bytes(), B.M.RECIPIENT.read_bytes()
    assert B.T.SHA(donor) == DONOR_SHA and base % 4 == 0
    blob = bytearray()
    evidence = dict(donor_sha256=DONOR_SHA, callbacks=[], assets=[], planes=[], fonts=[])
    mapping = {0x400c2d52:0x400bd30a, 0x400c1edc:0x400bc50c,
               0x400c19be:0x400bbfee, 0x400c654a:0x400c08fc,
               0x400c6470:0x400c0822, 0x400c7c32:0x47a53ae2,
               0x400c674c:0x47a53c02}
    bindings = {0x400da204:0x400dbff0, 0x40114334:0x40115ca8,
                0x40113e88:0x401157fc, 0x40113cf4:0x40115668,
                0x400e1742:0x400e31ea,
                0x4023deb8:0x402170ba, 0x4023deb9:0x402170bb,
                0x40240924:0x40219c2d, 0x40241104:0x4021a713,
                0x4025da35:0x4021222c,
                0x402a9134:0x40293c64, 0x402a1cf4:0x4028c824}
    clamp = next(s for s in doc['source_dialogs']['spans'] if s['donor']=='0x4019a6ba')
    assert clamp['end']=='0x4019a6e2'
    bindings[0x4019a6ba] = int(clamp['runtime'],16)
    for old in (0x4023deb8,0x4023deb9,0x40240924,0x40241104,0x4025da35):
        text=donor[old-B.BASE:donor.index(b'\0',old-B.BASE)+1]
        new=bindings[old]
        assert native[new-B.BASE:new-B.BASE+len(text)]==text
    for old,new,size in ((0x402a9134,0x40293c64,0x56c),(0x402a1cf4,0x4028c824,0x760)):
        a=donor[old-B.BASE:old-B.BASE+size];b=native[new-B.BASE:new-B.BASE+size]
        assert a[:8]==b[:8] and a[20:]==b[20:]
        for n in (8,12,16):assert struct.unpack_from('>I',a,n)[0]-old==struct.unpack_from('>I',b,n)[0]-new
        evidence['fonts'].append(dict(donor=hex(old),native=hex(new),bytes=size))

    def add(data):
        result=base+len(blob);blob.extend(data);blob.extend(bytes((-len(blob))%4));return result
    planes={}
    def plane(old):
        if old not in planes:
            data=donor[old-B.BASE:old-B.BASE+68]
            pos=native.find(data)
            new=pos+B.BASE if pos>=0 else add(data)
            planes[old]=new
            evidence['planes'].append(dict(donor=hex(old),address=hex(new),bytes=68,
                                           source='native identical pixels' if pos>=0 else 'copied donor pixels'))
        return planes[old]
    for old,(vector,height,width,pixels,mask,count) in _ASSETS.items():
        pixel_addresses=[plane(pixels+i*68) for i in range(count)];mask_at=plane(mask)
        objects=add(b''.join(struct.pack('>7I',0x4020650c,height,width,1,p,mask_at,0) for p in pixel_addresses))
        bindings[old]=add(struct.pack('>3I',objects,objects+28*count,objects+28*count)) if vector else objects
        evidence['assets'].append(dict(donor=hex(old),address=hex(bindings[old]),objects=hex(objects),
                                       count=count,height=height,width=width,kind='vector' if vector else 'bitmap'))
    for start,end,pid in _SPECIAL:
        code=bytearray(donor[start-B.BASE:end-B.BASE]);edits=[]
        rows=list(B.M.S.disasm(donor,B.BASE,start,end))
        for operand,target,_,_ in B.M.operands(rows):
            assert target in bindings,(hex(start),hex(target))
            off=operand-start;struct.pack_into('>I',code,off,bindings[target])
            edits.append(dict(offset=off,donor=hex(target),binding=hex(bindings[target])))
        # Original drawer clamps against this Machine parameter's descriptor.
        # Map the descriptor ID; preserve its value, formatting and bitmap logic.
        token=b'\x48\x78'+struct.pack('>H',pid);off=code.index(token)+2
        assert code.count(token)==1
        native_id=doc['source_parameters']['records'][str(pid)]['native']
        struct.pack_into('>H',code,off,native_id)
        target=add(code);mapping[start]=target
        evidence['callbacks'].append(dict(donor=hex(start),end=hex(end),runtime=hex(target),bytes=len(code),
            descriptor=dict(offset=off,donor=pid,native=native_id),relocations=edits))
    evidence.update(base=hex(base),bytes=len(blob),sha256=B.T.SHA(blob))
    return bytes(blob),mapping,evidence
