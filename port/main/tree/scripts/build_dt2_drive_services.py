#!/usr/bin/env python3
"""Link DT2 directory/identity/path services to the existing filesystem port.

Donor instructions and local branches are retained. External PC-relative
code references use nearby absolute-jump veneers; data references use the
filesystem's established RAM map. No UI hook or flash package is produced.
"""
from pathlib import Path
import argparse, json, re, struct
import build_dt2_pool_lock_references as L
B = L.B
INPUT = B.T.ROOT/'output/dn2-research/dt2-pool-lock-references-20261009'
SHA = '1fbddffc7e5973e8630bc64f9d1e3a0e19910049b339381e315155b939edcb6a'
MAPS = B.T.ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v3/src'
SERVICES = {
    'resolve_identity': 0x4015b178, 'get_path': 0x401575f6,
    'open_directory': 0x40156fc4, 'next_entry': 0x40157072,
    'rewind_directory': 0x40156fb2, 'valid_object': 0x4015b93e,
    'valid_virtual_object': 0x4015bfbc, 'is_directory': 0x4015bb34,
    'find_child': 0x401574e2, 'parent_object': 0x40155ea8,
}


def mapping(path):
    return {int(a,16):int(b,16) for a,b in (line.split() for line in path.read_text().splitlines())}


def build(out):
    raw = (INPUT/'main-os.bin').read_bytes(); assert B.T.SHA(raw) == SHA
    donor = B.M.S.DONOR.read_bytes(); assert B.T.SHA(donor) == B.M.S.SHA
    native = B.M.RECIPIENT.read_bytes()
    doc = json.loads((INPUT/'build-receipt.json').read_text()); copy = doc['runtime_copy']
    base, src = int(copy['destination'],16), int(copy['source'],16)
    payload = bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']])
    out.mkdir(parents=True,exist_ok=False)
    fn = mapping(MAPS/'fn_new_map.txt'); ram = mapping(MAPS/'ram_map.txt')
    bindings = {**fn, **ram, 0x400015a0:0x400015a0, 0x400016d2:0x400016d2}
    # These two leaf libc functions have complete literal native twins.
    for old, new in [(0x401360ac,0x40134490),(0x4018a498,0x4017ed4c)]:
        end,_ = B.M.function(donor,old)
        assert donor[old-B.BASE:end-B.BASE] == native[new-B.BASE:new-B.BASE+end-old]
        bindings[old] = new
    def append(blob):
        payload.extend(bytes(-len(payload)%4)); at = base+len(payload)
        payload.extend(blob); return at
    # get_path(NULL output buffer) uses the final byte of a private256B buffer.
    path_buffer = append(bytes(256)); bindings[0x44e6bc07] = path_buffer+255
    spans = []
    for name, old in SERVICES.items():
        end, rows = B.M.function(donor,old)
        at = append(donor[old-B.BASE:end-B.BASE]); bindings[old] = at
        relative = []
        for pc,hx,mn,ops in rows:
            match = re.search(r'\$([0-9a-f]{8})\(pc\)',ops)
            if match and not old <= int(match[1],16) < end:
                assert mn.split('.')[0] in ('jsr','lea'), (hex(pc),mn,ops)
                assert len(bytes.fromhex(hx)) == 4
                relative.append((pc,int(match[1],16)))
        veneers = {target:append(b'\x4e\xf9'+bytes(4)) for _,target in relative}
        spans.append((name,old,end,at,rows,relative,veneers))
    edits = []
    def patch(pc, at, width, old, new, why):
        edits.append(dict(donor=hex(pc),runtime=hex(at),bytes=width,
                          target=hex(old),binding=hex(new),reason=why))
    for name,old,end,at,rows,relative,veneers in spans:
        for pc,target,_,_ in B.M.operands(rows):
            assert target in bindings, ('unresolved',hex(old),hex(target))
            dest = bindings[target]
            struct.pack_into('>I',payload,at-base+pc-old,dest)
            patch(pc,at+pc-old,4,target,dest,'Explicit absolute binding')
        for target,veneer in veneers.items():
            assert target in bindings and target < 0x401ed000, hex(target)
            struct.pack_into('>I',payload,veneer-base+2,bindings[target])
        for pc,target in relative:
            dest = veneers[target]; delta = dest-(at+pc-old+2)
            assert -32768 <= delta < 32768
            struct.pack_into('>h',payload,at-base+pc-old+2,delta)
            patch(pc+2,at+pc-old+2,2,target,dest,'Nearby code veneer preserves local branches')
        fn[old] = at
    payload.extend(bytes(-len(payload)%4))
    assert base+len(payload) <= int(doc['runtime_limit'],16)
    image = bytearray(raw[:src-B.BASE])+payload; boot = B.BASE+len(image)
    bootstrap = (INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8] = b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),
        drive_services=dict(methods={name:hex(bindings[old]) for name,old in SERVICES.items()},
            donor_methods={name:hex(old) for name,old in SERVICES.items()},
            path_buffer=hex(path_buffer),edits=edits,
            filesystem_maps={name:B.T.SHA((MAPS/name).read_bytes()) for name in ('fn_new_map.txt','ram_map.txt')},
            connected_to_picker=False,
            remaining=['Directory view model and SamplePicker','Project pool identity table','Sample loading and UI integration']))
    (out/'main-os.bin').write_bytes(image); (out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for filename,table in [('fn_new_map.txt',fn),('ram_map.txt',ram)]:
        (out/filename).write_text(''.join(f'{a:#010x} {b:#010x}\n' for a,b in sorted(table.items())))
    for name,old,end,at,rows,relative,veneers in spans:
        (out/(name+'.asm')).write_text('\n'.join(f'{pc:08x} -> {at+pc-old:08x} {hx:24s} {mn:10s} {ops}' for pc,hx,mn,ops in rows)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),methods=doc['drive_services']['methods']),indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
