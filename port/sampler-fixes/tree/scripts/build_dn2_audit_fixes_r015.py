"""Build the local R015 candidate from a pinned R014 parent."""
import argparse
import copy
import json
from pathlib import Path
import shutil

import build_dn2_recovery_tail as tail
from build_dn2_sampler_fixes_r014 import BE, MARKER, need
from build_dt2_sampler_runtime import assemble

R014_FLAT = 'e2900a21dd4e1f0efceba7b574ac211afd2ed3ceef667fd960b9f894b6ea36d9'
R014_RUNTIME = '526e8e01d7738a4cc8ed0ee302c2048d92c8c8a95e030bd9f3c2185538b65451'
R014_STAGED = 'fc3959a3a59449d124f04e0ada46dada6c8075ee6ee327a0f0c48566b428274d'


class PatchContext:
    parent_build = 'R014'
    parent_flat = R014_FLAT
    parent_runtime = R014_RUNTIME
    parent_staged = R014_STAGED

    def __init__(self, parent, work):
        flat = parent/'expanded'
        self.doc = json.loads((flat/'build-receipt.json').read_text())
        raw = (flat/'main-os.bin').read_bytes()
        runtime = (flat/'runtime.bin').read_bytes()
        need(tail.sha(raw) == self.doc['main_sha256'] == self.parent_flat, 'wrong parent MAIN')
        need(tail.sha(runtime) == self.doc['runtime_sha256'] == self.parent_runtime, 'wrong parent runtime')
        region = self.doc['runtime_copy']
        self.base = int(region['destination'], 16)
        self.source = int(region['source'], 16)
        self.runtime_offset = self.source - tail.BASE
        self.original_size = len(runtime)
        start = self.runtime_offset
        end = start + len(runtime)
        need(self.doc['build'] == self.parent_build and region['bytes'] == len(runtime)
             and raw[start:end] == runtime and int(self.doc['bootstrap'],16) == tail.BASE+end,
             'unexpected parent layout')
        self.image = bytearray(raw[:end])
        self.bootstrap = raw[end:]
        self.edits = []
        self.additions = []
        self.work = work
        work.mkdir(parents=True, exist_ok=True)

    def replace(self, address, expected, replacement):
        size = len(expected)
        if self.base <= address and address+size <= self.base+self.original_size:
            offset = self.runtime_offset + address-self.base
        else:
            need(tail.BASE <= address and address+size <= self.source, 'patch outside parent')
            offset = address-tail.BASE
        need(size and size == len(replacement) and self.image[offset:offset+size] == expected,
             f'patch preimage differs at {address:#x}')
        self.image[offset:offset+size] = replacement
        self.edits.append(dict(address=hex(address), offset=offset, before=expected.hex(),
                               after=replacement.hex()))

    def append_asm(self, name, source):
        offset = len(self.image)
        address = self.base + offset-self.runtime_offset
        need(address % 4 == 0, 'unaligned runtime append')
        code = assemble(source, address, self.work, name)
        need(bool(code), f'empty {name} helper')
        code += bytes(-len(code) % 4)
        need(address+len(code) <= int(self.doc['runtime_limit'],16), 'runtime reservation exceeded')
        self.image.extend(code)
        self.additions.append(dict(name=name, address=hex(address), offset=offset,
                                   bytes=len(code), sha256=tail.sha(code)))
        return address


def verify_projection(expanded, doc):
    """Reverse the declared byte edits and runtime additions to recover pinned R014."""
    return verify_parent_projection(expanded, doc, 'R015', 'audit_fixes_r015', R014_FLAT)


def verify_parent_projection(expanded, doc, build_id, change_key, parent_flat):
    changes = doc[change_key]
    region = doc['runtime_copy']
    src = int(region['source'],16)-tail.BASE
    end = src+region['bytes']
    need(doc['build'] == build_id and int(doc['bootstrap'],16) == tail.BASE+end, 'bootstrap position differs')
    need(tail.sha(expanded[src:end]) == doc['runtime_sha256'], 'runtime differs')
    before = bytearray(expanded[:end])
    for item in reversed(changes['additions']):
        offset = item['offset']
        need(offset+item['bytes'] == len(before) and tail.sha(before[offset:]) == item['sha256'],
             'runtime helper differs')
        del before[offset:]
    for item in reversed(changes['edits']):
        offset = item['offset']
        after = bytes.fromhex(item['after'])
        need(before[offset:offset+len(after)] == after, 'recorded patch differs')
        before[offset:offset+len(after)] = bytes.fromhex(item['before'])
    bootstrap = expanded[end:]
    count = BE(region['bytes']//4)
    need(bootstrap.count(count) == 1, 'ambiguous runtime copy length')
    old_count = BE((len(before)-src)//4)
    need(tail.sha(before+bootstrap.replace(count,old_count)) == parent_flat,
         'image contains differences outside recorded patches')
    return expanded


def build(parent, out):
    import r015_used_samples
    import r015_held_locks
    import r015_slice_insert

    return build_revision(parent, out, PatchContext, 'R015', 'audit_fixes_r015',
                          (r015_used_samples, r015_held_locks, r015_slice_insert))


def build_revision(parent, out, context, build_id, change_key, modules):
    parent, out = parent.resolve(), out.resolve()
    need(not parent.is_relative_to(out) and not out.is_relative_to(parent),
         'output must be separate from the pinned input directory')
    ctx = context(parent, out/'asm')
    doc = copy.deepcopy(ctx.doc)
    changes = {module.__name__: module.apply(ctx) for module in modules}
    ctx.replace(MARKER,ctx.parent_build.encode('ascii'),build_id.encode('ascii'))
    runtime = bytes(ctx.image[ctx.runtime_offset:])
    old_boot = int(doc['bootstrap'],16)
    new_boot = tail.BASE+len(ctx.image)
    ctx.replace(tail.BASE+0xb2,b'\x4e\xf9'+BE(old_boot),b'\x4e\xf9'+BE(new_boot))
    old_count, count = BE(ctx.original_size//4), BE(len(runtime)//4)
    need(ctx.bootstrap.count(old_count) == 1, 'unexpected parent bootstrap')
    bootstrap = ctx.bootstrap.replace(old_count,count)
    raw_tail = bytes(ctx.image[tail.CUT-tail.BASE:])+bootstrap
    blob = tail.compress(3,tail.CUT,raw_tail).stored
    boot = json.loads((parent/'build-receipt.json').read_text())['boot_tail']
    need(tail.sha((parent/'main-os.bin').read_bytes()) == ctx.parent_staged, 'wrong staged parent')
    need(len(blob) <= len(runtime), 'compressed tail exceeds scratch')
    wrapper = tail.wrapper_bytes(len(blob),len(raw_tail))
    ctx.replace(tail.CAVE,tail.wrapper_bytes(boot['stored_bytes'],boot['expanded_tail_bytes']),wrapper)
    expanded = bytes(ctx.image)+bootstrap
    staged = expanded[:tail.CUT-tail.BASE]+blob
    boot.update(scratch_bytes=len(runtime), stored_bytes=len(blob), expanded_tail_bytes=len(raw_tail),
                stored_sha256=tail.sha(blob), tail_sha256=tail.sha(raw_tail), wrapper_bytes=len(wrapper),
                wrapper_sha256=tail.sha(wrapper), expanded_main_sha256=tail.sha(expanded),
                expanded_main_bytes=len(expanded))
    doc.pop('staged_main_sha256',None)
    changes.update(edits=ctx.edits, additions=ctx.additions, parent_expanded_sha256=ctx.parent_flat)
    doc[change_key] = changes
    doc.update(build=build_id, baseline_sha256=ctx.parent_staged, boot_tail=boot, bytes=len(staged),
               main_sha256=tail.sha(staged), runtime_sha256=tail.sha(runtime), bootstrap=hex(new_boot),
               flash_ready=False)
    doc['runtime_copy']['bytes'] = len(runtime)
    for patch in doc['frame_recorder']['patches']:
        if patch['name'] == 'identity':
            patch['after'] = build_id.encode('ascii').hex()
    need(tail.expand_verified(staged,doc) == expanded, 'restaged image does not match projection')
    flat_doc = copy.deepcopy(doc)
    flat_doc.pop('boot_tail')
    flat_doc.update(bytes=len(expanded), main_sha256=tail.sha(expanded), staged_main_sha256=tail.sha(staged))
    old_line = f'move.l #{ctx.original_size//4},%d1'
    boot_source = (parent/'bootstrap.S').read_text()
    need(boot_source.count(old_line) == 1, 'bootstrap source differs')
    for directory, data, receipt in ((out,staged,doc),(out/'expanded',expanded,flat_doc)):
        directory.mkdir(parents=True,exist_ok=True)
        (directory/'main-os.bin').write_bytes(data)
        (directory/'runtime.bin').write_bytes(runtime)
        (directory/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        (directory/'bootstrap.S').write_text(boot_source.replace(old_line,f'move.l #{len(runtime)//4},%d1'))
        for name in ('fn_new_map.txt','ram_map.txt'):
            shutil.copyfile(parent/name,directory/name)
    (out/'tail.aplib').write_bytes(blob)
    print(json.dumps(dict(build=build_id,staged=doc['main_sha256'],flat=flat_doc['main_sha256'],
                          helper_bytes=len(runtime)-ctx.original_size)))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    build(args.parent,args.out)
