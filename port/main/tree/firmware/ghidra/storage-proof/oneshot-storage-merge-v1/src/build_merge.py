#!/usr/bin/env python3
"""Offline raw MAIN composition; no container, device, or media operation."""
from pathlib import Path
from dataclasses import dataclass
import hashlib, importlib.util, json, re, struct, subprocess, sys

sys.dont_write_bytecode = True
JOB = Path(__file__).resolve().parents[1]
IN, OUT, WORK = JOB/'inputs', JOB/'candidate', JOB/'assembly'
V7 = IN/'v7-source'
sys.path.insert(0, str(V7/'src'))
from dnfw.patch import assemble as gas, cbuild, loader
from dnfw.transplant import cfplan, oneshot_cf
from dnfw.oneshot import coldfire as old_cf

BASE, APP, GB = 0x40000400, 0x30B580, 0x46800000
OLD_G, ANNEX, EXT = 0x16F90, 0x322510, 0x47A36000
CHUNK, PROBE = 0x47A38000, 0x47A39000
SHA = lambda x: hashlib.sha256(x).hexdigest()
BE = lambda x: struct.pack('>I', x)
BIN = JOB/'toolchain/build'
TOOL = gas.Toolchain((str(BIN/'gas/as-new'),), (str(BIN/'ld/ld-new'),),
                     (str(BIN/'binutils/objcopy'),), False)

def load_module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def run(args):
    r=subprocess.run([str(x) for x in args],capture_output=True,text=True)
    if r.returncode:raise RuntimeError(f'{args}\n{r.stdout}\n{r.stderr}')
    return r.stdout

def assemble(source, *, base, name='generated', code_end_symbol=None):
    """Keep every GNU source/object/disassembly beside the raw result."""
    p=WORK/name;p.mkdir(exist_ok=True)
    (p/'code.s').write_text('.text\n'+source+'\n')
    run([TOOL.as_argv[0],'-mcpu=5475',p/'code.s','-o',p/'code.o'])
    run([TOOL.ld_argv[0],f'-Ttext=0x{base:x}','-e','0','--no-warn-rwx-segments',p/'code.o','-o',p/'code.elf'])
    run([TOOL.objcopy_argv[0],'-O','binary','-j','.text',p/'code.elf',p/'code.bin'])
    dump_args=[BIN/'binutils/objdump','-d','-m','m68k:cfv4e']
    if code_end_symbol:
        symbols={row[2]:int(row[0],16) for line in run([BIN/'binutils/nm-new','--defined-only',p/'code.elf']).splitlines() if len(row:=line.split())==3}
        dump_args.append('--stop-address='+hex(symbols[code_end_symbol]))
    dump=run(dump_args+[p/'code.elf'])
    assert '<unknown>' not in dump and not cbuild.SCALE8.search(dump)
    (p/'code.asm').write_text(dump)
    return (p/'code.bin').read_bytes()

class Linked:
    def __getitem__(self, name):return self.symbols[name]
    def routines(self):return {k:v for k,v in self.symbols.items() if self.kinds.get(k) in ('t','T')}

def assembly_build(sources, *, base, include=(), entries=(), defines=None):
    """Assembly-only equivalent of cbuild; uses no C compiler or libgcc."""
    assert len(sources)==1 and Path(sources[0]).suffix=='.S'
    name=Path(sources[0]).stem+'-'+hex(base)+'-'+str((defines or {}).get('RAM','ext'))
    p=WORK/name;p.mkdir(exist_ok=True)
    args=['clang','-E','-P','-x','assembler-with-cpp','-D__ASSEMBLER__']
    for q in include:args+=['-I',q]
    for key,value in (defines or {}).items():args+=['-D'+key+'='+str(value)]
    source=run(args+[sources[0]]);(p/'preprocessed.s').write_text(source)
    # The original code uses one text section, including its static counters.
    image=assemble(source,base=base,name=name)
    nm=run([BIN/'binutils/nm-new','--defined-only',p/'code.elf'])
    (p/'symbols.txt').write_text(nm)
    symbols={};kinds={}
    for line in nm.splitlines():
        row=line.split()
        if len(row)==3:symbols[row[2]]=int(row[0],16);kinds[row[2]]=row[1]
    for entry in entries:assert entry in symbols
    result=Linked();result.image=image;result.bss=0;result.symbols=symbols;result.kinds=kinds;return result

def main():
    WORK.mkdir(exist_ok=True)
    stock=(IN/'stock-main.bin').read_bytes();tiny=(IN/'tiny-main.bin').read_bytes()
    v7=(V7/'out/os1handoff-v7/section_3_MAIN_OS.bin').read_bytes()
    dsp=(V7/'out/os1handoff-v7/section_7.bin').read_bytes();dt2=(IN/'dt2-main.bin').read_bytes()
    assert SHA(tiny)=='60229ed6654a8a3d4aa3df7df40f6491d4e088ca264b254ca7205918ec0c8e2d'
    assert SHA(v7)=='6b2e91a3e237674a6ba6cd0b8b1ae633ec195fc7fa5037e7030dd3b36c4a440d'
    assert SHA(dsp)=='b5b568a86d93041a0110a8df83cf17ad5a586d9b93c40882da40fb622a01bcb9'
    assert len(stock)==APP and len(tiny)==ANNEX+0x1920
    plan=cfplan.build(oneshot_cf.SPEC,dt2,stock);assert plan.ok,plan.refusals

    # Regenerate the original source first. Its emitted shims must exactly match
    # the shipped V7 recipe before the source-level base relocation is trusted.
    old_shims=old_cf.assemble_shims(lambda s,base:assemble(s,base=base,name='old-shims' if base==old_cf.SHIMS_VA else 'old-group'))
    saved=json.loads((V7/'src/dnfw/mods/oneshot_code.json').read_text())
    assert old_shims['code']==bytes.fromhex(saved['shims'])
    assert old_shims['group']==bytes.fromhex(saved['group'])
    assert old_shims['labels']==saved['labels']
    relocated=(V7/'src/dnfw/oneshot/coldfire.py').read_text().replace('CHUNK_VA = 0x46900000','CHUNK_VA = 0x47A38000')
    p=JOB/'src/oneshot_coldfire_relocated.py';p.write_text(relocated)
    new_cf=load_module('dnfw.oneshot.coldfire_relocated',p)
    new_shims=new_cf.assemble_shims(lambda s,base:assemble(s,base=base,name='new-shims' if base==new_cf.SHIMS_VA else 'new-group'))
    assert new_shims['group']==old_shims['group']

    # Compose the source-level parameter edits/chunk without installing V7's
    # independent startup loader. The unified copier below owns startup.
    original_install=loader.install
    def capture(content,chunks,**kwargs):return bytes(content)
    loader.install=capture
    try:
        old=old_cf.compose(stock,plan,old_shims)
        new=new_cf.compose(stock,plan,new_shims)
    finally:loader.install=original_install
    assert len(new['chunk'])==0xA00
    assert old['chunk']==v7[APP+40:APP+40+0xA00]

    pg=load_module('isolated_usbprobe_generator',V7/'scripts/gen_usbprobe_code.py')
    cbuild.build=assembly_build
    original_probe=pg.compose(stock)
    pg.RAM=PROBE
    relocated_probe=pg.compose(stock)
    def probe_image(spec,tag):
        raw=bytearray(stock)
        for e in spec['edits']:
            at=e['va']-BASE;before=bytes.fromhex(e['stock']);after=bytes.fromhex(e['new'])
            assert raw[at:at+len(before)]==before;raw[at:at+len(after)]=after
        at=spec['tag']['va']-BASE;n=spec['tag']['length']
        raw[at:at+n]=tag.encode().ljust(n,b'\0')
        return bytes(raw)
    old_probe=probe_image(original_probe,'os1handoff-v7')
    new_probe=probe_image(relocated_probe,'os1fs-merge-v1')
    # Reconstructed V7 prefix must match the real image byte-for-byte, except
    # its explicitly omitted startup hook/cave. No unaccounted behavioral edits.
    excluded=[(0x4000053E-BASE,8),(0x4028DA6E-BASE,138)]
    reconstructed=bytearray(stock)
    for component in [old['content'],old_probe]:
        for at,(a,b) in enumerate(zip(stock,component)):
            if a!=b:
                assert reconstructed[at] in (a,b)
                reconstructed[at]=b
    discrepancies=[at for at in range(APP) if reconstructed[at]!=v7[at]
                   and not any(x<=at<x+n for x,n in excluded)]
    assert not discrepancies,discrepancies[:20]

    raw=bytearray(tiny);edits=[]
    def patch(at,data,expected,why):
        assert raw[at:at+len(data)]==expected,(hex(at+BASE),why)
        edits.append({'address':hex(BASE+at),'file_offset':hex(at),'before':bytes(expected).hex(),'after':data.hex(),'why':why})
        raw[at:at+len(data)]=data
    for component,label in [(new['content'],'relocated ONESHOT source edits'),(new_probe,'relocated USB probe source edits')]:
        at=0
        while at<APP:
            if component[at]==stock[at]:at+=1;continue
            start=at
            while at<APP and component[at]!=stock[at]:at+=1
            patch(start,component[start:at],stock[start:at],label)
    # Remove only the explicit Maintenance force; native startup mode logic stays.
    gate=0x400CF088-BASE
    patch(gate,stock[gate:gate+6],bytes.fromhex('81b940287520'),'restore stock mode gate for normal playing')

    chunk_offset=len(raw);raw.extend(new['chunk'])
    ext_len=len(tiny)-ANNEX
    def loop(src,dest,size,name):
        assert size and size%4==0
        return f'''move.l #{size//4},%d1
lea {src:#x},%a2
lea {dest:#x},%a1
{name}:
move.l (%a2),(%a1)+
lea 4(%a2),%a0
subq.l #1,%d1
movea.l %a0,%a2
bne.w {name}
'''
    copier='move.l %a1,-(%sp)\nmove.l %a2,-(%sp)\n'
    copier+=loop(BASE+APP,GB,OLD_G,'copy_fs')
    copier+=loop(BASE+ANNEX,EXT,ext_len,'copy_extension')
    copier+=loop(BASE+chunk_offset,CHUNK,0xA00,'copy_oneshot')
    copier+=f'''move.l #{0x900//4},%d1
lea {PROBE:#x},%a0
clear_probe:
clr.l (%a0)+
subq.l #1,%d1
bne.w clear_probe
movea.l (%sp)+,%a2
movea.l (%sp)+,%a1
jmp {GB+0x26:#x}
'''
    code=assemble(copier,base=BASE+ANNEX,name='coordinated-copier')
    assert len(code)<=0x100
    # No new native function lives below EXT+0x100. Preserve every byte after
    # this dedicated copier slot, including all filesystem dispatch/function homes.
    patch(ANNEX,code+bytes.fromhex('4e71')*((0x100-len(code))//2),tiny[ANNEX:ANNEX+0x100],'coordinated pre-BSS copy; no filesystem/media call')
    assert raw[ANNEX+0x100:len(tiny)]==tiny[ANNEX+0x100:]
    assert raw[APP:ANNEX]==tiny[APP:ANNEX]
    assert raw[0x13E:0x146]==stock[0x13E:0x146]
    assert raw[0xB2:0xB9]==tiny[0xB2:0xB9]

    for name,data in [('main-os.bin',bytes(raw)),('section7.bin',dsp),('oneshot-chunk.bin',new['chunk']),('copier.bin',code)]:
        (OUT/name).write_bytes(data)
    for name in ['fn_new_map.txt','ram_map.txt']:(OUT/name).write_bytes((IN/name).read_bytes())
    (OUT/'usbprobe-relocated.json').write_text(json.dumps(relocated_probe,indent=2)+'\n')
    (OUT/'oneshot-layout.json').write_text(json.dumps(new['layout'],indent=2)+'\n')
    result={'ok':True,'scope':'Offline copy/relocation-only normal-mode prototype. No task worker, filesystem auto-init/mount/format, DSP loader or hardware validation.',
      'input_main_sha256':SHA(tiny),'v7_main_sha256':SHA(v7),'main_sha256':SHA(raw),'bytes':len(raw),'section7_sha256':SHA(dsp),
      'copier':{'source':hex(BASE+ANNEX),'bytes':len(code),'slot_bytes':0x100,'transfer':hex(GB+0x26)},
      'copies':[{'source':hex(BASE+APP),'destination':hex(GB),'bytes':OLD_G},{'source':hex(BASE+ANNEX),'destination':hex(EXT),'bytes':ext_len},{'source':hex(BASE+chunk_offset),'destination':hex(CHUNK),'bytes':0xA00}],
      'probe_clear':[hex(PROBE),hex(PROBE+0x900)],'reserved_sample_ranges':[['0x47a3a000','0x47a45800'],['0x47a46000','0x47a51800']],
      'v7_prefix_reconstructed_exact_outside_loader':True,'original_shims_reassembled_exact':True,'original_chunk_exact':True,
      'native_fs_original_graft_unchanged':True,'native_extension_after_copier_slot_unchanged':True,
      'normal_ui_hook_installed':False,'edits':edits,'old_layout':old['layout'],'new_layout':new['layout'],
      'toolchain_source_sha256':SHA((JOB/'toolchain/binutils-2.43.1.tar.xz').read_bytes()),'builder_sha256':SHA(Path(__file__).read_bytes())}
    (OUT/'build-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in ('ok','main_sha256','bytes','section7_sha256','copier','scope')},indent=2))

if __name__=='__main__':main()
