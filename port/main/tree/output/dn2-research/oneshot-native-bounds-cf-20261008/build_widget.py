#!/usr/bin/env python3
"""Produce only new standalone widget code. Never modify input MAIN or firmware."""
from pathlib import Path
import hashlib,json,struct,subprocess
P=Path(__file__).resolve().parent
ROOT=P.parents[2]
J=ROOT/'firmware/ghidra/storage-proof/oneshot-storage-merge-v1'
T=ROOT/'output/dn2-research/oneshot-gui-dt2-20261008/widget-twins.json'
BASE=0x40000400
LOAD=0x47a52a00
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(J/'runtime-candidate/main-os.bin').read_bytes()
donor=(J/'inputs/dt2-main.bin').read_bytes()
assert sha(raw)=='a44c4584e82e0e5bedcdc5a46a479ecd70c74c6b21340d58e73a5aa44634c77a'
assert sha(donor)=='57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d'
verified=[]
for row in json.loads(T.read_text()):
    if len(row['dn2_twins'])!=1: continue
    lo=int(row['dt2'],16)-BASE;n=row['size'];peer=int(row['dn2_twins'][0],16)-BASE
    a=bytearray(donor[lo:lo+n]); b=raw[peer:peer+n]
    for r in row['relocations']:
        off=r['offset']; assert struct.unpack_from('>I',a,off)[0]==int(r['donor'],16)
        assert struct.unpack_from('>I',b,off)[0]==int(r['dn2'],16)
        struct.pack_into('>I',a,off,int(r['dn2'],16))
    assert a==b
    verified.append({'donor':row['dt2'],'dn2':row['dn2_twins'][0],'bytes':n,'relocated_exact':True})
native=raw[0x401104f8-BASE:0x40110864-BASE]
assert len(native)==876
REF=ROOT/'output/dn2-research/oneshot-gui-reference-20261008'
builtin_meta=json.loads((REF/'builtin-chirp.json').read_text())
dsp=(J/'package-final/native-extracted-7').read_bytes() if (J/'package-final/native-extracted-7').is_file() else None
if dsp is None:
    candidates=list((J/'package-final/native-extracted-7').rglob('*'))
    dsp=next(p.read_bytes() for p in candidates if p.is_file() and sha(p.read_bytes())==builtin_meta['dsp_sha256'])
assert sha(dsp)==builtin_meta['dsp_sha256']
head_at=int(builtin_meta['header_file_offset'],16)
header=struct.unpack_from('<5I',dsp,head_at)
assert list(header)==builtin_meta['bank_header']==[0x3142534f,1,0x311814,7200,48000]
pcm_at=head_at+(header[2]-0x310800)
assert pcm_at==int(builtin_meta['pcm_file_offset'],16)
pcm=dsp[pcm_at:pcm_at+7200*2]
assert sha(pcm)==builtin_meta['pcm_sha256']
samples=struct.unpack('<7200h',pcm);cache=bytearray(401)
for x in range(96):
    vals=[n>>8 for n in samples[x*7200//96:(x+1)*7200//96]]
    cache[0x10+x]=max([0]+vals)&255;cache[0x70+x]=min([0]+vals)&255
assert bytes(cache)==(REF/'builtin-chirp-native-cache.bin').read_bytes()
assert sha(cache)==builtin_meta['cache_sha256']
(P/'builtin-cache.bin').write_bytes(cache+b'\0'*3)
(P/'native-render.original.bin').write_bytes(native)
(P/'native-render.bin').write_bytes(native)
BIN=J/'toolchain/build'
def run(args):
    r=subprocess.run([str(x) for x in args],cwd=P,capture_output=True,text=True)
    if r.returncode: raise RuntimeError(r.stdout+r.stderr)
    return r.stdout
def assemble():
    run([BIN/'gas/as-new','-mcpu=5475',P/'widget.S','-o',P/'widget.o'])
    run([BIN/'ld/ld-new','-Ttext='+hex(LOAD),'-e','0','--no-warn-rwx-segments',P/'widget.o','-o',P/'widget.elf'])
    run([BIN/'binutils/objcopy','-O','binary','-j','.text',P/'widget.elf',P/'widget.bin'])
    return {r[2]:int(r[0],16) for line in run([BIN/'binutils/nm-new','--defined-only',P/'widget.elf']).splitlines() if len(r:=line.split())==3}
symbols=assemble()
clone=bytearray(native);changes=[]
for at,old,new,why in [(0x22,0x401b91ca,symbols['os_wave_getter'],'private immutable UI cache'),
                      (0x34,0x40001608,symbols['os_wave_noop'],'private cache needs no native mutex acquire'),
                      (0x4a,0x4000172a,symbols['os_wave_noop'],'private cache needs no native mutex release')]:
    assert struct.unpack_from('>I',clone,at)[0]==old
    struct.pack_into('>I',clone,at,new)
    changes.append({'offset':at,'old':hex(old),'new':hex(new),'why':why})
(P/'native-render.bin').write_bytes(clone)
assert assemble()==symbols
code=(P/'widget.bin').read_bytes()
assert LOAD+len(code)<=0x47a53a00
assert symbols['os_wave_cache_poll']==0x47a52a00 and symbols['os_wave_draw']==0x47a52c20
assert raw[0x401103e4-BASE:0x4011046c-BASE]==donor[0x4010ea70-BASE:0x4010eaf8-BASE]
dump=run([BIN/'binutils/objdump','-d','-m','m68k:cfv4e',P/'widget.elf'])
assert '<unknown>' not in dump
(P/'widget.asm').write_text(dump)
result={'ok':True,'scope':'Native DT2 raw parameter marker convention; uncomposed standalone component','load':hex(LOAD),
        'end':hex(LOAD+len(code)),'bytes':len(code),'sha256':sha(code),'workspace_bytes':0x240,
        'workspace_recommendation':'0x47a56c00','native_twins_verified':verified,'native_clone_changes':changes,
        'symbols':{k:hex(v) for k,v in symbols.items() if k.startswith('os_wave_')},
        'main_sha256':sha(raw),'donor_sha256':sha(donor),
        'native_body_unmodified_except_three_address_operands':True,
        'builtin_chirp':{'dsp_sha256':sha(dsp),'pcm_sha256':sha(pcm),'cache_sha256':sha(cache),'frames':7200,'exact_root_extraction_match':True},
        'source_sha256':sha((P/'widget.S').read_bytes()),'twins_sha256':sha(T.read_bytes())}
(P/'build.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
if __name__=='__main__': pass
