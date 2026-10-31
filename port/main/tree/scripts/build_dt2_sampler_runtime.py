#!/usr/bin/env python3
"""Relocate sampler tables/registration out of MAIN's cleared tail at boot."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_sampler_registration as R
from dnfw.transplant import cfspec as C
T=R.T;BASE=R.BASE;BE=R.BE
INPUT=T.ROOT/'output/dn2-research/dt2-sampler-registration-v2-20261009'
INPUT_SHA='7b041b682624d1b6744d078e6b69abdcd707ad01a2348b856360396994c816f0'
RUNTIME,LIMIT=0x47a58000,0x47a60000


def assemble(source,at,out,name):
    (out/(name+'.S')).write_text(source)
    T.run([T.BIN/'gas/as-new','-mcpu=5475',out/(name+'.S'),'-o',out/(name+'.o')])
    T.run([T.BIN/'ld/ld-new',f'-Ttext={at:#x}','-e','0',out/(name+'.o'),'-o',out/(name+'.elf')])
    T.run([T.BIN/'binutils/objcopy','-O','binary','-j','.text',out/(name+'.elf'),out/(name+'.bin')])
    (out/(name+'.asm')).write_text(T.run([T.BIN/'binutils/objdump','-d',out/(name+'.elf')]))
    return (out/(name+'.bin')).read_bytes()


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert T.SHA(raw)==INPUT_SHA
    reg=json.loads((INPUT/'build-receipt.json').read_text())
    table=json.loads((R.INPUT/'build-receipt.json').read_text())
    controls=json.loads((R.INPUT/'controls.json').read_text())
    start=int(table['record0_va'],16);end=BASE+len(raw);size=end-start
    assert start==BASE+len(T.BASELINE.read_bytes()) and size%4==0 and RUNTIME+size<=LIMIT
    out.mkdir(parents=True,exist_ok=False)
    delta=RUNTIME-start;image=bytearray(raw);changes=[];touched=set()
    def relocated(v):return v+delta if start<=v<end else v
    def pointer(at,why):
        assert at not in touched,hex(at)
        val=struct.unpack_from('>I',image,at-BASE)[0];new=relocated(val)
        if new!=val:
            struct.pack_into('>I',image,at-BASE,new);touched.add(at)
            changes.append(dict(address=hex(at),before=hex(val),after=hex(new),why=why))
    # Only declared instruction operands and pointer-typed fields are changed.
    for row in table['patches']:
        if start<=row['now']<end:pointer(row['va'],row['what'])
    pointer(0x400c241a,'companion accessor hook')
    for row in reg['patches']:
        data=bytes.fromhex(row['after']);at=int(row['address'],16)
        for off in range(0,len(data)-3,2):
            value=struct.unpack_from('>I',data,off)[0]
            if start<=value<end:pointer(at+off,row['why'])
    for n in range(368):
        for off in C.POINTERS:pointer(start+60*n+off,'parameter record pointer')
    for m in controls['machines']:
        if m['descriptor_va']:
            at=int(m['descriptor_va'],16)
            for off in (0,4):pointer(at+off,'unexposed original control descriptor string')
    for at in reg['descriptors'].values():
        for off in (0,4):pointer(at+off,'registered descriptor COW string')
    for n in range(11):
        for off in (0,4,8):pointer(int(reg['names'],16)+12*n+off,'Machine name')
    # The five descriptor pointers immediately precede the 47 ownership words.
    reg_code=reg['symbols']['sampler_slot'];descriptors_at=reg_code-47*4-5*4
    assert raw[descriptors_at-BASE:descriptors_at-BASE+20]==b''.join(BE(reg['descriptors'][str(k)]) for k in range(6,11))
    for n in range(5):pointer(descriptors_at+4*n,'descriptor lookup table')
    code_ranges=[]
    for folder,name,entry in [(R.INPUT,'companion',int(table['companion_hook_va'],16)),
                              (INPUT,'registration',reg_code)]:
        source=(folder/(name+'.S')).read_text()
        source=re.sub(r'0x[0-9a-fA-F]+',lambda m:hex(relocated(int(m[0],16))),source)
        code=assemble(source,relocated(entry),out,name)
        old=(folder/(name+'.bin')).read_bytes();assert len(code)==len(old)
        image[entry-BASE:entry-BASE+len(code)]=code;code_ranges.append((entry,entry+len(code)))
    # Fail if an old-tail pointer remains in payload data. Code is rebuilt by
    # the linker above, never searched/replaced as a bag of integer constants.
    stale=[]
    for at in range(start,end-3,2):
        if any(a<=at<b for a,b in code_ranges):continue
        val=struct.unpack_from('>I',image,at-BASE)[0]
        if start<=val<end:stale.append((hex(at),hex(val)))
    assert not stale,stale
    bootstrap_at=end
    source=f'''.text
.global sampler_bootstrap
sampler_bootstrap:
 lea -16(%sp),%sp
 movem.l %d0-%d1/%a0-%a1,(%sp)
 lea {start:#x},%a0
 lea {RUNTIME:#x},%a1
 move.l #{size//4},%d1
copy:
 move.l (%a0)+,(%a1)+
 subq.l #1,%d1
 bne.s copy
 movem.l (%sp),%d0-%d1/%a0-%a1
 lea 16(%sp),%sp
 jmp 0x4030b980
.balign 4
'''
    bootstrap=assemble(source,bootstrap_at,out,'bootstrap')
    assert raw[0xb2:0xb8]==b'\x4e\xf9'+BE(0x4030b980)
    image[0xb2:0xb8]=b'\x4e\xf9'+BE(bootstrap_at);image.extend(bootstrap)
    payload=bytes(image[start-BASE:end-BASE]);(out/'runtime.bin').write_bytes(payload)
    (out/'main-os.bin').write_bytes(image)
    # Export the relocated registration metadata for the same native checks.
    relocated_reg={**reg,'main_sha256':T.SHA(image),
                   'symbols':{k:relocated(v) for k,v in reg['symbols'].items()},
                   'descriptors':{k:relocated(v) for k,v in reg['descriptors'].items()},
                   'names':hex(relocated(int(reg['names'],16))),
                   'attributes':hex(relocated(int(reg['attributes'],16))),
                   'machine_list_va':hex(relocated(int(reg['machine_list_va'],16)))}
    report={**relocated_reg,'baseline_sha256':INPUT_SHA,'bytes':len(image),
            'runtime_copy':{'source':hex(start),'destination':hex(RUNTIME),'bytes':size},
            'runtime_sha256':T.SHA(payload),'runtime_limit':hex(LIMIT),
            'bootstrap':hex(bootstrap_at),'bootstrap_bytes':len(bootstrap),
            'relocated_pointer_fields':changes,'relinked_code':[(hex(a),hex(b)) for a,b in code_ranges],
            'layout_basis':'Extends declared private storage after 0x47a57000, with 4 KiB gap; below bank-0 stack top 0x48000000. Existing five copies and state/buffer allocations unchanged.',
            'flash_ready':False,'remaining':['Machine assignment/frame path','Native SourcePageView/browser and sample pool',
                                           'WERP position and SLICE marker producers','Hardware validation of expanded runtime allocation']}
    (out/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('main_sha256','runtime_copy','bootstrap','flash_ready')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
