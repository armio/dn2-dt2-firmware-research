#!/usr/bin/env python3
"""Register native sampler control maps in the current development MAIN.

This is an integration component, not a flashable release. Native Machine
views, the project pool and metadata producers are subsequent connections.
"""
from pathlib import Path
import argparse, json, struct
import build_dt2_sampler_table as T
from dnfw.oneshot import coldfire as O
BASE=T.BASE;BE=lambda v:struct.pack('>I',v&0xffffffff)
INPUT=T.ROOT/'output/dn2-research/dt2-sampler-table-complete-records-20261009'
INPUT_SHA='a43ed6b1f5b548ad20dd079b74273be17a0c075b6abffedf86d5a2e55f8fc35d'
TYPES={'ONESHOT':5,'WERP':6,'STRETCH':7,'REPITCH':8,'GRID':9,'SLICE':10}


def read(raw,va,n):
    # The existing initializer copies this exact ONESHOT blob before BSS clear.
    if 0x47a38000<=va<0x47a38a00:va=0x4032fac0+va-0x47a38000
    return raw[va-BASE:va-BASE+n]


def build(out):
    raw=INPUT.joinpath('main-os.bin').read_bytes();assert T.SHA(raw)==INPUT_SHA
    controls=json.loads(INPUT.joinpath('controls.json').read_text())
    out.mkdir(parents=True,exist_ok=False)
    image=bytearray(raw);image.extend(bytes(-len(image)%4))
    def put(data):
        at=BASE+len(image);image.extend(data);return at
    def words(v):return b''.join(BE(x) for x in v)
    def cstr(s):return put(s.encode('ascii')+b'\0')
    def align():image.extend(bytes(-len(image)%4))
    oldnames=read(raw,0x47a38400,72);oldattrs=read(raw,0x47a38448,24)
    names=bytearray(oldnames)
    for name,short in [('Werp','WER'),('Stretch','STR'),('Repitch','REP'),('Grid','GRD'),('Slice','SLC')]:
        names.extend(words([cstr(name),cstr(short),0]))
    align();name_va=put(names);attr_va=put(oldattrs+oldattrs[4:8]*5)
    machine_list=[0,2,1,3,5,6,7,8,9,10,4];list_va=put(words(machine_list))
    maps={5:list(struct.unpack('>40I',read(raw,0x47a38480,160)))}
    descriptors={};owners=[0]*47
    for m in controls['machines']:
        kind=TYPES[m['machine']];mapping=maps.setdefault(kind,[0]*40)
        for rec in m['records']:
            mapping[rec['slot']-25]=rec['entry'];owners[rec['entry']-321]=kind
        if kind==5:continue
        # Descriptors hold COW std::string character pointers, not raw C strings.
        # The earlier controls-only component had never exposed its descriptors.
        title=put(O.cow_rep(m['machine']))+12;subtitle=put(O.cow_rep('SOURCE'))+12
        descriptors[kind]=put(words([title,subtitle,*m['page_entries'],10]))
    align();map_va=put(words([v for kind in range(5,11) for v in maps[kind]]))
    descriptor_va=put(words([descriptors[kind] for kind in range(6,11)]))
    owner_va=put(words(owners));code_va=BASE+len(image)
    source=f'''.text
.global sampler_slot,sampler_overview,sampler_count,sampler_page,sampler_owner,sampler_group
sampler_slot:
 move.l 12(%sp),%d0
 cmpi.l #5,%d0
 bcs.w slot_old
 cmpi.l #10,%d0
 bhi.w slot_old
 move.l %a0,%d1
 subi.l #25,%d1
 cmpi.l #39,%d1
 bhi.w slot_old
 subi.l #5,%d0
 move.l #160,%d2
 mulu.l %d2,%d0
 lea {map_va:#x},%a1
 adda.l %d0,%a1
 move.l (%a1,%d1.l*4),%d0
 move.l (%sp)+,%d2
 rts
slot_old:
 jmp 0x47a38800
sampler_overview:
 move.l 4(%sp),%d0
 subi.l #6,%d0
 cmpi.l #4,%d0
 bhi.w overview_old
 lea {descriptor_va:#x},%a0
 move.l (%a0,%d0.l*4),%d0
 rts
overview_old:
 jmp 0x47a38830
sampler_count:
 move.l 4(%sp),%d0
 subi.l #6,%d0
 cmpi.l #4,%d0
 bhi.w count_old
 moveq #1,%d0
 rts
count_old:
 jmp 0x47a3884a
sampler_page:
 move.l 4(%sp),%d0
 subi.l #6,%d0
 cmpi.l #4,%d0
 bhi.w page_old
 tst.l 8(%sp)
 bne.s page_empty
 lea {descriptor_va:#x},%a0
 move.l (%a0,%d0.l*4),%d0
 rts
page_empty:
 move.l #0x42432bd4,%d0
 rts
page_old:
 jmp 0x47a53ca0
sampler_owner:
 move.l %d2,%d0
 subi.l #321,%d0
 cmpi.l #46,%d0
 bhi.s owner_old
 lea {owner_va:#x},%a1
 move.l (%a1,%d0.l*4),%d0
 mvs.b 222(%a0),%d3
 cmp.l %d0,%d3
 bne.s owner_reject
 moveq #1,%d3
 bra.s owner_return
owner_reject:
 moveq #-1,%d3
owner_return:
 move.l (%sp)+,%a1
 move.l %d2,-(%sp)
 jmp (%a1)
owner_old:
 jmp 0x47a3888a
sampler_group:
 move.l 4(%sp),%d0
 cmpi.l #10,%d0
 bhi.s group_invalid
 cmpi.l #4,%d0
 beq.s group_midi
 moveq #1,%d0
 rts
group_midi:
 moveq #2,%d0
 rts
group_invalid:
 moveq #0,%d0
 rts
.balign 4
'''
    (out/'registration.S').write_text(source)
    T.run([T.BIN/'gas/as-new','-mcpu=5475',out/'registration.S','-o',out/'registration.o'])
    T.run([T.BIN/'ld/ld-new',f'-Ttext={code_va:#x}','-e','sampler_slot',out/'registration.o','-o',out/'registration.elf'])
    T.run([T.BIN/'binutils/objcopy','-O','binary','-j','.text',out/'registration.elf',out/'registration.bin'])
    (out/'registration.asm').write_text(T.run([T.BIN/'binutils/objdump','-d',out/'registration.elf']))
    symbols={}
    for line in T.run([T.BIN/'binutils/nm-new','--defined-only',out/'registration.elf']).splitlines():
        fields=line.split()
        if len(fields)==3 and fields[2].startswith('sampler_'):symbols[fields[2]]=int(fields[0],16)
    put((out/'registration.bin').read_bytes());patches=[]
    def patch(at,old,new,why):
        assert len(old)==len(new) and read(raw,at,len(old))==old,(hex(at),read(raw,at,len(old)).hex())
        image[at-BASE:at-BASE+len(old)]=new
        patches.append(dict(address=hex(at),before=old.hex(),after=new.hex(),why=why))
    patch(O.LIST_ALLOC,bytes.fromhex('48780018'),bytes.fromhex('4878002c'),'11-entry Machine list allocation')
    patch(O.LIST_CAP,bytes.fromhex('41e80018'),bytes.fromhex('41e8002c'),'11-entry Machine list capacity')
    for at,old,new in [(O.LIST_BEGIN,0x47a38460,list_va),(O.LIST_END,0x47a38478,list_va+44)]:
        patch(at+2,BE(old),BE(new),'Machine list bounds')
    for bound,at,op,col in O.NAME_SITES:
        patch(bound,bytes.fromhex('7205'),bytes.fromhex('720a'),'name upper bound')
        patch(at+2,BE(0x47a38400+col),BE(name_va+col),'11 name rows')
    for at in O.ATTR_BOUNDS:
        opcode='74' if at==0x400dc19c else '72'
        patch(at,bytes.fromhex(opcode+'05'),bytes.fromhex(opcode+'0a'),'permission upper bound')
    for at,col in O.ATTR_BASES:patch(at+2,BE(0x47a38448+col),BE(attr_va+col),'11 permission rows')
    patch(O.LOAD_BOUND,bytes.fromhex('7407'),bytes.fromhex('740c'),'stored sounds preserve types -1..10')
    for at,old,name,opcode in [(O.SLOT_HOOK,0x47a38800,'sampler_slot','4ef9'),
                              (O.OVERVIEW_FN,0x47a38830,'sampler_overview','4ef9'),
                              (O.COUNT_FN,0x47a3884a,'sampler_count','4ef9'),
                              (O.PAGE_FN,0x47a53ca0,'sampler_page','4ef9'),
                              (O.VALID_SITE,0x47a3888a,'sampler_owner','4eb9')]:
        patch(at,bytes.fromhex(opcode)+BE(old),bytes.fromhex(opcode)+BE(symbols[name]),name)
    patch(O.GROUP_FN,read(raw,O.GROUP_FN,6),b'\x4e\xf9'+BE(symbols['sampler_group']),'group all sampler Machines with audio Machines')
    (out/'main-os.bin').write_bytes(image)
    report=dict(baseline_sha256=INPUT_SHA,main_sha256=T.SHA(image),bytes=len(image),symbols=symbols,
                names=hex(name_va),attributes=hex(attr_va),machine_list=machine_list,machine_list_va=hex(list_va),
                slot_maps=maps,descriptors=descriptors,owners=owners,patches=patches,flash_ready=False,
                remaining=['Native SourcePageView and extra pages/browser',
                           'WERP position and SLICE marker producers','Project sample pool',
                           'Full startup/assignment/frame integration and hardware validation'])
    (out/'build-receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('main_sha256','bytes','flash_ready')}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
