#!/usr/bin/env python3
"""Small donor-versus-relocated setup comparison for all five Machines.

Exercises native setup/setter code with explicit donor-shaped fixtures.
Does not claim DN2 caller integration or hardware playback.
"""
from pathlib import Path
import argparse, hashlib, json, struct, sys
import build_dt2_sampler_dsp as C
sys.path.insert(0,str(C.ROOT/'output/dn2-research/oneshot-native-bounds-dt2-20261008'))
from native_conversion_model import NativeConversionModel
import sharc_dn2_fixups as fx
F=lambda x:struct.unpack('<I',struct.pack('<f',x))[0]
REC,TABLE,NOTE,TEMPO,META,STACK=0x2f0000,0x2f1000,0x2f2000,0x2f2100,0x2f2200,0x2fffc0


def execute(dk,mem,name,relocated,*,note=60,seed=1):
    old=C.ENTRIES[name+'-setup'];entry=C.mapped(old) if relocated else old
    exit=C.EXIT if relocated else 0x1c65fe
    regs={f'{b}{n}':0 for b in ('R','I') for n in range(16)}
    regs.update(R9=F(64),R6=1,R11=F(48000),R8=F(note),I4=TABLE+0x4c,I14=TABLE+0x4c,
                I15=REC+0x188,I0=META+0x100,I9=TEMPO,M8=NOTE,I6=STACK,I7=STACK-64,
                M5=0,M6=1,M7=0xffffffff,M13=0,M14=1,M15=0xffffffff)
    runner=dk.run.Runner(mem,entry,regs=regs,explicit_memory_model=True,approx_recips=True)
    def poke(at,value):dk.st._dm_write(runner.state,at,4,dk.st.Const(value&0xffffffff))
    for at in range(0x2f0000,0x300000,4):poke(at,0)
    before=bytearray(0x1d8)
    struct.pack_into('<I',before,0,0x19000000)
    struct.pack_into('<I',before,0x184,48000)
    struct.pack_into('<Q',before,0x188,7200)
    struct.pack_into('<q',before,0x1b0,999<<31)
    before[0x1b8]=1;before[0x1ba]=seed
    for i in range(0,len(before),4):poke(REC+i,struct.unpack_from('<I',before,i)[0])
    values={4:F(.125),8:F(.5),20:2,24:3,28:1,32:4,48:450}
    if name=='WERP':values.update({20:2,36:1,40:0,44:0,60:100000000})
    for off,value in values.items():poke(TABLE+off,value)
    for at,value in [(NOTE,F(note)),(TEMPO,F(120)),(META+0x100-76,900),
                     (META+0x100-80,450)]:poke(at,value)
    fix=fx.Fixups();NativeConversionModel(dk.st,mem,0x16f700 if relocated else 0xb88f70).install(fix)
    status,stop,count=fx.run(runner,20000,fix,stop_at=[exit,C.FAULT if relocated else 0xb8907a])
    assert status=='stop' and stop==exit,(name,relocated,status,stop,count)
    after=b''.join(struct.pack('<I',dk.st._dm_read(runner.state,REC+i,4).value) for i in range(0,len(before),4))
    assert runner.state.uregs[dk.st.UREG_CODES['I7']].value==regs['I7'],name
    return after,{'instructions':count,'fixups':dict(fix.counts)}


def main(folder):
    report=json.loads((folder/'build-receipt.json').read_text());raw=(folder/'section_7.bin').read_bytes()
    assert C.SHA(raw)==report['section7_sha256']
    dk=C.M.Digikit(C.SRC/'toolchains/digikit');fx.bind(str(C.SRC/'toolchains/digikit/tools'))
    old=dk.ldr.LoadedMemory.from_stream(C.DONOR.read_bytes());new=dk.ldr.LoadedMemory.from_stream(raw)
    rows=[]
    for name in ('GRID','WERP','REPITCH','STRETCH','SLICE'):
        for note,seed in ((60,1),(72,0)):
            a,da=execute(dk,old,name,False,note=note,seed=seed)
            b,db=execute(dk,new,name,True,note=note,seed=seed)
            assert a==b,(name,note,[(i,x,y) for i,(x,y) in enumerate(zip(a,b)) if x!=y])
            rows.append({'machine':name,'note':note,'seed':seed,'record_exact':True,
                         'bounds':[struct.unpack_from('<q',b,off)[0] for off in (0x198,0x1a0,0x190)],
                         'donor':da,'relocated':db})
            print(name,note,seed,'exact',flush=True)
    result={'ok':True,'section7_sha256':C.SHA(raw),'cases':rows,
            'scope':'Ten native setup/setter comparisons; full 472-byte record and stack depth. Explicit normalized donor input fixtures.',
            'limitations':['No DN2 frame conversion, live dispatch or hardware test',
                           'Alternate renderer relocated but not executed here',
                           'Existing emulator instruction fixups and byte-bound int64 conversion overlay retained']}
    (folder/'setup-check.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    main(p.parse_args().folder)
