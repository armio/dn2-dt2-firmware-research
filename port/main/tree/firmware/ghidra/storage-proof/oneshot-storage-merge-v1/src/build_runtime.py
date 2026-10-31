#!/usr/bin/env python3
"""Provisional normal-mode MAIN. Container/DSP approval belongs to root."""
from pathlib import Path
import hashlib, importlib.util, json, shutil, struct, sys
sys.dont_write_bytecode=True
import build_merge as B
J=B.JOB; OUT=J/'runtime-candidate'; SHA=B.SHA; BE=B.BE
S,WORKER=0x47A56000,0x47A52000

def main():
    OUT.mkdir(exist_ok=True)
    source=J.parents[0]/'sample-file-v1/candidate/main-os.bin'
    base=source.read_bytes()
    assert SHA(base)=='769860b6360e67a20c4147acf6f8e1c365dc94f12c8c1f1bbcdafb8ac8b7379c'
    sample_recipe=json.loads(source.with_name('build-receipt.json').read_text())
    (J/'inputs/sample-main.bin').write_bytes(base)
    (J/'inputs/sample-build-receipt.json').write_text(json.dumps(sample_recipe,indent=2)+'\n')
    tiny=(J/'inputs/tiny-main.bin').read_bytes()
    copy=(J/'copy-only/candidate/main-os.bin').read_bytes()
    stock=(J/'inputs/stock-main.bin').read_bytes()
    raw=bytearray(base);edits=[]
    def patch(va,new,old,why):
        at=va-B.BASE;assert raw[at:at+len(new)]==old,(hex(va),why)
        raw[at:at+len(new)]=new
        edits.append({'address':hex(va),'before':old.hex(),'after':new.hex(),'why':why})
    # Reuse the frozen source-level V7 relocation, including its stock mode gate.
    at=0
    while at<B.APP:
        if copy[at]==tiny[at]:at+=1;continue
        start=at
        while at<B.APP and copy[at]!=tiny[at]:at+=1
        patch(B.BASE+start,copy[start:at],tiny[start:at],'frozen copy-only V7 relocation/normal-mode overlay')
    worker_source=(J/'src/storage_worker.S').read_text()
    bank_source=int(sample_recipe['extension']['sample_source_file_offset'],16)
    bank=base[bank_source:bank_source+47104]
    assert SHA(bank)=='49f680159d2019f5e53e24b013177c5612ebabf5c7e4714ab6d9ef659afff542'
    assert b'/sample_808_snare_20261008_v1.osb\0' in worker_source.encode().replace(b'"',b'\0')
    worker=B.assemble(worker_source,base=WORKER,name='storage-worker',code_end_symbol='worker_code_end')
    syms={r[2]:int(r[0],16) for line in B.run([B.BIN/'binutils/nm-new','--defined-only',B.WORK/'storage-worker/code.elf']).splitlines() if len(r:=line.split())==3}
    assert len(worker)%4==0 and WORKER+len(worker)<=0x47A56000
    chunk=(J/'copy-only/candidate/oneshot-chunk.bin').read_bytes()
    chunk_offset=len(raw);raw.extend(chunk)
    worker_offset=len(raw);raw.extend(worker)

    # Extend only the old unknown-command arm. Its byte length stays10; all
    # existing commands and packing/routing remain the V7 implementation.
    src=J/'src/runtime-probe'
    if not src.exists():shutil.copytree(B.V7/'csrc/usbprobe',src)
    text=(B.V7/'csrc/usbprobe/probe.S').read_text()
    old='''        moveq   #2, %d0                 | unknown command
        move.b  %d0, 3(%a2)
        bra.w   80f'''
    assert text.count(old)==1
    text=text.replace(old,f'''        jsr     {syms['os_request']:#x} | explicit once/boot load request; no I/O here
        bra.w   80f''')
    text=text.replace('.equ PROTO,       3','.equ PROTO,       4')
    text=text.replace('| There is no write command, and none can be added by a request: the\n| dispatcher only knows the three below.', '| No arbitrary write API exists. Command4 requests the fixed readonly sample load\n| through a deferred UI worker; the three existing diagnostics are unchanged.')
    (src/'probe.S').write_text(text)
    pg=B.load_module('runtime_usb_generator',B.V7/'scripts/gen_usbprobe_code.py')
    pg.RAM=B.PROBE;pg.SRC=src;B.cbuild.build=B.assembly_build
    probe=pg.compose(stock)
    before=json.loads((J/'copy-only/candidate/usbprobe-relocated.json').read_text())
    before_by_va={e['va']:e for e in before['edits']}
    for e in probe['edits']:
        va=e['va'];n=bytes.fromhex(e['new']);o=bytearray.fromhex(before_by_va[va]['new'])
        if va==probe['cave']['va']:
            tag_at=probe['tag']['va']-va;size=probe['tag']['length']
            o[tag_at:tag_at+size]=b'os1fs-merge-v1'.ljust(size,b'\0')
            nb=bytearray(n);nb[tag_at:tag_at+size]=b'os1fs-live-v1'.ljust(size,b'\0');n=bytes(nb)
        patch(va,n,bytes(o),'protocol4 exact fixed sample-load request')

    patch(0x4002E464,b'\x4e\xb9'+BE(syms['os_ui_hook']),bytes.fromhex('4eb94011d2f4'),'UI task readonly sample worker; stock isDirty tailcall')
    patch(0x40025E82,b'\x4e\xf9'+BE(syms['os_frame_hook']),bytes.fromhex('2039402876f8'),'ISR prepared-frame/ACK only; native send remains')
    # The offline/maintenance sample writer and FSINIT dispatcher must not be
    # another entry to the worker's shared filesystem or sample buffer.
    patch(0x400CE1C2,stock[0x400CE1C2-B.BASE:0x400CE1C8-B.BASE],bytes.fromhex('4ef946800094'),'retire prior custom FS/SAMPLE console dispatcher; normal worker owns filesystem entry')
    assert raw[0x4002E462-B.BASE:0x4002E464-B.BASE]==bytes.fromhex('2f0a')
    assert raw[0x4002E46A-B.BASE:0x4002E46E-B.BASE]==bytes.fromhex('588f4a00')
    copies=[(B.BASE+B.APP,B.GB,B.OLD_G),
            (B.BASE+B.ANNEX,B.EXT,sample_recipe['extension']['copy_bytes']),
            (B.BASE+bank_source,0x47A3A000,47104),
            (B.BASE+chunk_offset,B.CHUNK,len(chunk)),
            (B.BASE+worker_offset,WORKER,len(worker))]
    asm='move.l %a1,-(%sp)\nmove.l %a2,-(%sp)\n'
    for i,(src_va,dst,n) in enumerate(copies):
        assert n%4==0
        asm+=f'''move.l #{n//4},%d1
lea {src_va:#x},%a2
lea {dst:#x},%a1
copy_{i}:
move.l (%a2),(%a1)+
lea 4(%a2),%a0
subq.l #1,%d1
movea.l %a0,%a2
bne.w copy_{i}
'''
    for name,at,n in [('probe',B.PROBE,0x900),('worker',S,0x1000)]:
        asm+=f'''move.l #{n//4},%d1
lea {at:#x},%a0
clear_{name}:
clr.l (%a0)+
subq.l #1,%d1
bne.w clear_{name}
'''
    for address,value in [(S,0x4F534C31),(S+0xA8,47104),(S+0xAC,0x310800)]:
        asm+=f'move.l #{value:#x},%d0\nmove.l %d0,{address:#x}\n'
    asm+=f'movea.l (%sp)+,%a2\nmovea.l (%sp)+,%a1\njmp {B.GB+0x26:#x}\n'
    copier=B.assemble(asm,base=B.BASE+B.ANNEX,name='runtime-copier')
    assert len(copier)<=0x100,len(copier)
    patch(B.BASE+B.ANNEX,copier+bytes.fromhex('4e71')*((256-len(copier))//2),base[B.ANNEX:B.ANNEX+256],'five exact pre-BSS copies and bounded probe/worker initialization')
    # All native filesystems and their full source data are preserved exactly.
    assert raw[B.APP:B.ANNEX]==base[B.APP:B.ANNEX]
    assert raw[B.ANNEX+256:len(base)]==base[B.ANNEX+256:]
    assert raw[bank_source:bank_source+47104]==bank
    (OUT/'main-os.bin').write_bytes(raw);(OUT/'worker.bin').write_bytes(worker)
    for name in ['fn_new_map.txt','ram_map.txt']:
        assert (J/'inputs'/name).read_bytes()==source.with_name(name).read_bytes()
        (OUT/name).write_bytes((J/'inputs'/name).read_bytes())
    (OUT/'worker-symbols.json').write_text(json.dumps(syms,indent=2)+'\n')
    (OUT/'probe.json').write_text(json.dumps(probe,indent=2)+'\n')
    result={'ok':True,'status':'Offline provisional; requires approved matching DSP loader and native/emitted integration before packaging.','main_sha256':SHA(raw),'bytes':len(raw),
      'sample_base_sha256':SHA(base),'sample_sha256':SHA(bank),'sample_full_le32_sum':hex(sum(struct.unpack('<11776I',bank))&0xffffffff),
      'worker_sha256':SHA(worker),'worker_source_sha256':SHA(worker_source.encode()),'worker_bytes':len(worker),'worker_code_end':hex(syms['worker_code_end']),
      'copier_bytes':len(copier),'copies':[{'source':hex(s),'destination':hex(d),'bytes':n} for s,d,n in copies],
      'clear_ranges':[[hex(B.PROBE),hex(B.PROBE+0x900)],[hex(S),hex(S+0x1000)]],
      'native_fs_bodies_maps_unchanged':True,'sample_source_unchanged':True,'format_or_write_api_in_worker':False,
      'producer_hook_enabled':True,'required_dsp_protocol':'bank-loader-v1 command4 + sticky reply-word6 ownership; do not pair with untouched V7 section7',
      'host_protocol_sha256':SHA((J/'host-protocol.json').read_bytes()),'symbols':{k:hex(v) for k,v in syms.items() if k.startswith('os_')},'edits':edits,'builder_sha256':SHA(Path(__file__).read_bytes())}
    (OUT/'build-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in ('ok','status','main_sha256','bytes','worker_bytes','copier_bytes','sample_full_le32_sum')},indent=2))

if __name__=='__main__':main()
