#!/usr/bin/env python3
"""Restore DT2's original bank/slot SAMP drawer over the old proof-name hack."""
from pathlib import Path
import argparse,json,shutil,struct
import build_dt2_directory_model as L
B=L.B
SHA='22d84fdf6f4862a780cdeaa3e2f1ab5fe94f0371a891e1a3c2bd78cef3657312'
DONOR,ENTRY,SIZE=0x400c7c32,0x47a53ae2,288
OLD_SHA='783b3dadf8ddabda27c8c9e8c27ceed3220674e11e354cbb602ed312fb1c1e33'
BINDINGS={0x40113cf4:0x40115668,0x40112cb2:0x40114626,
          0x40112ece:0x40114842,0x402a96a0:0x402941d0,
          0x4023a62d:0x40210858,0x4023deb8:0x402170ba,
          0x4025da35:0x4021222c,0x402299b7:0x40212b42,
          0x4024072f:0x402170bc}


def donor_drawer():
    donor,native=B.M.S.DONOR.read_bytes(),B.M.RECIPIENT.read_bytes()
    code=bytearray(donor[DONOR-B.BASE:DONOR-B.BASE+SIZE]);edits=[]
    for at,target,mn,ops in B.M.operands(list(B.M.S.disasm(donor,B.BASE,DONOR,DONOR+SIZE))):
        dest=BINDINGS[target];struct.pack_into('>I',code,at-DONOR,dest)
        edits.append(dict(donor_operand=hex(at),runtime_operand=hex(ENTRY+at-DONOR),
                          donor_target=hex(target),native_target=hex(dest)))
    assert code[12:16]==bytes.fromhex('222f0024'),'Original callback must consume the actual slot argument'
    assert code[196:204]==bytes.fromhex('2006ee807207c081'),'Original bank computation must remain intact'
    strings=[]
    for old,new in BINDINGS.items():
        if 0x40200000<=old<0x40290000:
            def string(raw,at):
                off=at-B.BASE;return raw[off:raw.index(0,off)+1]
            a,b=string(donor,old),string(native,new);assert a==b
            strings.append(dict(donor=hex(old),native=hex(new),text=a[:-1].decode()))
    for old,new,n in ((0x40112cb2,0x40114626,412),(0x40112ece,0x40114842,90)):
        assert donor[old-B.BASE:old-B.BASE+n]==native[new-B.BASE:new-B.BASE+n]
    return bytes(code),edits,strings


def build(folder,out):
    raw=bytearray((folder/'main-os.bin').read_bytes());assert B.T.SHA(raw)==SHA
    doc=json.loads((folder/'build-receipt.json').read_text());assert doc['main_sha256']==SHA
    copy=next(c for c in doc['copies'] if int(c['destination'],16)<=ENTRY<int(c['destination'],16)+c['bytes'])
    offset=int(copy['source'],16)-B.BASE+ENTRY-int(copy['destination'],16)
    before=bytes(raw[offset:offset+SIZE]);assert B.T.SHA(before)==OLD_SHA
    after,relocations,strings=donor_drawer();raw[offset:offset+SIZE]=after
    doc['samp_slot_display']=dict(base=str((folder/'main-os.bin').resolve()),base_sha256=SHA,
        donor=hex(DONOR),entry=hex(ENTRY),bytes=SIZE,copy=copy,file_offset=hex(offset),
        before_sha256=OLD_SHA,after_sha256=B.T.SHA(after),relocations=relocations,strings=strings,
        change='Restore original DT2 bank letter, raw slot number and OFF drawing; remove fixed three-sample name lookup and bank-letter suppression.',
        display='Original DT2 A1/A127/B1 etc.; per-bank slot zero displays OFF.',
        native_samp_ids=[doc['slot_maps'][str(k)][3] for k in range(5,11)],
        limits=['Display-only; no parameter, sample storage, loading or DSP change. Hardware display confirmation remains pending.'])
    doc.update(main_sha256=B.T.SHA(raw),flash_ready=False)
    out.mkdir(parents=True,exist_ok=False)
    (out/'main-os.bin').write_bytes(raw)
    for name in ('runtime.bin','bootstrap.S','fn_new_map.txt','ram_map.txt'):shutil.copy2(folder/name,out/name)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(main_sha256=doc['main_sha256'],entry=hex(ENTRY),restored_bytes=SIZE),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    p.add_argument('--out',type=Path,required=True);a=p.parse_args();build(a.folder,a.out)
