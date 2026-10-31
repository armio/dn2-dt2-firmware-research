#!/usr/bin/env python3
"""Connect imported Source/SLICE cursors to native DN2 voice allocation."""
from pathlib import Path
import argparse, json, re
import build_dn2_sample_cursor_readers as P
B=P.B
INPUT=B.T.ROOT/'output/dn2-research/dn2-sample-cursor-readers-20261009'
SHA='1ecb836d1088025e7576d7a7444284828bef0a2d370f9fd0ae22f9d92454d0fa'

def build(out):
    raw=(INPUT/'main-os.bin').read_bytes(); assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text()); copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray((INPUT/'runtime.bin').read_bytes()); at=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    asm=(B.T.ROOT/'scripts/asm/dn2_sample_cursor_tracks.S').read_text()
    payload.extend(B.R.assemble(asm,at,out,'cursor-tracks'))
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'cursor-tracks.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    names=dict(position_coarse='cursor_track_coarse',position_fine='cursor_track_fine',active='cursor_track_active')
    patches=[]
    for old in doc['sample_cursor_readers']['patches']:
        operand=int(old['operand'],16); before=int(old['after'],16)
        after=symbols[names[old['reader']]]
        assert payload[operand-base:operand-base+4]==B.BE(before)
        payload[operand-base:operand-base+4]=B.BE(after)
        for component in doc.values():
            if not isinstance(component,dict): continue
            for edit in component.get('edits',[]):
                if edit.get('runtime')==old['operand']:
                    assert edit['binding']==hex(before)
                    edit['binding']=hex(after)
        patches.append({**old,'before':hex(before),'after':hex(after)})
    assert base+len(payload)<=int(doc['runtime_limit'],16) and len(payload)%4==0
    image=bytearray(raw[:src-B.BASE])+payload; boot=B.BASE+len(image)
    bootstrap=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(bootstrap,boot,out,'bootstrap'))
    image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
               runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
               bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['sample_cursor_tracks']=dict(methods={k:hex(v) for k,v in symbols.items() if k.startswith('cursor_track_')},
        patches=patches,native_preferred_voice='0x4002b20e',owner_array='0x80005308',
        behavior='Prefer native last allocated voice if owned and active; fall back to first active owned voice; otherwise inactive.',
        limits=['Owner and audio reply updates are asynchronous; a UI frame can lag voice reassignment.',
                'MAIN/DSP/FS composition and physical validation remain.'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),cursor=doc['sample_cursor_tracks']),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out)
