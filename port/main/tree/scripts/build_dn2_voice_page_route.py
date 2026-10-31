#!/usr/bin/env python3
"""Link native VOICE page factories/controller and patch the two event slots."""
from pathlib import Path
import argparse,json,re,struct
import build_dt2_sample_manager as S
B=S.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-manager-20261009'
SHA='aac076620333d59f92420431baee93fcd81a8c32ce8ae6399970d358eff98cf2'


def build(out):
    raw=(INPUT/'main-os.bin').read_bytes();assert B.T.SHA(raw)==SHA
    doc=json.loads((INPUT/'build-receipt.json').read_text());copy=doc['runtime_copy']
    src,base=int(copy['source'],16),int(copy['destination'],16)
    payload=bytearray(raw[src-B.BASE:src-B.BASE+copy['bytes']]);at=base+len(payload)
    out.mkdir(parents=True,exist_ok=False)
    methods=doc['sample_manager']['methods']
    source=f'.equ sample_manager_factory,{methods["factory"]}\n.equ sample_manager_event,{methods["view_event"]}\n'
    source+=(B.T.ROOT/'scripts/asm/dn2_voice_page_route.S').read_text()
    source+=(B.T.ROOT/'scripts/asm/dn2_voice_page_open.S').read_text()
    code=B.R.assemble(source,at,out,'voice-page-route')
    nm=B.T.run([B.T.BIN/'binutils/nm-new','-n',out/'voice-page-route.elf'])
    symbols={m[2]:int(m[1],16) for m in re.finditer(r'(?m)^([0-9a-f]+) [Tt] (\w+)$',nm)}
    payload.extend(code)
    slot=next(int(e['runtime'],16) for e in doc['sample_manager']['edits'] if e['donor']=='0x401f025c')
    assert struct.unpack_from('>I',payload,slot-base)[0]==int(methods['view_event'],16)
    struct.pack_into('>I',payload,slot-base,symbols['sample_page_event'])
    image=bytearray(raw[:src-B.BASE])+payload
    assert struct.unpack_from('>I',image,0x401d8b78-B.BASE)[0]==0x40028dbe
    struct.pack_into('>I',image,0x401d8b78-B.BASE,symbols['voice_page_event'])
    assert base+len(payload)<=int(doc['runtime_limit'],16)
    boot=B.BASE+len(image)
    asm=(INPUT/'bootstrap.S').read_text().replace(f'#{copy["bytes"]//4},%d1',f'#{len(payload)//4},%d1')
    image.extend(B.R.assemble(asm,boot,out,'bootstrap'));image[0xb2:0xb8]=b'\x4e\xf9'+B.BE(boot)
    doc.update(baseline_sha256=SHA,main_sha256=B.T.SHA(image),bytes=len(image),
        runtime_copy={**copy,'bytes':len(payload)},runtime_sha256=B.T.SHA(payload),
        bootstrap=hex(boot),bootstrap_bytes=len(image)-(boot-B.BASE),flash_ready=False)
    doc['voice_page_route']=dict(methods={k:hex(symbols[k]) for k in ('voice_page_event','sample_page_event','sample_manager_open','voice_page_open')},
        bytes=len(code),code_sha256=B.T.SHA(code),sample_view_event_slot=hex(slot),native_voice_event_slot='0x401d8b78',
        behavior='VOICE cycles Voice Allocation / SampleManager; FUNC+VOICE delegates native unison handler',
        manager_factory=methods['factory'],voice_factory='0x4019f232',controller_open='0x4011d71e',
        limits=['Full browser service imports remain unresolved; no flashable SysEx',
                'Offline controller evidence is recorded separately; hardware behavior is untested'])
    (out/'main-os.bin').write_bytes(image);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    for name in ('fn_new_map.txt','ram_map.txt'):(out/name).write_bytes((INPUT/name).read_bytes())
    print(json.dumps(dict(main_sha256=doc['main_sha256'],runtime_bytes=len(payload),route=doc['voice_page_route']),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    build(parser.parse_args().output)
