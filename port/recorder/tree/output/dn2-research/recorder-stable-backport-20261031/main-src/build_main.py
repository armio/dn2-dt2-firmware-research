#!/usr/bin/env python3
"""Add the corrected DT2 Recorder workflow to stable T1E2 MAIN only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
STABLE = ROOT/'output/dn2-research/dn2-sampler-ui-slices-t1e2-20261015'
STABLE_SHA = '4f2cea43e6a70ae922dc58ac7c02cfb91f72fdeaa4b4146ba72e2007a2c39f96'
BASE = 0x40000400


def sha(data):
    return hashlib.sha256(data).hexdigest()


def repair_slice_fonts(parent, out):
    """Recorder import already binds exact native fonts; retain T1F3 Slice fix."""
    sys.path.insert(0, str(ROOT/'scripts'))
    import build_dt2_recorder_fonts as F
    doc = json.loads((parent/'build-receipt.json').read_text())
    raw, payload = bytearray((parent/'main-os.bin').read_bytes()), bytearray((parent/'runtime.bin').read_bytes())
    assert sha(raw) == doc['main_sha256'] and sha(payload) == doc['runtime_sha256']
    copy = doc['runtime_copy']; src, base = int(copy['source'], 16)-BASE, int(copy['destination'], 16)
    binds, proof = F.font_bindings(F.B.M.S.DONOR.read_bytes(), F.B.M.RECIPIENT.read_bytes())
    edits=[]; counts={}
    for name, expected in [('recorder_ui', 12), ('manual_slice_editor', 7)]:
        count=0
        for entry in doc[name]['edits']:
            donor=int(entry['target'],16)
            if donor not in binds:continue
            count+=1
            at, old, new = int(entry['runtime'],16), int(entry['binding'],16), binds[donor]
            assert struct.unpack_from('>I',payload,at-base)[0] == old
            if old == new:continue
            assert name == 'manual_slice_editor' and struct.unpack_from('>I',payload,old-base)[0] == 0
            payload[at-base:at-base+4]=struct.pack('>I',new)
            edits.append(dict(component=name,runtime=hex(at),before=hex(old),after=hex(new),donor=hex(donor)))
            entry['binding']=hex(new)
        assert count==expected,(name,count)
        counts[name]=count
    assert len(edits)==7
    raw[src:src+len(payload)]=payload
    doc['recorder_fonts']=dict(fonts=proof,edits=edits,bindings_verified=counts,
        reason='Recorder fonts imported with native bindings; repair retained Slice zero-prefix descriptors.',
        runtime_bytes_added=0,graphics_code_unchanged=True)
    doc.update(baseline_sha256=doc['main_sha256'],main_sha256=sha(raw),runtime_sha256=sha(payload))
    out.mkdir()
    for name in ('bootstrap.S','fn_new_map.txt','ram_map.txt'):shutil.copyfile(parent/name,out/name)
    (out/'main-os.bin').write_bytes(raw);(out/'runtime.bin').write_bytes(payload)
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')


def build(out):
    assert sha((STABLE/'main-os.bin').read_bytes())==STABLE_SHA
    out.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(ROOT/'scripts'))
    stages=[]
    def stage(name,script,args):
        dest=out/name
        with (out/(name+'.log')).open('w') as log:
            result=subprocess.run([sys.executable,'-B',str(script),*map(str,args),'--out',str(dest)],
                cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        if result.returncode:raise RuntimeError(f'{name} failed; see {out/(name+".log")}')
        receipt=json.loads((dest/'build-receipt.json').read_text())
        assert sha((dest/'main-os.bin').read_bytes())==receipt['main_sha256']
        stages.append(dict(name=name,source=str(script.relative_to(ROOT)),source_sha256=sha(script.read_bytes()),main_sha256=receipt['main_sha256']))
        print(name,receipt['main_sha256'],flush=True)
        return dest
    prior=stage('01-reservation',ROOT/'scripts/prepare_dn2_recorder_runtime.py',[STABLE])
    for name,script in [('02-save','build_dt2_recording_save.py'),('03-settings','build_dt2_recording_settings.py'),
        ('04-transport','build_dt2_recording_transport.py'),('05-ui','build_dt2_recorder_ui.py')]:
        prior=stage(name,ROOT/'scripts'/script,['--input',prior])
    prior=stage('06-route',HERE/'build_r001_recorder_route.py',['--input',prior])
    font=out/'07-fonts';repair_slice_fonts(prior,font);prior=font
    prior=stage('08-shortcuts',HERE/'build_r001_recorder_shortcuts.py',['--input',prior])
    prior=stage('09-persistence',ROOT/'scripts/build_dn2_recorder_persistence.py',['--parent',prior])
    final=out/'result';shutil.copytree(prior,final)
    doc=json.loads((final/'build-receipt.json').read_text())
    doc['build']='R001'
    doc['stable_recorder_backport']=dict(parent='T1E2',parent_main_sha256=STABLE_SHA,
        stages=stages,retained='Stable USB capture, SPI launch and sequencer handling; no later timing experiments.',
        recorder_fixes=['Native fonts','VOICE physical key phases','VOICE+YES/NO shortcuts',
            'Native DN2 tempo binding for finite R.LEN','Project Recorder preferences'],hardware_tested=False)
    copy=doc['runtime_copy'];raw=(final/'main-os.bin').read_bytes();payload=(final/'runtime.bin').read_bytes()
    assert raw[int(copy['source'],16)-BASE:int(copy['source'],16)-BASE+copy['bytes']]==payload
    assert payload[0x47aa5a0c-int(copy['destination'],16):0x47aa5a10-int(copy['destination'],16)]==b'R001'
    assert int(copy['destination'],16)+copy['bytes']<=int(doc['runtime_limit'],16)
    (final/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print('Final MAIN',doc['main_sha256'],final)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    build(p.parse_args().out.resolve())
