#!/usr/bin/env python3
"""Give Recorder exclusive ownership of its live reply fields on both pages."""
from pathlib import Path
import argparse,json,re
import build_dt2_recorder_reply_ownership as P
C,B,A,O,R=P.C,P.B,P.A,P.O,P.R
CODE,SAVE,LIMIT=0xbfa200,0x200f4320,0x200f5000
SAVES={'R0':SAVE,'R1':SAVE+8,'ASTATX':SAVE+16,'ASTATY':SAVE+24,'I0':SAVE+32}


def hook_specs(doc):
    hooks=[]
    for family in ('dsp_playback_diagnostic','dsp_render_diagnostic'):
        for h in doc[family]['hooks']:
            hooks.append(dict(name=family+'_'+str(h['checkpoint']),site=int(h['entry'],16),
                active_resume=int(h['replay'],16),reason='Skip diagnostic-only wrapper; execute original displaced native instruction.'))
    for name,site in (('heartbeat',0xbf4d4f),('stage_payload0',0xbf5300),
                      ('stage_payload1',0xbf5313),('stage_marker',0xbf5342),
                      ('helper_payload0',0xbf55b2),('helper_payload1',0xbf55c2),
                      ('helper_marker',0xbf55ed)):
        hooks.append(dict(name=name,site=site,active_resume=site+6,
            reason='Skip paired absolute reply stores only; preceding RAM/counter updates remain.'))
    hooks.append(dict(name='stage_codec_publication',site=0xbf53b0,active_resume=0xbf53b6,
        reason='Skip final legacy marker pair and chained codec diagnostic publication; preserve native continuation.'))
    assert len(hooks)==21
    return hooks


def build(parent,out):
    raw=(parent/'section_7.bin').read_bytes();doc=json.loads((parent/'build-receipt.json').read_text())
    assert C.SHA(raw)==doc['section7_sha256'] and 'recorder_reply_ownership' in doc
    k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000
    memory=B.decode_view(k,raw);hooks=hook_specs(doc)
    for h in hooks:
        before=memory.read_sw(h['site'],6);v=C.S.to_value(before)
        assert v>>40==0x11,(h,hex(v))
        if h['name'].startswith('dsp_'):assert(v>>32)&0x7f==0x10,(h,hex(v)) # I0 scratch store
        else:
            assert(v&0xffffffff) in (0x2c49d4,0x2c49d8,0x2c49dc,0x2c49e0),(h,hex(v))
            following=C.S.to_value(memory.read_sw(h['site']+3,6))
            assert following==v+0x1000 or (h['site']==0xbf53b0 and following==0x063e00bf2350),(h,hex(following))
        h.update(before=before.hex(),disabled_resume=h['site']+3)
    # All gates complete before their original diagnostic/native continuation.
    # They contain no CALL and do not change MODE1/interrupt enables. The
    # normal render path is serialized; codec ISR hooks do not enter these
    # publishers and have separate scratch. Fatal diagnostics remain intact.
    source='.SECTION/PM seg_pmco;\n'
    def label(s):return '.GLOBAL '+s+'.\n'+s+'.:\n'
    def restore():return ''.join(f'      {r} = DM({a:#x});\n' for r,a in SAVES.items())
    for i,h in enumerate(hooks):
        name='gate_'+str(i);source+=label(name)
        # R-register absolute copies preserve their paired S register while
        # SSE is set. ASTATX/Y also have SIMD companions, so each gets
        # its own 8-byte slot; I0 has no companion.
        source+=''.join(f'      DM({a:#x}) = {r};\n' for r,a in SAVES.items())
        source+=f'''      R0 = DM({R.WIRE+24:#x});
      R0 = LSHIFT R0 BY -16;
      I0 = R0; // Scalar capture of extracted cookie.
      R0 = I0; // Broadcast to both PEs before conditional branch.
      R1 = 0x5243;
      COMP(R0, R1);
      IF EQ JUMP 0x0; // -> {name}_active.
'''+restore()+label(name+'_replay')+f'''      I0 = 0x12345678;
      JUMP {h['disabled_resume']:#x};
'''+label(name+'_active')+restore()+f'      JUMP {h["active_resume"]:#x};\n'
    out.mkdir(parents=True,exist_ok=False);asm=out/'recorder-diagnostic-ownership.asm';asm.write_text(source)
    obj,offsets=A._selas(asm,out)
    labels={name:CODE+v for name,v in O.symbols((out/'recorder-diagnostic-ownership.doj').read_bytes()).items()}
    source=re.sub(r'(JUMP\s+)0x0(;\s*// -> (\w+\.))',lambda m:m[1]+hex(labels[m[3]])+m[2],source)
    asm.write_text(source);obj,again=A._selas(asm,out);assert offsets==again
    code=bytearray(O.load_bytes(obj));widths={a:b-a for a,b in zip(offsets,offsets[1:]+[len(code)])}
    fixes=[]
    for off in offsets:
        if widths[off]!=6:continue
        v=C.S.to_value(code[off:off+6]);reg=(v>>32)&0x7f
        if v>>40 in (0x10,0x11) and reg in (0x73,0x74):
            code[off:off+6]=C.S.to_bytes((v&~(0x7f<<32))|({0x73:0x76,0x74:0x77}[reg]<<32));fixes.append(CODE+off//2)
    image=bytearray(raw)
    for i,h in enumerate(hooks):
        entry=labels['gate_'+str(i)+'.'];replay=labels['gate_'+str(i)+'_replay.']
        code[2*(replay-CODE):2*(replay-CODE)+6]=bytes.fromhex(h['before'])
        patch=C.S.to_bytes(0x063e00000000|entry)
        C.B.write_span(image,C.S.code_address(h['site'],window='l2'),patch)
        h.update(entry=entry,replay=replay,active=labels['gate_'+str(i)+'_active.'],after=patch.hex())
    physical=C.S.code_address(CODE,window='l2')
    assert physical==0x200f4400 and physical+len(code)<=LIMIT
    blocks=[(SAVE,bytes(36)),(physical,bytes(code))];regions=C.B.load_regions(raw)
    for a,data in blocks:assert not any(a<b+len(body) and b<a+len(data) for b,body in regions),(hex(a),len(data))
    result=C.B.insert_before_final(bytes(image),b''.join(C.B.block(a,data) for a,data in blocks))
    walk=C.B.walk(result);first,last=walk.blocks[7],walk.blocks[-1]
    result=result[:first.offset]+C.B.block(first.target,flags=first.flags,argument=last.offset-first.offset)+result[first.end:]
    assert C.B.walk(result).complete
    for h in hooks:
        for field in ('site','disabled_resume','active_resume','entry','replay','active'):h[field]=hex(h[field])
    doc.update(baseline_sha256=C.SHA(raw),section7_sha256=C.SHA(result),flash_ready=False)
    doc['recorder_diagnostic_ownership']=dict(base=str(parent.resolve()/'section_7.bin'),base_sha256=C.SHA(raw),
        code=hex(CODE),physical=hex(physical),code_bytes=len(code),instruction_offsets=offsets,
        scratch=hex(SAVE),scratch_bytes=36,scratch_fields={r:hex(a) for r,a in SAVES.items()},
        hooks=hooks,labels={k:hex(v) for k,v in labels.items()},status_encoding_fixes=[hex(x) for x in fixes],
        enabled_cookie_address=hex(R.WIRE+26),enabled_cookie='0x5243',
        protected_reply_fields={'4':'recorded frame count','8':'audition cursor','12..19':'levels and peaks'},
        ownership='While Recorder enabled, every normal diagnostic family leaves both reply pages untouched. Internal diagnostic RAM updates continue. Closed Recorder retains original publication bytes. Prior final timing guard remains.',
        unchanged=['Native ACK+24 adapters','Native header0 and state+20','Fatal diagnostic publications','DSP source/audio/capture/USB packing','Timing and diagnostic counter accumulation'],
        shared_scratch='Gates contain no CALL, restore all scratch-held state before continuation, and cannot enter another gate before restoring. All gated publication belongs to the serialized normal render task; codec ISR observers have separate scratch and no branch to these publishers. Fatal handlers remain separate.',
        limits=['No physical SPI race/timing emulation; full writer-chain interleaving check is a separate integration result.'])
    (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
    print(json.dumps(dict(section7_sha256=doc['section7_sha256'],code_bytes=len(code),gates=len(hooks)),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('parent',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();build(a.parent,a.out)
