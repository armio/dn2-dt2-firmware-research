#!/usr/bin/env python3
"""Link DT2's buffered upload stream to the ported native File backend."""
from pathlib import Path
import argparse,json,struct
import build_dt2_directory_model as L
import build_dt2_waveform_events as W
B=L.B
INPUT=B.T.ROOT/'output/dn2-research/dt2-sample-file-20261009'
SHA='628cf4a2d9b47452ddacb83e9d21e3a882423118c7a09db7bf55127c6a94fbb9'

def build(out):
    doc=json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT=INPUT;L.SHA=SHA;L.COMPONENT='file_output_stream';L.LIMIT=0x47aa0000
    L.CODE=[('status_write',0x401587b8,0x40158886),
            ('flush',0x4015897c,0x401589c4),
            ('ownership',0x40159098,0x40159298),
            ('file_shared_owner',0x401e2870,0x401e28b8),
            ('put_byte',0x401e28b8,0x401e290a)]
    L.DATA=[('stream_types',0x402257c4,0x402257dc),
            ('stream_vtables',0x402257ec,0x40225834)]
    L.EXTRA_BINDINGS={**W.BINDINGS,0x44f37238:0x44647a68}
    L.EXTRA_SPANS=[]
    for key in ('sample_manager','sample_loader','sample_file'):
        L.EXTRA_SPANS+=doc[key]['spans']
        for edit in doc[key]['edits']:
            L.EXTRA_BINDINGS.setdefault(int(edit['target'],16),int(edit['binding'],16))
    donor=B.M.S.DONOR.read_bytes();native=B.M.RECIPIENT.read_bytes()
    def name(raw,ti):
        at=struct.unpack_from('>I',raw,ti+4-B.BASE)[0]
        return raw[at-B.BASE:].split(b'\0')[0]
    assert name(donor,0x4021e284)==name(native,0x40207c50)==b'N8Elektron20AbstractOutputStreamE'
    assert struct.unpack_from('>I',native,0x40207c6c-4-B.BASE)[0]==0x40207c50
    assert donor[0x401d25e0-B.BASE:0x401d25e4-B.BASE]==native[0x401bb476-B.BASE:0x401bb47a-B.BASE]
    L.EXTRA_BINDINGS.update({0x4021e284:0x40207c50,0x4021e2a0:0x40207c6c,0x401d25e0:0x401bb476})
    # Original optional begin/end std::function callbacks. Their registration
    # belongs to application startup; preserve private empty objects until that
    # application integration is linked instead of calling donor RAM.
    L.EXTRA_STATE=[('upload_callbacks',0x44f2bc48,0x44f2bc68)]
    L.EXTRA_DATA={};L.EXTRA_TYPED_DATA=[];L.EXTRA_CODE=[]
    L.DIRECTORY_AUX=False;L.RESERVE_VENEERS=True;L.INFER_NATIVE_LIBRARY_OPERANDS=False
    L.METHODS={'constructor':0x40159190,'write':0x401587d2,'put_byte':0x401e28b8,
        'flush':0x4015897c,'finish':0x40159098,'cancel':0x401590e6,
        'destroy':0x40159130,'delete':0x40159176,'error':0x401587b8}
    L.build(out)
    doc=json.loads((out/'build-receipt.json').read_text())
    doc['sample_file']['methods']['preallocate']=doc['sample_file']['methods'].pop('seek')
    doc['file_output_stream'].update(object_bytes=0x20110,buffer_bytes=0x20000,
        constructor_third_argument='total upload byte count; File preallocation, not a seek offset',
        transfer_dispatch_connected=False,application_callbacks_registered=False,
        limits=['Host dispatcher and application begin/end callback registration still need integration.',
                'Original cancel/destructor remove unfinished destination; finish flushes and finalizes File identity.'])
    (out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
