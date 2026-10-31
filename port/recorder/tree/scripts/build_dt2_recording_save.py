#!/usr/bin/env python3
"""Port DT2 recording readback, normalization and native sample-file writer.

SamplerView owns trim bounds, naming, background job and assignment. This
component preserves its original save ABI and file format, binding the worker
only to the already integrated DN2 filesystem and waveform RPC transport.
"""
from pathlib import Path
import argparse, json
import build_dt2_directory_model as L
B = L.B
INPUT = B.T.ROOT/'output/dn2-research/dn2-sampler-ui-slices-t1e2-20261015'
SHA = '4f2cea43e6a70ae922dc58ac7c02cfb91f72fdeaa4b4146ba72e2007a2c39f96'
LIMIT = 0x47ad0000


def build(out):
    doc = json.loads((INPUT/'build-receipt.json').read_text())
    L.INPUT = INPUT; L.SHA = SHA; L.COMPONENT = 'recording_save'; L.LIMIT = LIMIT
    L.CODE = [('recording_extrema', 0x4001266a, 0x400126fa),
              ('recording_read_normalize', 0x4001282e, 0x400128ca),
              ('save_recording', 0x40153994, 0x40153b1e)]
    L.DATA = []; L.EXTRA_DATA = {}; L.EXTRA_TYPED_DATA = []; L.EXTRA_CODE = []
    # Donor globals are private fixed scratch, not part of project sample RAM.
    # The sixteen zero bytes are the native sample's footer.
    L.EXTRA_STATE = [('recording_file_footer', 0x405a50a0, 0x405a50b0),
                     ('recording_file_buffer', 0x405a50b0, 0x405ad0b0)]
    L.STATE_ALIGNMENT = 4; L.EXTRA_SPANS = []
    bindings = {}
    for cfg in doc.values():
        if not isinstance(cfg, dict):
            continue
        if isinstance(cfg.get('spans'), list):
            L.EXTRA_SPANS[0:0] = [s for s in cfg['spans'] if all(k in s for k in ('donor', 'end', 'runtime'))]
        for edit in cfg.get('edits', []):
            if 'target' in edit and 'binding' in edit:
                bindings[int(edit['target'], 16)] = int(edit['binding'], 16)
    L.EXTRA_BINDINGS = bindings; L.DIRECTORY_AUX = False
    L.RESERVE_VENEERS = True; L.INFER_NATIVE_LIBRARY_OPERANDS = False
    L.METHODS = {'save_recording': 0x40153994,
                 'extrema': 0x4001266a, 'read_pcm': 0x4001282e,
                 'normalize': 0x4001288a}
    L.build(out)
    doc = json.loads((out/'build-receipt.json').read_text())
    doc['recording_save'].update(
        save_abi='(const char *path, start frame, frame count, stereo byte); native background job called by SamplerView',
        sample_format={'header_bytes': 64, 'sample_rate': 48000,
                       'pcm': 'native signed16 big-endian; stereo interleaved when selected',
                       'footer_bytes': 16, 'directory': '/recorded'},
        scratch_bytes=32784,
        source_policy='Recorded audio uses the original DT2 recorder format; existing imported samples are untouched.',
        lifecycle='Original SamplerView supplies selected trim bounds; worker reads recording RPC4, writes file, finalizes identity and closes.',
        required_integration=['Recorder DSP input/lifecycle and original SamplerView trim/name/save/assign must be linked before flashing.'],
        flash_ready=False)
    doc['flash_ready'] = False
    (out/'build-receipt.json').write_text(json.dumps(doc, indent=2)+'\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=INPUT)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args(); INPUT = args.input
    SHA = B.T.SHA((INPUT/'main-os.bin').read_bytes())
    build(args.out)
