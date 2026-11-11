"""Build R023 SEM controls on ColdFire MAIN; the SEM DSP is built by build_dn2_sem_dsp.py."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

PARENT_SHA = '26b86845969df2ffb7fb0c5a7854b357ba68e8d105eb4074b060c9ceeaa855d1'


class PatchContext(revision.PatchContext):
    parent_build = 'R022'
    parent_flat = '54284e835c74c36a0e2a34289ca45e5dbd226620b551b777baf15c3b2d862d71'
    parent_staged = 'c9bc78c9f6d32e7fcbfa8d38aa8f01235d15b7b85831d803252677e2cebec949'
    parent_runtime = '8bbb4f17fd4acc5b3a59b4c71d7e52af35ac1d6e16b7eb1f0c0d83d501c9609b'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R023', 'sem_filter_r023',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r023_sem_filter
    revision.build_revision(parent, out, PatchContext, 'R023', 'sem_filter_r023',
                            (r023_sem_filter,))




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True, help='parent ColdFire build folder')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
