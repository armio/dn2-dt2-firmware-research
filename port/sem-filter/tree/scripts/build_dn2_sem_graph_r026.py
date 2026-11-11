"""R026: R025 plus the SEM response graph (ColdFire MAIN only; the R025 DSP is inherited unchanged)."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

PARENT_SHA = 'eb4ec2506e412367f493f00dec61688fa4edd71fd0f7c60119edce43a433ab72'


class PatchContext(revision.PatchContext):
    parent_build = 'R025'
    parent_flat = 'e4258b251573695030745bf6ab18b0f18f0be3fab44fb08a0ddcf17a7c3f9abb'
    parent_staged = 'f2e49f55f4d1ee122f79a4447914b8d2d3f4e924e3bbe5b6cd0be4ff8681f99f'
    parent_runtime = '7cd729cdcf682b2b55452ff07202d4c0e7d18ee51c853488ead4b233ca1dc0eb'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R026', 'sem_graph_r026',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r026_sem_graph
    revision.build_revision(parent, out, PatchContext, 'R026', 'sem_graph_r026', (r026_sem_graph,))




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True, help='parent ColdFire build folder')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
