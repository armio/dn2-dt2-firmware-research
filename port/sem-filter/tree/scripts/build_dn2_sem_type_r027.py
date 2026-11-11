"""R027: R026 plus the SEM TYPE widget (ColdFire MAIN only; the R026 DSP is inherited unchanged)."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

PARENT_SHA = 'af0569022decada477daccc3ff318a3fa6495b458b95358c7d762a4a995a4542'


class PatchContext(revision.PatchContext):
    parent_build = 'R026'
    parent_flat = 'de1eac8299f568e2ed7538f73c1b7a4afe925e010a2aab4f0a62b0ab346708b4'
    parent_staged = 'b92ec2a1cd1a60b1533955eef6e03b20c6f004fa83b92f33a15b4d360df66601'
    parent_runtime = '8c8cb41a31a01900272a28fc36f8375d770ca39d07091217f9e80701d1d77c4a'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R027', 'sem_type_r027', PatchContext.parent_flat)


def build(parent, out):
    import r027_sem_type
    revision.build_revision(parent, out, PatchContext, 'R027', 'sem_type_r027', (r027_sem_type,))




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True, help='parent ColdFire build folder')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
