"""R024: retain R023 MAIN behavior; the optimized SEM DSP is built by build_dn2_sem_dsp.py."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

PARENT_SHA = '0ff6ed69713a510c1f4db749007f19b9c6a66002d14eb6fb6a932fadd57d6db5'


class PatchContext(revision.PatchContext):
    parent_build = 'R023'
    parent_flat = 'f0104221cbb9efaad0c316f69a50946e100f7e357d230ea026290b1dfc2d9bee'
    parent_staged = '0f7634b320166676605f190269abd3654ea5c0a89a1832c7e85778ece23c0d8a'
    parent_runtime = 'eb97b3d04ff1b6e46dde42536c09f1644b0577626ad25548628ac49ed991eaee'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R024', 'sem_efficiency_r024',
                                             PatchContext.parent_flat)


def build(parent, out):
    revision.build_revision(parent, out, PatchContext, 'R024', 'sem_efficiency_r024', ())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True, help='parent ColdFire build folder')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
