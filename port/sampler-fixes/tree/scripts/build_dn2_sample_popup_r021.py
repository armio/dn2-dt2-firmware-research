"""Build R021 from R020; deferred sampler SYN view selection only."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R020'
    parent_flat = 'd8f327c07b4930d4e062feba5d9914d2777e33c68b5a7f3e8165fb4a9f3e4311'
    parent_staged = '63ee355380d98ef9123a4e8051f705bfe76cf29d86571d44a53f23e01a824e2c'
    parent_runtime = '3c2002eabc0f6fbdd4ea860cd954950c92805f5c310da800d6c56c33e45bb064'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R021', 'sample_popup_r021',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r021_source_route
    revision.build_revision(parent, out, PatchContext, 'R021', 'sample_popup_r021',
                            (r021_source_route,))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
