"""Build R018 from the pinned local R017 candidate."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R017'
    parent_flat = '4e3558d6a91f394711e8c4149f93cbd34005383d96905a4d29c593383254ddb4'
    parent_staged = '71a5cf5076663f50a243732cb5ef02bcaee12f92210e088e5a5402a2e8dce0e8'
    parent_runtime = '659af06c12fded77d3d20305d2ed50eca868e8fe30655c231c905e1e8fac3fcb'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R018', 'manual_fixes_r018',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r018_controls
    import r018_storage
    revision.build_revision(parent, out, PatchContext, 'R018', 'manual_fixes_r018',
                            (r018_controls, r018_storage))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
