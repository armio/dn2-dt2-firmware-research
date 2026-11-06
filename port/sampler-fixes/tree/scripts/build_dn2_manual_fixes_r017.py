"""Build and optionally package R017 from the pinned, hardware-tested R016 image."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R016'
    parent_flat = '11e7f7ec3ab5e07d27ff39090e115bee75b0e3e253c7edc337b661c45e0b4fd0'
    parent_staged = 'b1791b047331d218496abbebc14424320ebfaa74b3d1eeee626838a10d9c5a0c'
    parent_runtime = '87a0c635176984a2b377e88b76f514b7e8dd305be00dca1d6d6c4dd3116a3db1'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R017', 'manual_fixes_r017',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r017_sample_manager
    import r017_sequence_bounds
    import r017_slice_bounds
    import r017_sample_replace

    revision.build_revision(parent, out, PatchContext, 'R017', 'manual_fixes_r017',
                            (r017_sample_manager, r017_sequence_bounds, r017_slice_bounds,
                             r017_sample_replace))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
