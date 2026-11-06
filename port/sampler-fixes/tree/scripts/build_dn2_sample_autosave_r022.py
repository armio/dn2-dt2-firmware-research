"""Build R022 from R021; refresh sample identities in working-state backups."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R021'
    parent_flat = '454fd8de5f3ed70ce29941d66a06eb77846a30db3451ba4f57d8a950e4b4f5db'
    parent_staged = '250a04f5860ced260503518088027330e88caaccdba41305e3947d5ea5a13996'
    parent_runtime = '619d92d88b8a43616d8bc4972ebbcab1972d89f9887d5960d5432dbfa17594da'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R022', 'sample_autosave_r022',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r022_sample_mirror
    revision.build_revision(parent, out, PatchContext, 'R022', 'sample_autosave_r022',
                            (r022_sample_mirror,))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
