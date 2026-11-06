"""Build R019 from the pinned local R018 candidate."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R018'
    parent_flat = 'eee8ededea98a2957c57bc89ca6b4fc773922b28d41269583c57f74252ed2fcc'
    parent_staged = 'fd057c9dd26e08c8ed0f48c5e5e02adc0ae4bfb48d9c06f1e92acc06f6188920'
    parent_runtime = '8daf8dfde36f8f989a171c5a034a7578242dc5687e21515d1123b4b4a2cebcd1'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R019', 'emulator_fixes_r019',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r019_project
    revision.build_revision(parent, out, PatchContext, 'R019', 'emulator_fixes_r019',
                            (r019_project,))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
