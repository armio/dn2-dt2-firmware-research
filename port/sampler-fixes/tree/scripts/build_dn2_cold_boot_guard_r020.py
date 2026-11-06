"""Build R020 from the pinned local R019 candidate; MAIN-only cold-start guard."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

ROOT = revision.tail.ROOT


class PatchContext(revision.PatchContext):
    parent_build = 'R019'
    parent_flat = '2087d73870483fc26bbd1d95b6588a2e90c6f5fe0aa6204076e64c612d501d10'
    parent_staged = 'c556b78e2bfb48310b05516e760171d937859d28aab2e34722c245f790cb23d4'
    parent_runtime = 'cc71d7627c2c489ac4954921a778c438c4072e4bcc65901c88fa14a911dc3ba0'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R020', 'cold_boot_guard_r020',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r020_cold_start
    revision.build_revision(parent, out, PatchContext, 'R020', 'cold_boot_guard_r020',
                            (r020_cold_start,))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
