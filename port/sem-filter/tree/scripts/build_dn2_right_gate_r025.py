"""R025: retain R024 MAIN behavior; the right-lane gate DSP is built by build_dn2_right_gate.py."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as revision

PARENT_SHA = '6b44e1e366dc9e88cd4a21eecfaebd17e4a2aec8fd616330cf317068f7f29407'


class PatchContext(revision.PatchContext):
    parent_build = 'R024'
    parent_flat = 'e3689bfdbfdbd367b0d29acc9d3376bd22bf9d8ae913f1f4529ba8e9f27ef2dc'
    parent_staged = '248c4434e68e69970110bdc39d1b2db25a846f7fa0c39147ac64362b5edfc675'
    parent_runtime = '8e77a0f7fe3e43ad7ca8e7910d2962949f9b04978aa88dc5a9e00be26a798b4a'


def verify_projection(expanded, doc):
    return revision.verify_parent_projection(expanded, doc, 'R025', 'right_gate_r025',
                                             PatchContext.parent_flat)


def build(parent, out):
    revision.build_revision(parent, out, PatchContext, 'R025', 'right_gate_r025', ())




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True, help='parent ColdFire build folder')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
