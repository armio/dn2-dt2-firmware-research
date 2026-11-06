"""Build the local R016 sample storage, Recorder and SYN control fixes."""
import argparse
from pathlib import Path

import build_dn2_audit_fixes_r015 as previous



class PatchContext(previous.PatchContext):
    parent_build = 'R015'
    parent_flat = 'e620125b666a4708f81665d0907a084a21dc08fb2eef3354a0dc5997c8f55949'
    parent_staged = 'e26f84cde1ecc92ac7f297a8a2a6e27209035ee554755576e7861387ec4bb6b4'
    parent_runtime = '13bf7ec300eef7285ea5da5deeefeca9bf312ff7fa9a7a898909c5843f24b9dc'


def verify_projection(expanded, doc):
    return previous.verify_parent_projection(expanded, doc, 'R016', 'function_fixes_r016',
                                             PatchContext.parent_flat)


def build(parent, out):
    import r016_sample_loader
    import r016_recorder_assignment
    import r016_sampler_controls
    import r016_sample_randomizer

    previous.build_revision(parent, out, PatchContext, 'R016', 'function_fixes_r016',
                            (r016_sample_loader, r016_recorder_assignment, r016_sampler_controls,
                             r016_sample_randomizer))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.parent, args.out)
