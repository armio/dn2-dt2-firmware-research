#!/usr/bin/env python3
"""Run one optional offline DSP fixture against a private R008 source build."""
import argparse
import importlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CHECKS = {
    'phase': ('check_dt2_buffer_phase_accounting', 'output/dn2-research/buffer-phase-r004/dsp'),
    'scratch': ('check_dt2_dsp_scratch_efficiency', 'output/dn2-research/sample-scratch-r005-20261101/dsp'),
    'guard': ('check_dt2_usb_guarded_publication', 'output/dn2-research/usb-guard-r007-20261101/dsp'),
    'reasons': ('check_dt2_usb_guard_reasons', 'dsp'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check', choices=CHECKS)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    paths = json.loads(args.toolchain.read_text())
    digikit = Path(paths['digikit']).resolve()
    os.environ['DIGIKIT'] = str(digikit)
    sys.path[:0] = list(map(str, [work/'scripts', digikit/'tools',
                                 ROOT/'port/dsp/support', ROOT/'port/tools/dnfw/src']))
    import sharc_waverider_render as support
    import sharc_run

    class ExecutionDigikit(support.Digikit):
        def __init__(self, historical_path):
            super().__init__(historical_path)
            self.run = sharc_run

    support.Digikit = ExecutionDigikit
    name, folder = CHECKS[args.check]
    result = importlib.import_module(name).check(work/folder)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
