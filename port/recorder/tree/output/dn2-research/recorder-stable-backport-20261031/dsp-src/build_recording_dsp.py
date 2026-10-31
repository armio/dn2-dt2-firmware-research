#!/usr/bin/env python3
"""Add the proven Recorder fixes to T1E2 without later USB timing experiments."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'scripts'))
import build_dt2_recording_input as capture
import build_dt2_usb_reply_guard as acknowledgment
import build_dt2_recorder_reply_ownership as reply
import build_dt2_recorder_diagnostic_ownership as ownership
import build_dt2_recorder_control_snapshot as snapshot


def build(out):
    if out.exists():
        raise FileExistsError(f'Choose a fresh output directory: {out}')
    out.mkdir(parents=True)
    stable = capture.BASE
    original = stable.read_bytes()
    assert hashlib.sha256(original).hexdigest() == capture.BASE_SHA == '409811b1776c9a2cf1c73e5fce2f5dbcf7378c9fd6f835f45ba1a0e97c1a3cc3'
    stages = []
    one = out/'01-capture'
    capture.build(one, capture.WIRE)
    # Three legacy R/S paired stores reach the first packed USB sample. Keep
    # the ACK location/value, using scalar DAG stores without changing timing.
    two = out/'02-ack-integrity'
    acknowledgment.BASE = one/'section_7.bin'
    acknowledgment.SHA = capture.C.SHA(acknowledgment.BASE.read_bytes())
    acknowledgment.build(two)
    three = out/'03-reply-ownership'
    reply.build(two, three)
    four = out/'04-diagnostic-ownership'
    ownership.build(three, four)
    five = out/'05-control-snapshot'
    snapshot.build(four, five)
    for directory in (one, two, three, four, five):
        doc = json.loads((directory/'build-receipt.json').read_text())
        stages.append({'name':directory.name,'sha256':doc['section7_sha256']})
    final = (five/'section_7.bin').read_bytes()
    receipt = json.loads((five/'build-receipt.json').read_text())
    receipt['recorder_reply_ownership']['unchanged'] = [
        item.replace('AC4 frame length', 'T1E2 0xABC frame length')
        for item in receipt['recorder_reply_ownership']['unchanged']]
    receipt['recorder_stable_backport'] = {
        'base':'T1E2', 'baseline_sha256':capture.BASE_SHA, 'stages':stages,
        'retained':['T1E2 USB42 exporter and source selection', 'T1E2 SPI frame size and handoff',
                    'T1E2 sampler and voice allocation code', 'T1E2 codec output path'],
        'excluded':['USB/SPI handoff experiments', 'ordered frame queues',
                    'USB stage publication and direct-packing experiments'],
        'hardware_validated':False,
    }
    (out/'section_7.bin').write_bytes(final)
    (out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'section7_sha256':capture.C.SHA(final),'bytes':len(final),'stages':stages},indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out.resolve())
