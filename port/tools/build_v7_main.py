#!/usr/bin/env python3
"""Build the original V7 MAIN prerequisite from private official sections."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "dnfw/src"))

from dnfw.oneshot import coldfire
from dnfw.patch import assemble, cbuild
from dnfw.transplant import cfplan, oneshot_cf
import gen_usbprobe
import native_assembly

DN2_SHA = "57b06a7960b7c3dc9803bde6b31896b89a2fbdcc404a932ff503f3856d4d7a61"
DT2_SHA = "57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d"
V7_SHA = "6b2e91a3e237674a6ba6cd0b8b1ae633ec195fc7fa5037e7030dd3b36c4a440d"


def read_checked(path, expected):
    data = path.read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise ValueError(f"{path}: SHA-256 {got}, expected {expected}")
    return data


def build(dn2, dt2):
    plan = cfplan.build(oneshot_cf.SPEC, dt2, dn2)
    if not plan.ok:
        raise ValueError("ColdFire donor guards failed: " + "; ".join(plan.refusals))
    shims = coldfire.assemble_shims(assemble.assemble)
    main = bytearray(coldfire.compose(dn2, plan, shims)["content"])
    cbuild.build = native_assembly.build
    probe = gen_usbprobe.compose(dn2)
    for edit in probe["edits"]:
        at = edit["va"] - gen_usbprobe.BASE
        before, after = bytes.fromhex(edit["stock"]), bytes.fromhex(edit["new"])
        if main[at:at + len(before)] != before:
            raise ValueError(f"USB probe conflict at {edit['va']:#x}")
        main[at:at + len(before)] = after
    tag = probe["tag"]
    at = tag["va"] - gen_usbprobe.BASE
    main[at:at + tag["length"]] = b"os1handoff-v7".ljust(tag["length"], b"\0")
    got = hashlib.sha256(main).hexdigest()
    if got != V7_SHA:
        raise ValueError(f"V7 MAIN mismatch: {got}, expected {V7_SHA}")
    source = coldfire.shim_source() + coldfire.GROUP_SOURCE
    shims_json = {
        "os": "Digitone II 1.11", "new_type": coldfire.NEW_TYPE,
        "shims_va": coldfire.SHIMS_VA,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "shims": shims["code"].hex(), "labels": dict(sorted(shims["labels"].items())),
        "group": shims["group"].hex(),
    }
    return bytes(main), shims_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dn2-main", type=Path, required=True)
    parser.add_argument("--dt2-main", type=Path, required=True)
    parser.add_argument("--binutils-prefix", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shims-output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.shims_output.exists():
        parser.error("output already exists; choose new build output paths")
    prefix = str(Path(args.binutils_prefix).resolve())
    os.environ["ONESHOT_BINUTILS"] = prefix
    os.environ["PATH"] = str(Path(prefix).parent) + os.pathsep + os.environ["PATH"]
    data, shims = build(read_checked(args.dn2_main, DN2_SHA), read_checked(args.dt2_main, DT2_SHA))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.shims_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    args.shims_output.write_text(json.dumps(shims, indent=1) + "\n")
    print(f"V7 MAIN verified: {V7_SHA}")


if __name__ == "__main__":
    main()
