#!/usr/bin/env python3
"""Replay the source MAIN stages after the reconstructed ONESHOT/FS baseline.

All outputs, extracted donor bytes and generated listings stay in --work.
No device interfaces or firmware packaging commands are invoked.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASELINE = "oneshot-drive-v3-m3b-rev3-stackfix-20261009"
BASELINE_SHA = "205673af2a58674bb239195d4d40a5084d22d626aab59ca11547a31a0d7b0c64"
DN2_SHA = "57b06a7960b7c3dc9803bde6b31896b89a2fbdcc404a932ff503f3856d4d7a61"
DT2_SHA = "57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d"
FINAL_SHA = "4f2cea43e6a70ae922dc58ac7c02cfb91f72fdeaa4b4146ba72e2007a2c39f96"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != target.resolve():
        shutil.copyfile(source, target)


def materialize(work, digikit):
    for folder in ("tree", "metadata"):
        for source in sorted((HERE / folder).rglob("*")):
            if not source.is_file():
                continue
            target = work / source.relative_to(HERE / folder)
            target.parent.mkdir(parents=True, exist_ok=True)
            text = source.read_text().replace("@WORKSPACE@", str(work))
            text = text.replace("@DIGIKIT@", str(digikit))
            target.write_text(text)


def link(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        if target.resolve() != source.resolve():
            raise RuntimeError(f"Conflicting build dependency: {target}")
    else:
        target.symlink_to(source.resolve(), target_is_directory=source.is_dir())


def run_script(work, name, args, env, log):
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as output:
        completed = subprocess.run([sys.executable, str(work / "scripts" / name), *map(str, args)],
                                   cwd=work, env=env, stdout=output, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise RuntimeError(f"{name} failed; inspect {log}")


def build(args):
    work = args.work.resolve()
    if work == HERE or HERE in work.parents:
        raise ValueError("Use a private build/work directory outside port/main")
    for path, expected in ((args.dn2_main, DN2_SHA), (args.dt2_main, DT2_SHA),
                           (args.baseline_dir / "main-os.bin", BASELINE_SHA)):
        if digest(path) != expected:
            raise ValueError(f"Input hash mismatch: {path}")
    work.mkdir(parents=True, exist_ok=True)
    materialize(work, args.digikit.resolve())
    lib = work / "firmware/ghidra/oneshot-proof/v7-source/src"
    link(args.dnfw_src, lib)
    binroot = work / "firmware/ghidra/storage-proof/oneshot-storage-merge-v2/toolchain/build"
    for relative, tool in (("gas/as-new", "as"), ("ld/ld-new", "ld"),
                           ("binutils/objcopy", "objcopy"), ("binutils/nm-new", "nm"),
                           ("binutils/objdump", "objdump")):
        executable = Path(args.binutils_prefix + tool).resolve()
        if not executable.is_file():
            raise ValueError(f"Missing binutils tool: {executable}")
        link(executable, binroot / relative)
    research = work / "output/dn2-research"
    copy(args.dn2_main, work / "firmware/dn2-1.11/section_3_MAIN_OS.bin")
    copy(args.dt2_main, work / "firmware/dt2-1.16/section_3_MAIN_OS.bin")
    copy(args.dt2_main, research / "dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin")
    copy(args.baseline_dir / "main-os.bin", research / BASELINE / "main-os.bin")
    for name in ("fn_new_map.txt", "ram_map.txt"):
        copy(args.maps / name, work / "firmware/ghidra/storage-proof/oneshot-storage-merge-v3/src" / name)
    copy(args.worker_symbols, work / "firmware/ghidra/storage-proof/oneshot-storage-merge-v3/runtime-candidate/worker-symbols.json")
    # This stage only checks the decompression capacity against a DSP length.
    copy(args.dsp, research / "dt2-sample-cursor-dsp-20261009/section_7.bin")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join([str(args.dnfw_src.resolve()), str(args.digikit.resolve())])}
    mapping = research / "dt2-browser-runtime-map-20261009/map.json"
    if not mapping.is_file():
        run_script(work, "map_dt2_browser_runtime.py", [], env, work / "logs/browser-runtime-map.log")
    plan = json.loads((HERE / "stages.json").read_text())
    completed = []
    for number, stage in enumerate(plan, 1):
        out = research / stage["output"]
        image = out / "main-os.bin"
        if image.is_file():
            if digest(image) != stage["main_sha256"]:
                raise RuntimeError(f"Existing stage hash mismatch: {out}")
            if not (out / "build-receipt.json").is_file():
                raise RuntimeError(f"Incomplete stage receipt; remove before retrying: {out}")
        else:
            if out.exists():
                raise RuntimeError(f"Incomplete stage directory; remove before retrying: {out}")
            substitutions = {"{out}": str(out), "{prior}": str(research / stage["input"])}
            argv = [substitutions.get(value, value) for value in stage["argv"]]
            run_script(work, stage["script"], argv, env,
                       work / "logs" / f"{number:03d}-{stage['component']}.log")
            if digest(image) != stage["main_sha256"]:
                raise RuntimeError(f"Reproduced stage hash mismatch: {out}; got {digest(image)}")
        for name in stage.get("carry", []):
            copy(research / stage["input"] / name, out / name)
        print(f"{number}/{len(plan)} {stage['component']} {stage['main_sha256']}", flush=True)
        completed.append(stage["component"])
        if args.stop_after == stage["component"]:
            return image
    if digest(image) != FINAL_SHA:
        raise RuntimeError("Final MAIN hash mismatch")
    result = work / "result/main-os.bin"
    copy(image, result)
    (result.parent / "main-build.json").write_text(json.dumps({"main_sha256": FINAL_SHA,
        "stages": completed, "source_plan_sha256": digest(HERE / "stages.json")}, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("work", "dn2-main", "dt2-main", "baseline-dir", "maps", "worker-symbols",
                   "dsp", "dnfw-src", "digikit"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--binutils-prefix", required=True)
    parser.add_argument("--stop-after")
    args = parser.parse_args()
    print(build(args))


if __name__ == "__main__":
    main()
