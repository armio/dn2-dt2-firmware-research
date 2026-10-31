#!/usr/bin/env python3
"""Fetch pinned open-source build tools; never download device firmware."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "dependencies.json").read_text())


def run(*args, cwd=None):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)


def checkout(name, sources):
    pin = PINS[name]
    target = sources / name
    if not target.exists():
        with tempfile.TemporaryDirectory(prefix=name + "-", dir=sources) as tmp:
            work = Path(tmp) / "repo"
            run("git", "init", "--quiet", work)
            run("git", "-C", work, "remote", "add", "origin", pin["url"])
            run("git", "-C", work, "fetch", "--depth=1", "origin", pin["commit"])
            run("git", "-C", work, "checkout", "--quiet", "--detach", "FETCH_HEAD")
            work.rename(target)
    head = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(target), "status", "--porcelain", "--untracked-files=no"], text=True
    ).strip()
    if head != pin["commit"] or dirty:
        raise SystemExit(f"{target}: expected clean pinned source {pin['commit']}; refusing to overwrite")
    return target


def binutils_source(sources):
    pin = PINS["binutils"]
    archive = sources / f"binutils-{pin['version']}.tar.xz"
    if not archive.exists():
        temporary = archive.with_suffix(".download")
        try:
            run("curl", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--max-time", "300",
                "--output", temporary, pin["url"])
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != pin["sha256"]:
                raise SystemExit("Downloaded binutils archive has unexpected SHA-256")
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin["sha256"]:
        raise SystemExit(f"{archive}: unexpected SHA-256")
    source = sources / f"binutils-{pin['version']}"
    if not source.exists():
        with tempfile.TemporaryDirectory(prefix="binutils-", dir=sources) as tmp:
            with tarfile.open(archive) as tar:
                tar.extractall(tmp, filter="data")
            (Path(tmp) / source.name).rename(source)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path(".toolchain"))
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    for command in ("git", "curl", "cargo", "make", "cc", "clang"):
        if not shutil.which(command):
            parser.error(f"missing build prerequisite: {command}")
    prefix = args.prefix.resolve()
    sources = prefix / "src"
    sources.mkdir(parents=True, exist_ok=True)
    digikit = checkout("digikit", sources)
    selache = checkout("selache", sources)
    run("cargo", "build", "--release", "--locked", "-p", "selas", cwd=selache)
    source = binutils_source(sources)
    build = prefix / "binutils-build"
    build.mkdir(exist_ok=True)
    if not (build / "Makefile").exists():
        run(source / "configure", "--target=m68k-linux-gnu", f"--prefix={prefix}",
            "--disable-nls", "--disable-werror", "--disable-gprofng", "--disable-gdb",
            "--disable-sim", "--disable-gold", "--disable-libctf", "--disable-multilib",
            "--without-debuginfod", "--with-system-zlib", cwd=build)
    run("make", f"-j{args.jobs}", "MAKEINFO=true", "all-gas", "all-ld", "all-binutils", cwd=build)
    run("make", "MAKEINFO=true", "install-gas", "install-ld", "install-binutils", cwd=build)
    bindir = prefix / "bin"
    bindir.mkdir(exist_ok=True)
    container_tool = bindir / "elektron-fw"
    run("cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-o", container_tool,
        *sorted((HERE / "elektron-firmware-tool").glob("*.c")))
    paths = {
        "digikit": str(digikit),
        "selas": str(selache / "target/release/selas"),
        "binutils_build": str(build),
        "binutils_prefix": str(bindir / "m68k-linux-gnu-"),
        "container_tool": str(container_tool),
        "dnfw_pythonpath": str(HERE / "dnfw/src"),
        "dnfw_source": str(HERE / "dnfw"),
    }
    (prefix / "paths.json").write_text(json.dumps(paths, indent=2) + "\n")
    print(f"Build tools ready: {prefix / 'paths.json'}")


if __name__ == "__main__":
    main()
