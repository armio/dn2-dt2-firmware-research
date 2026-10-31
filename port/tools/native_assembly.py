"""Assembly-only equivalent of dnfw.patch.cbuild; no cross-GCC required."""

import os
from pathlib import Path
import subprocess
import tempfile

from dnfw.patch import cbuild


def build(sources, *, base, entries=(), include=(), defines=None, toolchain=None):
    if base % 4:
        raise ValueError("assembly base must be four-byte aligned")
    prefix = os.environ.get("ONESHOT_BINUTILS", "m68k-linux-gnu-")

    def run(*args):
        return subprocess.run([str(a) for a in args], capture_output=True, check=True).stdout

    with tempfile.TemporaryDirectory(prefix="dnfw_asm_") as tmp:
        work = Path(tmp)
        objects = []
        for n, source in enumerate(sources):
            source = Path(source)
            if source.suffix != ".S":
                raise ValueError(f"assembly-only build refuses {source}")
            text = run("clang", "-E", "-P", "-x", "assembler-with-cpp", "-D__ASSEMBLER__",
                       *(f"-I{Path(p)}" for p in include),
                       *(f"-D{k}={v}" for k, v in (defines or {}).items()), source)
            asm, obj = work / f"{n}.s", work / f"{n}.o"
            asm.write_bytes(text)
            run(prefix + "as", "-mcpu=5475", "-o", obj, asm)
            objects.append(obj)
        script, elf, raw = work / "link.ld", work / "out.elf", work / "out.bin"
        script.write_text(cbuild.LINKER_SCRIPT.format(base=base))
        run(prefix + "ld", "--no-warn-rwx-segments", "--gc-sections",
            *(f"--undefined={e}" for e in entries), "-T", script, "-o", elf, *objects)
        run(prefix + "objcopy", "-O", "binary", "-R", ".bss", elf, raw)
        symbols, kinds = {}, {}
        for line in run(prefix + "nm", "--defined-only", elf).decode().splitlines():
            at, kind, name = line.split()
            symbols[name], kinds[name] = int(at, 16), kind
        missing = [e for e in entries if e not in symbols]
        if missing:
            raise ValueError(f"missing assembly entry points: {missing}")
        data = raw.read_bytes() if raw.exists() else b""
        size = symbols["__image_end"] - base
        if len(data) > size:
            raise ValueError("assembly extends beyond __image_end")
        data += bytes(size - len(data))
        disassembly = run(prefix + "objdump", "-d", "-m", "m68k:cfv4e", elf).decode()
        if cbuild.SCALE8.search(disassembly) or "<unknown>" in disassembly:
            raise ValueError("assembly contains unsupported ColdFire instructions")
        return cbuild.Linked(base, data, symbols["__bss_end"] - symbols["__bss_start"], symbols, kinds)
