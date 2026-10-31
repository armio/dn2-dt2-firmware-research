"""Assemble the ONESHOT adapter (`csrc/oneshot/sharc/oneshot5.asm`) for its fixed place.

    python scripts/gen_oneshot_sharc.py [--fix]

The adapter branches to its own labels by **absolute** address (the forms the
firmware itself uses), so its source carries the numbers. This assembles it with
selache's `selas` (WSL), reads each label's parcel offset from the object's symbol
table, and checks that every hard-coded target equals `ADAPTER_SW + offset` of the
label its comment names. `--fix` rewrites the numbers and assembles again (the
instruction lengths do not depend on them), then checks once more.

Writes `csrc/oneshot/sharc/oneshot5.json`: the object's parcels, the instruction
offsets and the label map. Our own code only; no donor byte is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import sharc_waverider_m3 as m3                     # noqa: E402
import sharc_waverider_render as m1                 # noqa: E402
from dnfw.image import sharc_object                 # noqa: E402
from dnfw.oneshot import build as OB                # noqa: E402

SOURCE = ROOT / "csrc" / "oneshot" / "sharc" / "oneshot5.asm"
OUT = ROOT / "csrc" / "oneshot" / "sharc" / "oneshot5.json"
LABELS = tuple(re.findall(r"^\.GLOBAL (os_\w+\.);", SOURCE.read_text(), re.MULTILINE))
# `IF .. JUMP 0x...; // -> label` and `DM(I7, M7) = 0x...; // return address - 1: label - 1`
# one line each: a comment on the next line must never lend its label to this one
TARGET = re.compile(r"((?:JUMP|CALL)[ \t]+)(0x[0-9a-f]+)(;[ \t]*//[ \t]*(?:[^>\n]*->[ \t]*)?(os_\w+\.))")
RETURN = re.compile(r"(DM\(I7, M7\) = )(0x[0-9a-f]+)(;[ \t]*//[^\n]*?(os_\w+\.) - 1)")


def status_postpass(text: str, be: bytes, offsets: list[int]):
    """Bind only named V7 absolute ASTAT moves to native UREG76/77.

    The pinned selas aliases emit73/74. Native instructions and PRM-bound
    decoding require76/77. Length/opcode/address remain identical; no other
    instruction is patched. Callers must independently decode these records.
    """
    instructions = []
    for line in text.splitlines():
        clean = line.split('//', 1)[0].strip()
        if clean.endswith(';') and not clean.startswith('.'):
            instructions.append(clean)
    if len(instructions) != len(offsets):
        raise ValueError('source/instruction offsets disagree for status post-pass')
    out = bytearray(be)
    records = []
    for index, line in enumerate(instructions):
        match = re.fullmatch(r'DM\((0x30dc(?:88|8c))\) = (ASTAT[XY]);', line)
        load = False
        if match is None:
            match = re.fullmatch(r'(ASTAT[XY]) = DM\((0x30dc(?:88|8c))\);', line)
            load = match is not None
        if match is None:
            if 'ASTAT' in line:
                raise ValueError('unrecognized status transfer: ' + line)
            continue
        name, address = ((match[1], int(match[2], 16)) if load else (match[2], int(match[1], 16)))
        wrong = 0x73 if name == 'ASTATX' else 0x74
        right = 0x76 if name == 'ASTATX' else 0x77
        opcode = 0x10 if load else 0x11
        expected = bytes((opcode, wrong)) + address.to_bytes(4, 'big')
        replacement = bytes((opcode, right)) + address.to_bytes(4, 'big')
        start = offsets[index]
        end = offsets[index + 1] if index + 1 < len(offsets) else len(be)
        if bytes(out[start:end]) != expected:
            raise ValueError(f'status transfer opcode/length/address mismatch at{start:#x}: {line}')
        out[start:end] = replacement
        records.append({'source': line, 'byte_offset': start, 'pm_sw': hex(OB.ADAPTER_SW + start//2),
                        'from_parcels_be': expected.hex(), 'to_parcels_be': replacement.hex(),
                        'ureg': right, 'direction': 'load' if load else 'store', 'dm': hex(address)})
    if records and len(records) != 6:
        raise ValueError('expected six V7 ASTAT transfers')
    return bytes(out), records


def assemble(text: str, work: pathlib.Path) -> tuple[bytes, dict[str, int], list[int]]:
    src = work / "oneshot5.asm"
    src.write_bytes(text.encode())
    obj = work / "oneshot5.doj"
    r = m1._wsl(f"{m1.SELAS} -proc ADSP-21569 -o {m1._wsl_path(obj)} {m1._wsl_path(src)}\n", work)
    if r.returncode or not obj.exists():
        raise SystemExit(f"selas failed:\n{r.stdout}{r.stderr}")
    data = obj.read_bytes()
    syms = sharc_object.symbols(data)
    be, offsets = m3._selas(src, work)
    be, _ = status_postpass(text, be, offsets)
    return be, {k: OB.ADAPTER_SW + syms[k] for k in LABELS if k in syms}, offsets


def targets(text: str, labels: dict[str, int]) -> tuple[str, list[str]]:
    wrong = []

    def fix(m, minus=0):
        want = labels[m.group(4)] - minus
        if int(m.group(2), 16) != want:
            wrong.append(f"{m.group(2)} -> {want:#x} ({m.group(4)})")
        return f"{m.group(1)}{want:#x}{m.group(3)}"

    text = TARGET.sub(lambda m: fix(m), text)
    text = RETURN.sub(lambda m: fix(m, 1), text)
    return text, wrong


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--fix", action="store_true")
    a = p.parse_args()
    text = SOURCE.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(dir=ROOT / "out" if (ROOT / "out").exists() else None) as tmp:
        work = pathlib.Path(tmp)
        be, labels, offsets = assemble(text, work)
        fixed, wrong = targets(text, labels)
        if wrong and not a.fix:
            print("targets that do not match the labels:\n  " + "\n  ".join(wrong))
            return 1
        if wrong:
            SOURCE.write_bytes(fixed.encode())
            print("fixed:\n  " + "\n  ".join(wrong))
            be2, labels2, offsets2 = assemble(fixed, work)
            if labels2 != labels or offsets2 != offsets or len(be2) != len(be):
                raise SystemExit("the fixed source moved its own labels; run again")
            _, again = targets(fixed, labels2)
            if again:
                raise SystemExit(f"still wrong after the fix: {again}")
            be, text = be2, fixed
        entry, _ = m3._selas_line(f"JUMP {OB.ADAPTER_SW:#x};", work)
        early = None
        if 'os_handoff_early_guard.' in labels:
            guard = labels['os_handoff_early_guard.']
            guard_jump, _ = m3._selas_line(f"JUMP {guard:#x};", work)
            if len(guard_jump) != 6:
                raise ValueError('native early-copy branch replacement is not six bytes')
            early = {'load_address': '0x283850e4', 'from': '0e0700001600',
                     'to': sharc_object.load_bytes(guard_jump).hex(), 'entry_sw': hex(guard),
                     'original_pm_sw': '0x1c2872', 'copy_pm_sw': '0x1c2875', 'skip_pm_sw': '0x1c2888',
                     'scope': 'SVclear original copy; SVset rawON requested0..4<->5 crossing forces existing copy; otherwise original skip'}
    # Recover records from the original alias encodings without reassembling;
    # the canonical spec stores only the corrected native UREG encodings.
    original_aliases = bytearray(be)
    for index, line in enumerate([x.split('//',1)[0].strip() for x in text.splitlines()
                                  if x.split('//',1)[0].strip().endswith(';') and not x.split('//',1)[0].strip().startswith('.')]):
        if 'ASTAT' in line:
            original_aliases[offsets[index]+1] = 0x73 if 'ASTATX' in line else 0x74
    _, status_records = status_postpass(text, bytes(original_aliases), offsets)
    spec = {
        "source": SOURCE.relative_to(ROOT).as_posix(),
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "toolchain": "selache selas -proc ADSP-21569 (js216/selache 2b26d3b, GPL-3.0, native; negative Type6b shift and byte-bound ASTAT UREG alias post-passes)",
        "section": "seg_pmco", "load_sw": hex(OB.ADAPTER_SW),
        "labels": {k: hex(v) for k, v in labels.items()},
        "object_parcels_be": be.hex(), "instruction_offsets": offsets,
        "entry_jump": {"source": f"JUMP {OB.ADAPTER_SW:#x};", "object_parcels_be": entry.hex()},
        "status_ureg_postpass": status_records}
    if early is not None:
        spec['native_earlycopy_patch'] = early
    OUT.write_text(json.dumps(spec,
        indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(be)} bytes, {len(offsets)} instructions, labels "
          + ", ".join(f"{k}{v:#x}" for k, v in labels.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
