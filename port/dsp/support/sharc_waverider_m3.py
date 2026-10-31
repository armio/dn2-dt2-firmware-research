"""Original selache assembler wrappers, extracted from sharc_waverider_m3.py."""
import pathlib
import sharc_waverider_render as m1
from dnfw.image import sharc_object

def _selas(src: pathlib.Path, work: pathlib.Path):
    """Reassemble SRC with a global label before every instruction; -> (be bytes, offsets)."""
    lines, k = [], 0
    for line in src.read_text(encoding="utf-8").splitlines():
        text = line.split("//", 1)[0].strip()
        if text and not text.startswith(".") and not text.endswith(":"):
            lines += [f".GLOBAL x_i{k};", f"x_i{k}:"]
            k += 1
        lines.append(line)
    lab = work / (src.stem + "_lab.asm")
    lab.write_bytes(("\n".join(lines) + "\n").encode())
    obj = work / (src.stem + ".doj")
    r = m1._wsl(f"{m1.SELAS} -proc ADSP-21569 -o {m1._wsl_path(obj)} {m1._wsl_path(lab)}\n", work)
    if r.returncode or not obj.exists():
        raise SystemExit(f"selas failed for {src.name}:\n{r.stdout}{r.stderr}")
    data = obj.read_bytes()
    syms = sharc_object.symbols(data)
    offs = [2 * syms[f"x_i{j}"] for j in range(k)]
    return fix_shift_imm(sharc_object.code(data, "seg_pmco"), offs), offs

def fix_shift_imm(be: bytes, offs: list[int]) -> bytes:
    """Type 6b shift by an immediate, `Rn = LSHIFT Rx BY -k`: sign-extend the shift field.

    The field is 12 bits; its top four bits sit at bits 14:11 of the instruction's third
    and fourth bytes. selas writes them as 0 for a negative shift, so `BY -16` assembles
    as 023e 0000 f00b. Stock DN2 1.11 writes 023e 7800 f00b: all 368 of its negative
    shift immediates carry 0x78 there and all 281 positive ones 0x00. Both decoders ignore
    those bits, so the runner took ours as valid; on silicon it raised ILOPI
    (docs/waverider-dsp-compare.md, section 11)."""
    out = bytearray(be)
    for o in offs:
        insn = out[o:o + 6]
        if len(insn) == 6 and insn[0] == 0x02 and insn[1] == 0x3E and insn[2] == 0 and insn[3] == 0                 and insn[4] & 0x80:
            out[o + 2] = 0x78
    return bytes(out)

def _selas_line(line: str, work: pathlib.Path):
    src = work / f"one_{abs(hash(line)) & 0xffff:x}.asm"
    src.write_bytes((".SECTION/PM seg_pmco;\n.GLOBAL f.;\nf.:\n" + line + "\nNOP;\n").encode())
    be, off = _selas(src, work)
    # first instruction only (strip the trailing NOP: it is the last parcel-aligned instr)
    end = off[1] if len(off) > 1 else len(be)
    return be[:end], off

