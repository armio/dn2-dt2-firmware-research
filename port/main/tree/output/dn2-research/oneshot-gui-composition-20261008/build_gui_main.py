#!/usr/bin/env python3
"""Compose a bounded GUI extension on the frozen, hardware-tested MAIN.

No packing, device access or edits to any input artifact. The full-page draw
entry must be an independently reviewed cdecl function
(view, canvas, dispatch_value), not
the waveform-only widget. It owns the fixed UI workspace internally.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
OWN = Path(__file__).resolve().parent
ROOT = OWN.parents[2]
MERGE = ROOT / "firmware/ghidra/storage-proof/oneshot-storage-merge-v1"
BASE = 0x40000400
MAIN_SHA = "a44c4584e82e0e5bedcdc5a46a479ecd70c74c6b21340d58e73a5aa44634c77a"
GUI_BASE, CODE_LIMIT = 0x47A52A00, 0x47A56000
WORKER, WORKER_SOURCE, WORKER_BYTES = 0x47A52000, 0x403304C0, 2404
GUI_SOURCE, GUI_FILE = 0x40330EC0, 0x330AC0
WORKSPACE, WORKSPACE_BYTES = 0x47A56C00, 0x240
COUNT_OPERAND, TAG_ADDRESS = 0x40322996, 0x402CF884
TAG = "os1fs-gui-v1"
BINUTILS = MERGE / "toolchain/build"
BE = lambda value: struct.pack(">I", value)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv):
    process = subprocess.run([str(v) for v in argv], capture_output=True,
                             text=True, stdin=subprocess.DEVNULL)
    if process.returncode:
        raise RuntimeError(f"{argv}: {process.stdout}\n{process.stderr}")
    return process.stdout


def assemble(source, address, folder):
    folder.mkdir(parents=True, exist_ok=False)
    (folder / "code.s").write_text(".text\n" + source + "\n")
    run([BINUTILS / "gas/as-new", "-mcpu=5475", folder / "code.s", "-o", folder / "code.o"])
    run([BINUTILS / "ld/ld-new", f"-Ttext=0x{address:x}", "-e", "0", "--no-warn-rwx-segments",
         folder / "code.o", "-o", folder / "code.elf"])
    run([BINUTILS / "binutils/objcopy", "-O", "binary", "-j", ".text", folder / "code.elf", folder / "code.bin"])
    dump = run([BINUTILS / "binutils/objdump", "-d", "-m", "m68k:cfv4e", folder / "code.elf"])
    assert "<unknown>" not in dump
    (folder / "code.asm").write_text(dump)
    symbols = {}
    for line in run([BINUTILS / "binutils/nm-new", "--defined-only", folder / "code.elf"]).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in ("t", "T") and fields[2] not in ("__bss_start", "_edata", "_end"):
            symbols[fields[2]] = int(fields[0], 16)
    (folder / "symbols.json").write_text(json.dumps(symbols, indent=2) + "\n")
    return (folder / "code.bin").read_bytes(), symbols


def changed_ranges(old, new):
    rows, cursor = [], 0
    while cursor < len(old):
        if old[cursor] == new[cursor]:
            cursor += 1
            continue
        start = cursor
        while cursor < len(old) and old[cursor] != new[cursor]:
            cursor += 1
        rows.append({"file_offset": hex(start), "rom_address": hex(BASE + start),
                     "bytes": cursor - start, "before": old[start:cursor].hex(), "after": new[start:cursor].hex()})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui-bin", type=Path, required=True)
    parser.add_argument("--gui-symbols", type=Path, required=True,
                        help="JSON symbols object, or a build receipt containing symbols")
    parser.add_argument("--gui-receipt", type=Path, required=True)
    parser.add_argument("--controls-bin", type=Path, required=True)
    parser.add_argument("--controls-receipt", type=Path, required=True)
    parser.add_argument("--extra-source", type=Path, action="append", default=[],
                        help="Reviewed fullpage/helper assembly appended after the waveform component")
    parser.add_argument("--draw-symbol", default="os_gui_page_draw")
    parser.add_argument("--poll-symbol", default="os_gui_poll")
    parser.add_argument("--output-dir", type=Path, default=OWN / "candidate")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    assert output.is_relative_to(OWN) and not output.exists(), "Use a fresh directory inside the owned composition review"
    input_paths = [MERGE / "runtime-candidate/main-os.bin", MERGE / "runtime-candidate/build-receipt.json",
                   MERGE / "runtime-candidate/worker.bin", args.gui_bin.resolve(), args.gui_symbols.resolve(),
                   args.gui_receipt.resolve(), args.controls_bin.resolve(), args.controls_receipt.resolve(),
                   Path(__file__).resolve()] + [p.resolve() for p in args.extra_source]
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in input_paths}
    original = input_paths[0].read_bytes()
    assert sha(original) == MAIN_SHA and len(original) == 0x330A24
    baseline_recipe = json.loads(input_paths[1].read_text())
    assert baseline_recipe["main_sha256"] == MAIN_SHA and baseline_recipe["copier_bytes"] == 250
    worker = input_paths[2].read_bytes()
    assert len(worker) == WORKER_BYTES
    assert original[WORKER_SOURCE - BASE:] == worker
    symbol_json = json.loads(args.gui_symbols.read_text())
    gui_symbols = symbol_json.get("symbols", symbol_json)
    gui_symbols = {name: int(value, 0) if isinstance(value, str) else value for name, value in gui_symbols.items()}
    waveform = args.gui_bin.read_bytes()
    assert len(waveform) > 0 and len(waveform) % 4 == 0
    assert GUI_BASE + len(waveform) < CODE_LIMIT
    gui_receipt = json.loads(args.gui_receipt.read_text())
    assert gui_receipt["ok"] is True
    assert gui_receipt["main_sha256"] == MAIN_SHA
    assert gui_receipt["sha256"] == sha(waveform)
    assert int(gui_receipt["load"], 0) == GUI_BASE
    assert gui_receipt["workspace_bytes"] <= WORKSPACE_BYTES
    output.mkdir(parents=True)
    snapshots = []
    for path in input_paths:
        relative = path.relative_to(ROOT)
        snapshot = output / "inputs" / relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(path.read_bytes())
        assert sha(snapshot.read_bytes()) == hashes[str(relative)]
        snapshots.append({"source": str(relative), "snapshot": str(snapshot.relative_to(ROOT)),
                          "sha256": hashes[str(relative)]})
    gui = bytearray(waveform)
    controls = args.controls_bin.read_bytes()
    controls_recipe = json.loads(args.controls_receipt.read_text())
    controls_start = int(controls_recipe["load"], 0)
    assert controls_start == 0x47A53A00 and controls_recipe["main_sha256"] == MAIN_SHA
    assert controls_recipe["sha256"] == sha(controls) and controls_recipe["bytes"] == len(controls)
    assert int(controls_recipe["end"], 0) == controls_start + len(controls)
    assert GUI_BASE + len(gui) <= controls_start and controls_start + len(controls) < CODE_LIMIT
    gui.extend(bytes(controls_start - GUI_BASE - len(gui)))
    gui.extend(controls)
    for name, value in controls_recipe["symbols"].items():
        address = int(value, 0)
        assert name not in gui_symbols and controls_start <= address < controls_start + len(controls)
        gui_symbols[name] = address
    extras = []
    for index, path in enumerate(args.extra_source):
        gui.extend(bytes((-len(gui)) % 16))
        address = GUI_BASE + len(gui)
        definitions = "\n".join(f".equ {name},{value:#x}" for name, value in gui_symbols.items())
        data, symbols = assemble(definitions + "\n" + path.read_text() + "\n.balign 4\n", address,
                                 output / f"assembly/extra-{index:02d}")
        assert data and len(data) % 4 == 0 and address + len(data) < CODE_LIMIT
        new_symbols = {name: value for name, value in symbols.items() if name not in gui_symbols}
        assert all(address <= value <= address + len(data) for value in new_symbols.values())
        gui_symbols.update(new_symbols)
        gui.extend(data)
        extras.append({"source": str(path.resolve().relative_to(ROOT)), "address": hex(address),
                       "bytes": len(data), "sha256": sha(data), "symbols": {k:hex(v) for k,v in new_symbols.items()}})
    poll, draw = gui_symbols[args.poll_symbol], gui_symbols[args.draw_symbol]
    assert all(GUI_BASE <= address < GUI_BASE + len(gui) and address % 2 == 0 for address in (poll, draw))
    bridge_address = GUI_BASE + len(gui)
    bridge_source = f""".global gui_ui_hook,gui_draw_hook,gui_bridges_end
gui_ui_hook:
| Duplicate the original screen stack argument for the native tailcall chain.
move.l 4(%sp),-(%sp)
jsr 0x47a52000
lea 4(%sp),%sp
| Preserve actual native isDirty results, all volatile registers and CCR.
lea -16(%sp),%sp
movem.l %d0-%d1/%a0-%a1,(%sp)
move.w %ccr,%d0
move.l %d0,-(%sp)
pea {WORKSPACE:#x}
jsr {poll:#x}
lea 4(%sp),%sp
btst #1,%d0
beq.s gui_ui_restore
| An actual cache publication/invalidation marks the native screen dirty once.
move.l 24(%sp),-(%sp)
jsr 0x4011d2fe
lea 4(%sp),%sp
move.l 24(%sp),-(%sp)
jsr 0x4011d2f4
move.w %ccr,%d1
lea 4(%sp),%sp
move.l %d0,4(%sp)
move.l %a0,12(%sp)
move.l %d1,(%sp)
gui_ui_restore:
move.l (%sp)+,%d0
move.w %d0,%ccr
movem.l (%sp),%d0-%d1/%a0-%a1
lea 16(%sp),%sp
rts
gui_draw_hook:
| Entered by JMP with the original parent frame, not a synthetic return.
| Explicit dispatch value prevents guessing the machine type from view.
move.l %d0,-(%sp)
move.l %d2,-(%sp)
move.l %a2,-(%sp)
jsr {draw:#x}
lea 4(%sp),%sp
| The original shared ADDQ8 and register/stack epilogue remain untouched.
jmp 0x400182c4
gui_bridges_end:
.balign 4
"""
    bridges, bridge_symbols = assemble(bridge_source, bridge_address, output / "assembly/bridges")
    final_end = bridge_address + len(bridges)
    assert final_end <= CODE_LIMIT and final_end % 4 == 0
    raw = bytearray(original)
    patches = []
    def patch(address, expected, value, why):
        assert len(expected) == len(value)
        offset = address - BASE
        assert raw[offset:offset + len(expected)] == expected, (hex(address), why)
        raw[offset:offset + len(value)] = value
        patches.append({"address": hex(address), "file_offset": hex(offset), "bytes": len(value),
                        "before": expected.hex(), "after": value.hex(), "why": why})
    patch(COUNT_OPERAND, BE(WORKER_BYTES // 4), BE((final_end - WORKER) // 4), "Extend fifth contiguous copy only")
    patch(0x4002E464, bytes.fromhex("4eb947a52000"), bytes.fromhex("4eb9") + BE(bridge_symbols["gui_ui_hook"]),
          "Native UI poll/isDirty first; UI-only waveform cache afterward")
    patch(0x400182BC, bytes.fromhex("2f022f0a4ebaf166"), bytes.fromhex("4ef9") + BE(bridge_symbols["gui_draw_hook"]) + bytes.fromhex("4e71"),
          "Only selected draw branch; preserve shared stack cleanup at400182C4")
    patch(0x4033031C, bytes.fromhex("7001"), bytes.fromhex("7002"), "ONESHOT has exactly two native Source pages")
    patch(0x400C24EE, bytes.fromhex("4ef947a38860"), bytes.fromhex("4ef9") + BE(gui_symbols["os_gui_page_accessor"]),
          "Type5 page0/page1 explicit accessor; all other types retain original prologue/fallback")
    patch(0x401F80B8, bytes.fromhex("400e31d0"), BE(gui_symbols["os_controls_sample_format"]),
          "Truthful fixed-bank sample display A1; parameter editing and audio value unchanged")
    patch(TAG_ADDRESS, b"os1fs-live-v1".ljust(16, b"\0"), TAG.encode().ljust(16, b"\0"), "Exact GUI build identity; protocol4 unchanged")
    assert raw[0x400182C4 - BASE:0x400182D0 - BASE] == original[0x400182C4 - BASE:0x400182D0 - BASE]
    assert raw[WORKER_SOURCE - BASE:len(original)] == worker
    assert len(raw) <= GUI_FILE
    raw.extend(bytes(GUI_FILE - len(raw)))
    raw.extend(gui)
    raw.extend(bridges)
    assert len(raw) == WORKER_SOURCE - BASE + final_end - WORKER
    allowed = [(p["address"], p["bytes"]) for p in patches]
    for offset, (old, new) in enumerate(zip(original, raw)):
        if old != new:
            assert any(int(address, 0) <= BASE + offset < int(address, 0) + size for address, size in allowed)
    assert sha(worker) == baseline_recipe["worker_sha256"]
    for path, digest in hashes.items():
        assert sha((ROOT / path).read_bytes()) == digest, ("input changed during build", path)
    (output / "main-os.bin").write_bytes(raw)
    (output / "gui.bin").write_bytes(gui)
    (output / "bridges.bin").write_bytes(bridges)
    copies = baseline_recipe["copies"]
    copies[-1] = {**copies[-1], "bytes": final_end - WORKER}
    report = {"schema": "dn2-gui-composition-v1", "ok": True, "approved_for_packaging": False,
              "scope": "Exact raw composition only; GUI semantic and native copy/ABI gates are separate",
              "input_main_sha256": MAIN_SHA, "main_sha256": sha(raw), "bytes": len(raw),
              "builder_sha256": sha(Path(__file__).read_bytes()), "source_hashes_at_build": hashes,
              "source_snapshots": snapshots,
              "required_file_hashes": {item["snapshot"]: item["sha256"] for item in snapshots},
              "gui_sha256": sha(gui), "waveform_sha256": sha(waveform), "extra_sources": extras,
              "controls": {"ram": hex(controls_start), "bytes": len(controls), "sha256": sha(controls)},
              "bridge_sha256": sha(bridges), "symbols": {k:hex(v) for k,v in bridge_symbols.items()},
              "gui_symbols": {k:hex(v) for k,v in gui_symbols.items()}, "poll_entry": hex(poll), "draw_entry": hex(draw),
              "fullpage_draw_contract": "cdecl(view, canvas, dispatch_value); guarded fallback and native controls supplied by GUI component",
              "tag": TAG, "probe_protocol": 4, "copier_bytes": 250, "copies": copies,
              "gui_code": [hex(GUI_BASE), hex(final_end)], "gui_rom": [hex(GUI_SOURCE), hex(BASE + len(raw))],
              "gui_file_start": hex(GUI_FILE), "workspace": [hex(WORKSPACE), hex(WORKSPACE + WORKSPACE_BYTES)],
              "frame": ["0x47a56100", "0x47a56b80"], "existing_clear_ranges": baseline_recipe["clear_ranges"],
              "worker_prefix_exact": True, "existing_DSP_ISR_and_native_FS_bytes_exact": True,
              "shared_draw_cleanup_exact": True, "patches": patches,
              "changed_prefix_ranges": changed_ranges(original, raw),
              "limitations": ["Recovered stock owners are unchanged; no universal RAM ownership claim.",
                              "GUI fullpage readiness and type/source/count guards require their separate proof.",
                              "No packing, hardware, audio or physical GUI test occurs here."]}
    (output / "build-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k:report[k] for k in ("ok", "main_sha256", "bytes", "gui_code", "workspace", "copier_bytes")}, indent=2))


if __name__ == "__main__":
    main()
