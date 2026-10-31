"""Original USB probe generator, narrowed to its compose function.

From dn2_firmware_explore V7 research snapshot, AGPL-3.0-or-later.
Derived from irpina/digihealth (sysinfo.s), GPL-2.0-or-later,
used under GPL-3.0 within the AGPL project. See dnfw/LICENSE.
No firmware or compiled payload is stored here.
"""

import struct
from pathlib import Path
from dnfw.patch import cbuild

SRC = Path(__file__).resolve().parent / "dnfw/csrc/usbprobe"

BASE = 0x40000400
MAIN_OS = 3

# The cave: one of the three 896-byte runs `dnfw cave scan` passes on both
# checks. It is shared with lfowaves (its stub) and arpplocks (its UI cave),
# so the probe excludes those two; it is clear of lfo4, bootscreen, midiarp,
# arpmodes, moddest and fxmod, and of waverider-m5b's section 3.
CAVE, CAVE_CAP = 0x402CF52C, 896
RAM = 0x46F00000                     # above BSS end 0x466b74d0; 0x900 bytes
# STATS layout 2's code and counters (`csrc/usbprobe/ext.S`), because the first
# cave was full. The second of the three clean 896-byte runs, 0x402d0664,
# entered 4 B in and left 4 B short of arpmodes' cave at 0x402d08c0, which
# guards 4 B either side of itself. midiarp (to 0x402d0872) and arpplocks (to
# 0x402d08b8) execute from this run, so the probe excludes those two -- it
# already excluded arpplocks.
CAVE2, CAVE2_CAP = 0x402D0668, 0x402D08B8 - 0x402D0668
TAG_BYTES = 16

# (what, site, stock bytes, the routine it now calls). Each stock run is one
# whole 6-byte instruction, replayed by the routine it calls.
SITES = [
    ("SysEx router, before the Elektron header compare", 0x4012169A,
     "47f940207ae6", "probe_rx"),                         # lea 0x40207ae6,%a3
    ("audio-frame ISR, after its register save", 0x40025E3E,
     "2039fc045640", "isr_in"),                           # movel 0xfc045640,%d0
    ("audio-frame ISR, its frame count before rte", 0x40027B82,
     "52b94058e8d4", "isr_out"),                          # addql #1,0x4058e8d4
    ("context switch, interrupts masked", 0x40000438,
     "203cffffdfff", "task_switch"),                      # movel #0xffffdfff,%d0
]

# Read, not written: the code the hooks rely on around each site.
GUARDS = [
    (0x4012166E, "4feffff048d70c0c"),   # the router's entry
    (0x40207AE6, "f000203c"),                            # the header its compare walks
    (0x401216BE, "71927617b680656a"),                    # device byte > 0x17 is dropped
    (0x401233F2, "42004fefffe848d70c1c"),                # the SysEx sender's entry
    (0x4012092C, "2f027402222f0008206f000c202f0010b480"),  # stock MidiRpc: port 2 or 4 = USB
    (0x40025E36, "4e56ff1448d73fff"),                    # the ISR's register save
    (0x40027BBE, "4cee3fffff144e5e4e73"),                # ... and its only rte
    (0x40000410, "46fc2700"),                            # the switch masks interrupts
    (0x40000452, "4ce8ffff000c4e73"),                    # ... and reloads every register
    (0x400CF0E2, "60fe"),                                # the idle loop's spin (the prio-1 task)
]


def compose(stock: bytes) -> dict:
    for what, va, want, _ in SITES:
        got = stock[va - BASE:va - BASE + len(want) // 2].hex()
        if got != want:
            raise SystemExit(f"{what} at 0x{va:08x} is {got}, not {want}: not stock 1.11")
    for va, want in GUARDS:
        got = stock[va - BASE:va - BASE + len(want) // 2].hex()
        if got != want:
            raise SystemExit(f"guard 0x{va:08x} is {got}, not {want}: not stock 1.11")
    cave_stock = stock[CAVE - BASE:CAVE - BASE + CAVE_CAP]
    if any(cave_stock):
        raise SystemExit(f"cave 0x{CAVE:08x} is not free in this image")

    cave2_stock = stock[CAVE2 - BASE:CAVE2 - BASE + CAVE2_CAP]
    if any(stock[CAVE2 - BASE - 4:CAVE2 - BASE + CAVE2_CAP + 4]):
        raise SystemExit(f"cave 0x{CAVE2:08x} is not free in this image")
    ext = cbuild.build([SRC / "ext.S"], base=CAVE2, include=[SRC],
                       entries=["ext_out", "ext_sw", "ext_stats"])
    if ext.bss or len(ext.image) > CAVE2_CAP:
        raise SystemExit(f"ext.S is {len(ext.image)} B (+{ext.bss} bss), its cave {CAVE2_CAP} B")
    linked = cbuild.build([SRC / "usbprobe.S"], base=CAVE, include=[SRC],
                          entries=[s for *_, s in SITES],
                          defines={"RAM": f"0x{RAM:08x}", "TAG_BYTES": TAG_BYTES,
                                   "EXT_OUT": f"0x{ext['ext_out']:08x}",
                                   "EXT_SW": f"0x{ext['ext_sw']:08x}",
                                   "EXT_STATS": f"0x{ext['ext_stats']:08x}"})
    if linked.bss:
        raise SystemExit(f"{linked.bss} B of .bss: the probe keeps its state in the cave")
    code = linked.image
    if len(code) > CAVE_CAP:
        raise SystemExit(f"the probe is {len(code)} B, the cave {CAVE_CAP} B")
    tag_va = linked["probe_tag"]
    if any(code[tag_va - CAVE:tag_va - CAVE + TAG_BYTES]):
        raise SystemExit("the tag field is not zero in the linked image")

    edits = [{"va": CAVE, "stock": cave_stock[:len(code)].hex(), "new": code.hex(),
              "what": f"usbprobe code cave, {len(code)} of {CAVE_CAP} B"},
             {"va": CAVE2, "stock": cave2_stock[:len(ext.image)].hex(), "new": ext.image.hex(),
              "what": f"usbprobe STATS layout 2 cave, {len(ext.image)} of {CAVE2_CAP} B"}]
    for what, va, want, target in SITES:
        new = bytes.fromhex("4eb9") + struct.pack(">I", linked[target])
        edits.append({"va": va, "stock": want, "new": new.hex(), "what": f"usbprobe hook: {what}"})
    return {
        "os": "Digitone II 1.11",
        "licence": "derived from irpina/digihealth (sysinfo.s), GPL-2.0-or-later, used here under GPL-3.0 within this AGPL-3.0-or-later project",
        "stock_length": len(stock),
        "cave": {"va": CAVE, "capacity": CAVE_CAP, "used": len(code)},
        "cave2": {"va": CAVE2, "capacity": CAVE2_CAP, "used": len(ext.image)},
        "ram": {"va": RAM, "length": 0x900},
        "tag": {"va": tag_va, "length": TAG_BYTES},
        "edits": edits,
        "guards": [{"va": va, "bytes": want} for va, want in GUARDS],
        "symbols": {k: v for k, v in sorted({**linked.symbols, **ext.symbols}.items())
                    if not k.startswith("__")},
        "routines": {k: v for k, v in sorted({**linked.routines(), **ext.routines()}.items())},
    }

