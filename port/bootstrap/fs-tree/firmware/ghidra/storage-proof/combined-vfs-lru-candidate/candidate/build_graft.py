#!/usr/bin/env python3
"""Build the ekFS graft: DT2 1.16 +Drive sample filesystem -> DN2 1.11 MAIN_OS.

Follows firmware/ghidra/PLUSDRIVE-GRAFT-SPEC.md, with the architecture settled
during analysis:

  - flash driver family retargeted to DN2's own (byte-identical siblings)
  - shared libc/mutex/libgcc functions retargeted (full-body verified)
  - publish-chain call NOP'd (DT2-only UI mirror notification)
  - ekFS code, VFS state (remapped RAM), factory strings/tables grafted

  - v7 (relocate-at-boot): v1/v2/v5 all logo-hung for the SAME root cause:
    the graft sat inside the OS-owned RAM range [0x402FC000, 0x466B74D0)
    (v1 over live variables; v2/v5 in the bss past the image end -- the
    init table overwrote the graft before the wrapper ran). v6 moved the
    home to 0x49000000 and HARDWARE-VALIDATED the boot mechanism: the OS
    booted fully (copyr ran, stock clear ran, display and exception
    handler up) but threw EXCEPTION V04 (illegal instruction) at the
    wrapper PC 0x4900005C -- the copy's writes completed silently while
    fetches read garbage: 0x49000000 is an unbacked hole. (The 0x4E6Dxxxx
    flash-driver state does NOT prove contiguous RAM above 0x48000000.)
    v7 moves the home one constant, to 0x466C0000: the bottom of the
    stack band [0x466B74D0, 0x48000000) -- stock-proven bank-0 SDRAM
    (code runs at 0x40000400, stack top 0x48000000, one chip select),
    zero references (band scan finds only SP-top 0x47FFFFFC writes and
    the 0x47EFFFFF stack floor), 21.9 MB below the stack floor, and the
    same kind of space DT2 itself uses for its ekFS bss clusters (DT2's
    SP is 0x48000000 too, byte-parallel reset).

  - the stock bss-clear body (file 0xB2) jumps to a 92-byte position-
    independent copy+clear routine at the graft's IMAGE address
    (0x4030B980): it copies the graft to 0x466C0000 BEFORE anything uses
    bss, then runs the STOCK clear over the FULL stock range -- the image
    tail becomes ordinary zeroed bss again, so every OS variable and the
    DDR-restore blocks behave exactly as shipped. Register contract
    matches the stock clear (A0/D1 clobberable, D4-D7 preserved; A1/A2
    additionally saved).

  - master-init hook: helper2 jsr (file 0xCEB50) redirected to the graft
    wrapper at 0x466C0000+92 (zero state, stock helper2, premount,
    mount(0)) -- runs after flash-init AND helper1 installed the flash
    IRQ handlers the mount's flash read depends on.

  - v8 (format-on-first-boot): the wrapper now calls the grafted DT2
    #FORMAT_FS path (FUN_4015A424 -> FUN_4015A164: erase the ekFS LBAs,
    write superblock magic 0x656B4653 v4 + geometry + VFS root + CRC,
    remount) whenever mount(0) fails on the missing superblock magic.
    First boot on a content-less DN2: the +Drive formats itself and
    comes up MOUNTED and EMPTY ( Elektron's factory flow, no jig).
    Format closure: DT2_FUN_4015A424 + 90-fn subtree (DumpClosure.java
    walk, merged into dt2_closure.log); erase 0x4012DDF2 retargets to
    DN2's own driver sibling (auto-match).

Usage: build_graft.py [--write] [--no-mount]   (default: dry-run report)
"""
import re
import struct
import sys

DT2 = '@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/inputs/dt2-1.16-main-os.bin'
DN2 = '@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/inputs/dn2-1.11-main-os.bin'
CLOSURE = '@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/inputs/dt2_closure.log'
OUT = '@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/candidate/main-os.bin'

BASE = 0x40000400
DT2_SBSS = 0x40312000          # DT2 bss start
APPEND_AT = 0x30B580           # stock image length; graft stored here
IMAGE_STORE = 0x4030B980       # = 0x40000400 + APPEND_AT (graft's image addr)
GRAFT_BASE = 0x46800000        # v49: the RELOCATION. The graft now lives
                               # ABOVE the stock allocator's arena, in the
                               # band a third party runs hardware-proven
                               # compiled C from (dn2_firmware_explore:
                               # lfo4-ext code at 0x46800000..0x46806d54,
                               # its table at 0x46900000 -- all shipped
                               # and stable across many flashed mods).
                               # v44-v48 hardware proved the OLD band
                               # (0x466C0000..) is scribbled by a wandering
                               # async writer (heap/pool churn: four CK
                               # flips at four different times, code-only,
                               # varying values -- the v22 pool-record,
                               # v31 churn-window, v32 zero-hole writer),
                               # and heals cannot chase it (v48: the [G3,G5]
                               # window was CLEAN and the crash still
                               # happened). If the crash PERSISTS at this
                               # new base, the scribble theory is falsified
                               # and the derailment is data-dependent --
                               # either way this one flash discriminates.
BSS_CLEAR_END = 0x466B74D0     # stock bss-clear end constant (stays as-is)
DN2_BSSCLEAR_FILE = 0xB2       # file offset of the bss-clear function body

# v5 hook: the helper2 jsr (runs after flash-init AND helper1 have both
# installed the flash IRQ handlers the mount's flash read depends on)
DN2_MASTER_JSR_FILE = 0xCEB50  # jsr <helper2> inside DN2 master init
DN2_HOOK_TARGET = 0x4012C340   # stock helper2 (FUN_4012c340)
MOUNT_AT_BOOT = '--no-mount' not in sys.argv
CONSOLE = '--console' in sys.argv   # v10/v11: + boot-flags bit 0x20 (service
# console, hardware-proven in v9) on top of the v8_3 format path
FMT_CMD = '--fmt-cmd' in sys.argv   # v12: v9-style boot (console, NO format
# at boot) + a #FORMAT console command: the dispatcher's no-op #BREAK
# handler is repointed to the grafted format, so it runs in the CONSOLE
# TASK (task context -- DT2's own #FORMAT_FS runs in its console task;
# DN2 user project-saves prove eMMC writes work in task context).
DT2_PREMOUNT = 0x4015A43A      # grafted; called by the wrapper
DT2_MOUNT = 0x4015A450         # grafted; called by the wrapper

# publish family (DT2-only UI mirror notification) - call sites get NOP'd
PUBLISH = {0x400C0EEA, 0x400C0EC8, 0x400C0E9E, 0x400C0D1C}

# verified retargets (direct-compare asserted); everything else is
# auto-classified by the full-body matcher or grafted
KNOWN = {
    # early-boot / mutex family: byte-parallel region, identical addresses
    0x40001164: 0x40001164,
    0x400011A6: 0x400011A6,
    0x400011EE: 0x400011EE,
    0x4000141A: 0x4000141A,
    0x4000157C: 0x4000157C,
    0x400015A0: 0x400015A0,
    0x400016D2: 0x400016D2,
    0x40001896: 0x40001896,
    # flash driver: retarget to DN2's own (verified by decompile compare)
    0x4012DEDA: 0x4012C59A,   # flash read
    0x4012E0C0: 0x4012C780,   # flash write
    0x4012DDF2: 0x4012C4B2,   # flash erase (prologue + pea 0x23/24/26
                              # triple: DN2 0x4012C4EE/510/520)
}

# rodata blobs carried from DT2 (image addresses); None end = computed
STRING_BLOCK = (0x40229DCA, None)
DIR_TABLE = (0x4029EB8C, 0x4029ED00)      # 29 ptrs
PAIR_TABLE = (0x4029ED00, 0x402A1488)     # 1265 x {hash, path}
MISC_RODATA = {                            # target: bytes to carry
    0x4023c8e6: 16,    # "/incoming\0" (format remount-path dir name)
    0x4021F848: 8,     # ""
    0x40240503: 8,     # ".."
    0x4024344A: 8,     # "."
    0x402B663C: 0x100, # {mutex ptr, -0x20, ...} table
}


def be(v):
    return struct.pack('>I', v)


# ---------------------------------------------------------------- closure ---
fns = {}   # entry -> (end, name)
insts = {} # addr -> length
refs = []  # (frm, to, ty, desc)
inst_re = re.compile(r'^INST ([0-9a-f]+) ([0-9a-f]+|[0-9]+)$')
ref_re = re.compile(r'^REF ([0-9a-f]+) ([0-9a-f]+) (\S+) ; (.*)$')
fn_re = re.compile(r'^FN ([0-9a-f]+) ([0-9a-f]+) (\d+) (\S+)( THUNK)?$')
for line in open(CLOSURE):
    line = line.split('DumpClosure.java> ', 1)[1].strip() \
        if 'DumpClosure.java> ' in line else line.strip()
    line = line.replace(' (GhidraScript)', '')
    m = inst_re.match(line)
    if m:
        insts[int(m.group(1), 16)] = int(m.group(2))
        continue
    m = ref_re.match(line)
    if m:
        refs.append((int(m.group(1), 16), int(m.group(2), 16),
                     m.group(3), m.group(4)))
        continue
    m = fn_re.match(line)
    if m:
        fns[int(m.group(1), 16)] = (int(m.group(2), 16), m.group(4))

dt2 = open(DT2, 'rb').read()
dn2 = open(DN2, 'rb').read()
dn2_entries = set(int(x, 16) for x in
                  open('@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/inputs/dn2_entries.txt').read().split())
report = []
fail = []


def rprint(*a):
    s = ' '.join(str(x) for x in a)
    report.append(s)
    print(s)


# ------------------------------------------------------------- 1. classify ---
def is_reloc_value(v):
    # DT2 code/rodata addresses, DT2 RAM, peripherals, flash offsets
    return (0x40000000 <= v < 0x50000000) or (0xEC000000 <= v < 0x100000000) \
        or (0x00400000 <= v < 0x00460000) or (0xFC000000 <= v < 0x100000000)


def masked_pattern(buf):
    pat = bytearray(buf)
    mask = bytearray(b'\xff' * len(buf))
    i = 0
    while i + 4 <= len(buf):
        v = struct.unpack('>I', buf[i:i + 4])[0]
        if is_reloc_value(v):
            mask[i:i + 4] = b'\x00\x00\x00\x00'
            i += 4
            continue
        i += 2
    return bytes(pat), bytes(mask)


def longest_solid_run(mask):
    best, run, start = (0, 0), 0, 0
    for j in range(len(mask)):
        if mask[j] == 0xFF:
            run += 1
            if run > best[0]:
                best = (run, start)
        else:
            run = 0
            start = j + 1
    return best  # (length, offset)


def find_in_dn2(pat, mask):
    """All DN2 offsets where the masked pattern matches."""
    hits = []
    n = len(pat)
    rlen, roff = longest_solid_run(mask)
    if rlen < 4:
        return None  # too masked; caller decides
    chunk = pat[roff:roff + rlen]
    i = dn2.find(chunk)
    while i != -1:
        s = i - roff
        if s >= 0 and s + n <= len(dn2) and all(
                (dn2[s + j] & mask[j]) == (pat[j] & mask[j])
                for j in range(n) if mask[j] == 0xFF):
            hits.append(s)
        i = dn2.find(chunk, i + 1)
        if len(hits) > 64:
            break
    return hits


rprint(f'closure: {len(fns)} functions, {len(refs)} refs')
shared = {}   # dt2 entry -> dn2 entry (retarget)
grafted = {}  # dt2 entry -> span end

# v36: FORCE-GRAFT memcmp (DT2 0x40189FF4, byte-identical sibling of DN2
# 0x4017e8a8). The v33/v34/v35 evidence chain is complete:
#   - the wipe path compares paths via `lea 0x40189ff4,A3; jsr (A3)`
#   - the full-body matcher classified memcmp as shared and the build
#     RETARGETED it to STOCK 0x4017e8a8 (v35 build log: "RETARGET
#     FUN_40189ff4 -> 0x4017e8a8"; the built graft carries
#     `lea 0x4017e8a8,A3` at 0x466c1bdc)
#   - on this unit, the longword at 0x4017e8a8 reads back STALE BUS DATA
#     (v35: memcmp probed EARLY/MID/LATE returned the previous probe's
#     first dword every time -- wrmutex's 00000000, dense-3c00's
#     0811B908, drv-dispatch's 206F0004; bytes 4..15 read CORRECT, so
#     only that one word is broken)
#   - so the retargeted call derailed AT ENTRY: execution ran the echoed
#     `2F 3C 00 00 48 D7` = move.l #0x000048D7,-(SP) -- pushing exactly
#     the 000048D7 seen in v33's crash stack -- and trapped V04 at +0xA
#     = PC 0x4017E8B2. Every v33 crash detail accounted for.
# Grafting copies memcmp into the verified-clean band instead, exactly as
# CRASH_FIRST did for udiv/bfd4/4015bce8/4015b4f0.
FORCE_GRAFT = {0x40189FF4}

for entry in sorted(fns):
    end, name = fns[entry]
    if entry in PUBLISH:
        continue
    if entry in FORCE_GRAFT:
        grafted[entry] = end
        continue
    body = dt2[entry - BASE:end - BASE]
    pat, mask = masked_pattern(body)
    hits = find_in_dn2(pat, mask)
    if entry in KNOWN:
        # direct masked comparison at the known address (search may fail on
        # short bodies or heavily masked patterns); additionally mask the
        # 4-byte absolute operands of 6-byte instructions (jsr/jmp/pea/lea/
        # move.l #imm) -- masked_pattern can straddle opcode+operand and
        # leave an operand half in "solid" bytes
        tgt = KNOWN[entry] - BASE
        plen = min(32, len(pat))
        imask = bytearray(b'\xff' * plen)
        ia = entry
        while ia - entry < plen:
            ilen = insts.get(ia, 0)
            if ilen == 0:
                break
            o = ia - entry
            if ilen == 6 and o + 6 <= plen:
                imask[o + 2:o + 6] = b'\x00\x00\x00\x00'
            ia += ilen
        m = bytes(mask[i] & imask[i] for i in range(plen))
        d2 = dt2[entry - BASE:entry - BASE + plen]
        d1 = dn2[tgt:tgt + plen]
        ok = len(d1) == plen and any(m[i] == 0xFF for i in range(plen)) \
            and all(
            (d1[i] & m[i]) == (pat[i] & m[i])
            for i in range(plen) if m[i] == 0xFF)
        if not ok:
            fail.append(f'KNOWN mapping {entry:#x}->{KNOWN[entry]:#x} not '
                        f'verified by direct compare')
        elif KNOWN[entry] not in dn2_entries:
            fail.append(f'KNOWN target {KNOWN[entry]:#x} is not a DN2 entry')
        else:
            shared[entry] = KNOWN[entry]
        continue
    if hits is None:
        # body too masked to match (e.g. all-reloc trampolines): graft it
        grafted[entry] = end
        continue
    if len(hits) == 1 and hits[0] + BASE in dn2_entries:
        shared[entry] = hits[0] + BASE
    else:
        # no match, ambiguous match, or match not at a function entry:
        # grafting our own copy is always safe
        grafted[entry] = end

# functions that touch DT2 flash-driver state must never be grafted:
# their state lives in DN2's driver, a private copy would desync it
DRIVER_STATE = range(0x44E3FE7C, 0x44E3FED8 + 4)
for entry in list(grafted):
    s, e = entry, grafted[entry]
    touches = any(DT2_SBSS <= to < 0x48000000 and to in DRIVER_STATE
                  and entry <= frm < e for frm, to, ty, desc in refs)
    if touches:
        fail.append(f'driver-state function {fns[entry][1]} @{entry:#x} would '
                    f'be grafted; needs a verified DN2 counterpart')

for entry in sorted(grafted):
    end, name = fns[entry]
    rprint(f'  GRAFT {name} @{entry:#x}..{end:#x} ({end-entry} B)')
for entry in sorted(shared):
    rprint(f'  RETARGET {fns[entry][1]} {entry:#x} -> {shared[entry]:#x}')
rprint(f'grafted: {len(grafted)} fns '
       f'({sum(e - s for s, e in ((k, grafted[k]) for k in grafted))} B), '
       f'retargeted: {len(shared)}, publish-excluded: {len(PUBLISH)}')

GRAFT_ROOTS = {DT2_PREMOUNT, DT2_MOUNT, 0x4015A424}
changed = True
while changed:
    changed = False
    for entry in list(grafted):
        if entry in GRAFT_ROOTS:
            continue
        called = False
        for frm, to, ty, desc in refs:
            # v16: DATA refs (pea'd callbacks, fn-table slots) are LIVE --
            # the registrar pea's FUN_4015aa02 as an indirect callback and
            # the old CALL/JUMP-only check pruned it, leaving the pea
            # pointing at unmapped bytes.
            if ('CALL' in ty or 'JUMP' in ty or 'DATA' in ty) and to == entry:
                ef = next((e for e in grafted if e != entry
                           and e <= frm < grafted[e]), None)
                if ef is not None:
                    called = True
                    break
        if not called:
            rprint(f'  PRUNE (dead) {fns[entry][1]} @{entry:#x}')
            del grafted[entry]
            changed = True

# sanity: grafted spans must not overlap (split-fn spans are copied whole)
spans = sorted((e, grafted[e]) for e in grafted)
for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
    if s2 < e1:
        fail.append(f'grafted span overlap: {s1:#x}..{e1:#x} and {s2:#x}..{e2:#x}')
# and no grafted entry inside another span's gap is fine (span covers it)

# ------------------------------------------------- 2. RAM cluster + map ---
ram_targets = set()
for frm, to, ty, desc in refs:
    ef = next((e for e in grafted if e <= frm < grafted[e]), None)
    if ef is not None and DT2_SBSS <= to < 0x48000000:
        ram_targets.add(to)

# supplementary scan: operand-slot dwords Ghidra made no ref for
suppl = []
for entry in grafted:
    body = dt2[entry - BASE:grafted[entry] - BASE]
    for addr, ilen in insts.items():
        if not (entry <= addr < grafted[entry]):
            continue
        off = addr - entry
        for p in range(2, ilen - 2, 2):
            if off + p + 4 > len(body):
                break
            v = struct.unpack('>I', body[off + p:off + p + 4])[0]
            if v % 2 == 0 and 0x40000400 <= v < 0x48000000:
                # already covered by a real ref from this site?
                if not any(f2 == addr and t2 == v for f2, t2, _, _ in refs):
                    suppl.append((addr, v))
                    if DT2_SBSS <= v < 0x48000000:
                        ram_targets.add(v)
if suppl:
    rprint(f'supplementary operand refs: {len(suppl)}')
    for a, v in suppl[:8]:
        rprint(f'  {a:#x} -> {v:#x}')
refs = refs + [(a, v, 'SUPPL', 'supplementary') for a, v in suppl]

rprint(f'\ngraft RAM targets: {len(ram_targets)}')
clusters = []
for a in sorted(ram_targets):
    if clusters and a - clusters[-1][1] <= 0x800:
        clusters[-1][1] = a
    else:
        clusters.append([a, a])
cluster_spans = []   # (span, targets, cluster_start)
# v16: bulk-use reservations. A cluster's span must cover not just the
# REFERENCED dwords but the whole BULK REGION the code memsets/writes --
# the wipe's memset(journal, 0, 0x14010) and the VFS init's
# memset(vfs, 0, 0xb000) zero far past the referenced dword, and on the
# first v16 emu run that memset ERASED THE SUPERBLOCK MIRROR cluster
# that the packing had placed inside the journal's reach (the magic
# vanished between the F3 and G1 markers).
BULK = {
    # VFS span candidate: native transaction and bounded factory arrays.
    0x4065D8C0: 0x8000,     # hash-page raw read: 8192 dwords
    0x4067D8C4: 0x2C4000,   # (0x58000 disk + 0x800 factory) hash/id pairs
    0x40941D90: 0x8000,     # object-record lookup scratch
    0x40949D90: 0x8000,     # object-record read/modify/write scratch
    0x40959D90: 0x8000,     # object allocation bitmap scratch
    0x44F2BD6C: 0x8000,     # formatter zero-write slab
    0x46F63ED0: 0xE10000,   # 450 native 32-KiB factory data pages
    0x47D73ED0: 0x40000,    # 2048 native 128-byte factory contexts
    # Candidate: retain the native sixteen 32-KiB data-cache buffers.
    0x405D5770: 0x80000,    # native data cache; descriptors follow its full span
    # v62: these three independent scratch buffers carry a complete
    # 32-KiB flash transaction. Truncating memcpy would leave the following
    # unchanged 0x8000-byte flash write reading past the allocation.
    0x405BD770: 0x8000,     # journal read/modify/write scratch
    0x405C5770: 0x8000,     # journal release staging scratch
    0x405CD770: 0x8000,     # journal allocation staging scratch (G1)
    0x47E203CC: 0x8000,     # manifest buffer read
    0x46F4DCB0: 0x200,      # superblock mirror
    # The logical bitmap is 0x14010 B, but allocation/release stage three
    # full 0x8000-B chunks over [0x5D80C0, 0x5D8180). Reserve their whole
    # source interval, including the adjacent donor mirror/state offsets.
    0x46F39CA0: (0x005D8180 - 0x005D80C0) << 9,
    0x46F58ED0: 0xB000,     # VFS state: init memset
}
# A bulk reservation can contain targets that the address-gap heuristic
# put in later clusters. They must share the same translation: notably
# journal+0x8000 (0x46F41CA0) is an interior pointer, not a second buffer.
# Merge every cluster whose first target lies inside the reserved extent;
# retaining the old offsets also preserves the superblock/state immediately
# after the logical journal. Adjacent, non-overlapping buffers stay distinct.
merged_clusters = []
for s, e in clusters:
    if merged_clusters:
        ps, pe = merged_clusters[-1]
        reserved_end = max([pe + 1] +
                           [ba + bl for ba, bl in BULK.items()
                            if ps <= ba <= pe])
        if s < reserved_end:
            merged_clusters[-1][1] = e
            continue
    merged_clusters.append([s, e])
clusters = merged_clusters
for s, e in clusters:
    span = e - s
    bulks = [ba - s + bl for ba, bl in BULK.items() if s <= ba <= e]
    if bulks:
        span = max(span, *bulks)     # cover every bulk region in full
    else:
        span += 0x400                # struct tail pad
    span = (span + 0xFF) & ~0xFF
    ts = [t for t in ram_targets if s <= t <= e]
    cluster_spans.append((span, ts, s))
    rprint(f'  cluster {s:#x}..{e:#x} (+{span:#x} reserved'
           + (f', bulk {bulks}' if bulks else '') + ')')
state_size = sum(sp for sp, _, _ in cluster_spans)
rprint(f'state block: {state_size:#x} B (mapped inside the graft)')

# --------------------------------------------------- 3. rodata blobs ---
sb_start = STRING_BLOCK[0] - BASE
sb_end = sb_start
o = sb_start
while True:
    e = dt2.find(b'\x00', o)
    if e == -1:
        fail.append('string block scan failed')
        break
    s = dt2[o:e]
    if not s.startswith(b'/factory'):
        break
    sb_end = e + 1
    o = e + 1
string_block = (STRING_BLOCK[0], sb_end + BASE)
rprint(f'\nstring block: {string_block[0]:#x}..{string_block[1]:#x} '
       f'({string_block[1]-string_block[0]} B)')

# ------------------------------------------------------- 4. image layout ---
blob_layout = [  # (name, old_start, old_end, bytes)
    ('string_block', string_block[0], string_block[1],
     dt2[string_block[0] - BASE:string_block[1] - BASE]),
    ('dir_table', DIR_TABLE[0], DIR_TABLE[1],
     dt2[DIR_TABLE[0] - BASE:DIR_TABLE[1] - BASE]),
    ('pair_table', PAIR_TABLE[0], PAIR_TABLE[1],
     dt2[PAIR_TABLE[0] - BASE:PAIR_TABLE[1] - BASE]),
]
for t, ln in sorted(MISC_RODATA.items()):
    blob_layout.append((f'misc_{t:#x}', t, t + ln,
                        dt2[t - BASE:t - BASE + ln]))

copyr_len = 92                 # copy+clear routine leading the graft
# v56: fd_entry -- + the UNMOUNT-STATE CLEAR. v55 hardware proved the
# format takes its unmount-error path EVERY time: the FS-object scan
# (FUN_4015bce8) finds a non-zero field in [mapped(0x46F4DED0),
# mapped(0x46F4DFB0)) -- something the boot-time mount wrote -- so the
# body bails with moveq #$ff,d4 (= 0xFFFFFFFF sign-extended; our earlier
# "0 or 0xFF" reading was wrong) and NEVER RUNS. Zeroing that region is
# exactly the "unmounted" state the scan tests for. fd_entry order:
# FD -> (heal NOPd) -> U0 -> lock -> unmount -> U1 -> CLEAR -> format.
# code = 174 + pea len(4) + pea dst(6) + jsr memset(6) + addq(2) = 192 B
FD_CODE_LEN = 192
FD_STRS_LEN = 32
wrapper_len = ((60 + (14 if CONSOLE else 0)) if MOUNT_AT_BOOT else 0)
if FMT_CMD:
    # v12..v15: strings + stub + pattern + SP-trace area follow the
    # wrapper; wrapper itself is v9's 56-B body (no tail).
    wrapper_len = ((56 if MOUNT_AT_BOOT else 0)
                   + 8 + 8 + 68 + 8 + 512 + 64 + 16 + 16 + 16
                   + 8 * 40 + 32 + 82 + 386        # v29: heal + probes
                   + 44                           # v57: G5 grew (jsr+G5R)
                   + FD_CODE_LEN + FD_STRS_LEN)    # v50: fd_entry
wrapper_at = GRAFT_BASE + copyr_len     # master-init hook target (runtime)

# v27 GUARD. The --fmt-cmd omission that produced the broken v25 was
# invisible: the build still "succeeded" and still emitted a flashable
# image, it just had no #FORMAT command and a 60-byte wrapper. Every
# v12+ layout IS the --fmt-cmd layout, so refuse to build without it
# rather than shipping another image that cannot run the ladder.
if not FMT_CMD:
    fail.append('build_graft.py must be run with --fmt-cmd (v12+ layout; '
                'without it the #FORMAT command, pattern and marker '
                'thunks are not emitted)')

# v33: JUMP THE WINDOW SURGICALLY. The v31 boot map measured the damage
# precisely: a contiguous block at 0x466c3000-0x466c4000, 13/13 consecutive
# 0x100 probes damaged, with 0x466c2f00 and 0x466c4000 both byte-clean. The
# overwritten bytes are a low-entropy conversion/lookup table
# (1F/3F/7F/BF/FF/17/03/23/A3/C3), and EVERY historically-damaged address
# falls in that one block:
#     0x466c3298 / 0x466c32d0  v24 bfd4 / udiv
#     0x466c343c               v28 FUN_4015bce8
#     0x466c31e8               v29 FUN_4015b4f0
#     0x466c30f0               v31 FUN_4015b4f0 (PC landed at +2, mid-immediate)
#
# v32 tried the blunt version -- raise the whole code start to 0x466c5000 --
# and it was WORSE: total silence, then a V04 at 0x466c066e, i.e. two bytes
# into `dump4` at 0x466c066c, the last 40 B of the wrapper. The copyr is
# fine, the gap is explicitly zero-filled by the emitter, and dump4 sits at
# the SAME address as v31 where it worked -- so something at boot wrote
# there once a 20 KB zero hole appeared. Mechanism unknown; the blunt
# approach is abandoned rather than debugged blind.
#
# v33 instead leaves the layout contiguous and jumps ONLY the 4 KB
# measured window, when the running cursor would actually enter it. That
# is a 4 KB hole rather than 20 KB, and it keeps the v31 shape the map was
# proven on.
WINDOW = (0x466C3000, 0x466C4000)


def skip_window(cur):
    """Advance past the measured damaged window if cur would land in it."""
    if WINDOW[0] <= cur < WINDOW[1]:
        return WINDOW[1]
    return cur


cur = GRAFT_BASE + copyr_len + wrapper_len
cur = (cur + 3) & ~3
# v49: the v33 WINDOW is now VESTIGIAL -- the relocated base sits
# entirely above it, so skip_window never fires and the layout places
# functions contiguously (the old 4 KB hole is gone; pre-window homes
# shift by exactly +0x140000, post-window homes by +0x13F000).
assert not (WINDOW[0] < wrapper_at + wrapper_len
            and wrapper_at < WINDOW[1]), 'wrapper overlaps the window'
assert GRAFT_BASE >= WINDOW[1], 'v49: graft base must sit above the window'


def place(cur, mod):
    # advance cur so cur %% 4 == mod %% 4 (preserves DT2 alignment:
    # ColdFire faults on unaligned long accesses)
    while cur % 4 != mod % 4:
        cur += 1
    return cur


# v25: priority placement. The v24 hardware run dumped the relocated
# functions' actual boot bytes and split them cleanly:
#   0x466c1cbc (fn_new[0x40157d28]+0x70) = 4fef0010 2001e588 e9899280
#   41f31800 -- BYTE-IDENTICAL to the emulator's pristine image, i.e.
#   that code SURVIVED boot.
#   0x466c3298 (bfd4) and 0x466c32d0 (udiv) = descriptor records, and
#   both differ run-to-run (v22/v23/v24 all different) -- DESTROYED by
#   a boot-time scribbler that eats the TOP of the graft. udiv+bfd4 are
#   the two functions in every single crash frame, so this is the G3:DIV
#   / exception cause. The scribble is pre-format: the v24 CK ladder was
#   CONSTANT from F3 through G3, so nothing changes during the format.
# v28 MEASURED THIS WRONG. The v28 boot map shows 21 of 22 code probes
# byte-identical to the built image -- the graft is NOT scribbled. udiv
# and bfd4 are FULLY INTACT at boot at their v28 homes; the corruption
# seen in v22..v26 was inflicted DURING the format run, not before it.
# Exactly one code address is hit: 0x466c343c = FUN_4015bce8, the
# function ekfs_format calls at +0x18 (jsr at DT2 0x4015a17c), overwritten
# with hash/CRC-table words (B8F7B738 FF3B3535 ...) and the source of the
# v26 V04. The v28 DS0059 faults at precisely that PC, so the map
# predicted the crash out of sample.
#
# v29: move FUN_4015bce8 off 0x466c343c by making it the third
# CRASH_FIRST entry (lands ~0x466c0a0c, clear of both 0x466c343c and the
# wrapper/trampoline area), and dump the map AGAIN after format424 returns
# so one flash yields a before/after diff of what the format itself does.
CRASH_FIRST = [0x40183E94, 0x4015BFD4, 0x4015BCE8]
order = ([e for e in CRASH_FIRST if e in grafted]
         + [e for e in sorted(grafted) if e not in CRASH_FIRST])
fn_new = {}   # dt2 entry -> new entry
for entry in order:
    cur = skip_window(cur)
    cur = place(cur, entry % 4)
    fn_new[entry] = cur
    cur += grafted[entry] - entry
blob_new = {}
for name, s, e, _ in blob_layout:
    cur = skip_window(cur)
    cur = place(cur, s % 4)
    blob_new[name] = (s, e, cur)
    cur += e - s
# v25: PIN the state block to its v24-proven address. Reordering the
# crash-critical pair shrank the emitted code by ~0x4fc, which slid the
# state block down to 0x466d67e0. That is NOT cosmetic: the boot wrapper
# zeroes exactly [STATE_BASE, state_end), so the window decides which
# stock RAM variables get clean zeros. Sliding it changed boot behaviour
# (v25's mount started formatting during the boot phase and the console
# ladder never ran). Every ref into the block is patched from ram_map
# below, so restoring the address is safe and keeps the v24 behaviour
# while the two crash-critical functions move low.
STATE_BASE = max(cur, GRAFT_BASE + 0x16BC0)   # v49: the v25 pin, scaled
# with the base (old floor 0x466D6BC0 = GRAFT_BASE_old + 0x16BC0). The
# v25 lesson (sliding the state block changed boot behavior) was about
# the OLD band's stock RAM variables; at 0x46816BC0 we are deep in the
# third-party-proven unclaimed window.
ram_map = {}
state_cursor = cur
state_pad = 0
for sp, ts, cs in cluster_spans:
    want = place(state_cursor, cs % 4)
    state_pad += want - state_cursor
    for t in ts:
        ram_map[t] = want + (t - cs)
    state_cursor = want + sp
# v42: the write-checker's A2-save scratch (see the v40 stub block below
# for the ABI bug it fixes). One private dword, 16-aligned, inside the
# state block: wrapper-zeroed, measured-quiet, referenced by nothing else.
CHECKER_SCRATCH = (state_cursor + 15) & ~0xF
state_cursor = CHECKER_SCRATCH + 16
state_end = state_cursor
# Candidate-only explicit limit for the inherited documented stack floor.
STATE_LIMIT = 0x47EFFFFF
if state_end > STATE_LIMIT:
    fail.append(f'candidate state end {state_end:#x} exceeds stack floor {STATE_LIMIT:#x}')
# v33 GUARD: nothing the format executes may live in the measured window.
# v14..v31 all shipped images with functions inside it and every one of them
# died there; make that a build failure rather than a 14-minute flash.
_bad = [a for a, n in fn_new.items() if WINDOW[0] <= a < WINDOW[1]]
_bad += [blob_new[nm][2] for nm, _, _, _ in blob_layout
         if WINDOW[0] <= blob_new[nm][2] < WINDOW[1]]
if _bad:
    fail.append(f'v33: {len(_bad)} unit(s) land in the damaged window '
                f'{WINDOW[0]:#x}-{WINDOW[1]:#x}: '
                + ', '.join(hex(a) for a in sorted(_bad)[:8]))
# v16: the state block is zero-initialized scratch -- it does NOT belong
# in the image. It lives in RAM at [STATE_BASE, state_end), zeroed by
# the boot wrapper's loop, so the flashed file only carries code+blobs
# (keeps the image under the DT2's own 3.28 MB section size even with
# the bulk-buffer reservations).
graft_actual = STATE_BASE - GRAFT_BASE      # emitted tail = code + blobs
G = (graft_actual + 15) & ~15   # 16-byte align (copyr copy length)
rprint(f'layout: copyr {copyr_len} B, wrapper {wrapper_len} B, '
       f'code ends {STATE_BASE:#x}, G={G:#x}, state {STATE_BASE:#x}'
       f'..{state_end:#x} (RAM-only, {state_end - STATE_BASE:#x} B), '
       f'pads {state_pad} B')

# ------------------------------------------------------- 5. address map ---
def map_addr(t):
    for entry in grafted:
        if entry <= t < grafted[entry]:
            return fn_new[entry] + (t - entry)
    for name, s, e, _ in blob_layout:
        if s <= t < e:
            return blob_new[name][2] + (t - s)
    if t in ram_map:
        return ram_map[t]
    if t in shared:
        return shared[t]
    return None


# --------------------------------------------------------- 6. relocation ---
pieces = {}
for entry in grafted:
    pieces[entry] = bytearray(
        dt2[entry - BASE:grafted[entry] - BASE])

rewritten = set()
nop_sites = 0
branch_re = re.compile(r'^(bra|bsr|[a-z]+)\.(b|w|l)\b', re.I)
for entry in grafted:
    buf = pieces[entry]
    for frm, to, ty, desc in refs:
        if not (entry <= frm < grafted[entry]):
            continue
        off = frm - entry
        if to in PUBLISH and ('CALL' in ty or 'JUMP' in ty):
            if buf[off:off + 2] == b'\x4e\xb9' and off + 6 <= len(buf):
                buf[off:off + 6] = b'\x4e\x71' * 3
                nop_sites += 1
                rewritten.add((entry, off))
                continue
        new_to = map_addr(to)
        if new_to is None:
            # v16 audit: an absolute reference into image space that the
            # DT2 and DN2 do NOT share byte-for-byte is a latent wild
            # branch/data fetch (e.g. pea'd callbacks, DT2-only strings).
            # If the bytes differ, fail LOUD instead of passing silently.
            if 0x40000400 <= to < 0x4030C000:
                d2 = dt2[to - BASE:to - BASE + 16]
                d1 = dn2[to - 0x40000400:to - 0x40000400 + 16]
                if d2 != d1:
                    fail.append(f'UNMAPPED abs ref {frm:#x}->{to:#x} '
                                f'({ty}) into differing image bytes')
                    rprint(f'  !! UNMAPPED abs {frm:#x} -> {to:#x} ({ty}) '
                           f'dt2={d2[:8].hex()} dn2={d1[:8].hex()}')
            continue
        m = branch_re.match(desc)
        if m and m.group(2) in ('b', 'w') and ('JUMP' in ty or 'CALL' in ty):
            if entry <= to < grafted[entry]:
                continue  # intra-function: rigid copy preserves it
            width = 2 if m.group(2) == 'b' else 4
            new_disp = new_to - (fn_new[entry] + off + width)
            if width == 2:
                # bra/bcc .b: one word, displacement byte at off+1
                if not -128 <= new_disp <= 127:
                    fail.append(f'bra.b overflow {frm:#x}->{to:#x}')
                    continue
                buf[off + 1:off + 2] = struct.pack('>b', new_disp)
            else:
                # bra/bcc .w: opcode word + 16-bit displacement at off+2
                if not -32768 <= new_disp <= 32767:
                    fail.append(f'bra.w overflow {frm:#x}->{to:#x}')
                    continue
                buf[off + 2:off + 4] = struct.pack('>h', new_disp)
            rewritten.add((entry, off))
            continue
        enc = be(to)
        ilen = insts.get(frm, 8)
        p = bytes(buf[off:off + ilen]).find(enc)
        if p >= 0 and p % 2 == 0:
            buf[off + p:off + p + 4] = be(new_to)
            rewritten.add((entry, off + p))

for entry in grafted:
    if len(pieces[entry]) != grafted[entry] - entry:
        fail.append(f'buffer length drift in fn {entry:#x}: '
                    f'{len(pieces[entry])} != {grafted[entry] - entry}')
rprint(f'relocation: {len(rewritten)} sites rewritten, '
       f'{nop_sites} publish calls NOPd')

# ------------------------- 6b. PC-relative branch pass (v8.1) --------------
# v8 hardware postmortem: the ref-driven relocation silently skipped
# cross-function PC-relative calls whose Ghidra description carries no size
# suffix -- the #FORMAT_FS trampoline FUN_4015A424's "jsr 0x4015a164"
# (JSR (d16,PC) = 4E BA xxxx) kept its DT2 displacement FD3A, pointed 12 B
# short of the grafted body, and the first v8 boot died V04 (illegal
# instruction) at 0x466C1E0C -- BEFORE any flash write. Decode PC-relative
# control flow straight from the opcode bytes (instruction boundaries from
# the closure log INST lines) so no ref-classification quirk can hide a
# site: bra/bsr/bcc .b (0x6xxx, ilen 2) and .w (0x6xxx, low byte 0, ilen 4),
# jsr/jmp (d8,PC) (4E80/4EF8) and (d16,PC) (4EBA/4EFA). The .l form
# (low byte 0xFF, ilen 6) is ABSOLUTE long -- already handled by the pass
# above. Displacements are relative to the extension word (addr+2) in both
# the original and the copy, so the mapping is exact.
pcrel_sites = 0
pcrel_cross = []
for entry in sorted(grafted):
    body = dt2[entry - BASE:grafted[entry] - BASE]
    for addr in sorted(a for a in insts if entry <= a < grafted[entry]):
        ilen = insts[addr]
        off = addr - entry
        if off + 2 > len(body):
            continue
        w = struct.unpack('>H', body[off:off + 2])[0]
        d_off = d_size = None
        if (w & 0xF000) == 0x6000:                     # bra/bsr/bcc family
            if ilen == 2:
                d_off, d_size = off + 1, 1             # .b: byte at off+1
            elif ilen == 4 and (w & 0x00FF) == 0:
                d_off, d_size = off + 2, 2             # .w: word at off+2
        elif w in (0x4EBA, 0x4EFA) and ilen == 4:       # jsr/jmp (d16,PC)
            d_off, d_size = off + 2, 2
        elif w in (0x4E80, 0x4EF8) and ilen == 2:       # jsr/jmp (d8,PC)
            d_off, d_size = off + 1, 1
        if d_off is None:
            continue
        if d_size == 1:
            disp = struct.unpack('>b', body[d_off:d_off + 1])[0]
        else:
            disp = struct.unpack('>h', body[d_off:d_off + 2])[0]
        target = addr + 2 + disp
        if entry <= target < grafted[entry]:
            continue  # intra-function: rigid copy preserves it
        new_to = map_addr(target)
        if new_to is None:
            fail.append(f'pcrel {w:#06x} at {addr:#x} -> {target:#x}: '
                        f'no graft home (unresolved branch)')
            continue
        new_disp = new_to - (fn_new[entry] + off + 2)
        if d_size == 1 and not -128 <= new_disp <= 127:
            fail.append(f'pcrel.b overflow {addr:#x} -> {target:#x}')
            continue
        if d_size == 2 and not -32768 <= new_disp <= 32767:
            fail.append(f'pcrel.w overflow {addr:#x} -> {target:#x}')
            continue
        buf = pieces[entry]
        if d_size == 1:
            buf[d_off:d_off + 1] = struct.pack('>b', new_disp)
        else:
            buf[d_off:d_off + 2] = struct.pack('>h', new_disp)
        pcrel_sites += 1
        pcrel_cross.append((addr, w, target, new_to))
        rewritten.add((entry, d_off))
for addr, w, target, new_to in pcrel_cross:
    rprint(f'  pcrel {w:#06x} at {addr:#x} -> {target:#x} '
           f'==> {new_to:#x}')
rprint(f'pcrel pass: {pcrel_sites} cross-function branches retargeted')

# ---------------- 6b2. general (d16,PC) operand pass (v16) -----------------
# Emulator postmortem: FUN_40155ed6+0x6c used `lea (d16,PC),A3; jsr (A3)`.
# The lea's displacement was never retargeted, so the graft landed 0x22 B
# into FUN_40155c16 -- skipping its `lea <vfs-op>,A0` prologue -- and the
# jsr (A0) went through stale A0 = &VFS-list-head (state DATA). The same
# hole affects ANY instruction using (d16,PC) addressing: lea xxFA,
# pea 487A, move xx3A literal-pool loads, cmpi, etc. Catch them all by
# decoding the mode field: low 6 bits == 0b111010, ilen 4 (opcode+disp16).
# pcrel base = extension word (addr+2), identical in old and new layouts,
# so rewriting the 16-bit displacement preserves the target exactly with
# NO length change.
pcrel_lea_sites = 0
pcrel_fb = []
for entry in sorted(grafted):
    body = dt2[entry - BASE:grafted[entry] - BASE]
    for addr in sorted(a for a in insts if entry <= a < grafted[entry]):
        ilen = insts[addr]
        off = addr - entry
        if off + 4 > len(body):
            continue
        w = struct.unpack('>H', body[off:off + 2])[0]
        if (w & 0x3F) == 0x3B:                      # (d8,Xn/PC,Xn) full ext
            pcrel_fb.append((addr, w))
            continue
        if (w & 0x3F) != 0x3A or ilen != 4:
            continue
        disp = struct.unpack('>h', body[off + 2:off + 4])[0]
        target = addr + 2 + disp
        if entry <= target < grafted[entry]:
            continue        # intra-function pool/branch: rigid copy keeps it
        new_to = map_addr(target)
        if new_to is None:
            fail.append(f'pcrel-op {w:#06x} at {addr:#x} -> {target:#x}: '
                        f'no graft home')
            continue
        new_disp = new_to - (fn_new[entry] + off + 2)
        if not -32768 <= new_disp <= 32767:
            fail.append(f'pcrel-op overflow {addr:#x} -> {target:#x}')
            continue
        buf = pieces[entry]
        buf[off + 2:off + 4] = struct.pack('>h', new_disp)
        pcrel_lea_sites += 1
        rewritten.add((entry, off + 2))
        rprint(f'  pcrel-op {w:#06x} at {addr:#x} -> {target:#x} '
               f'==> {new_to:#x}')
rprint(f'pcrel-op pass: {pcrel_lea_sites} (d16,PC) sites retargeted, '
       f'{len(pcrel_fb)} full-format (0xFB) sites (offset tables: '
       'self-relocating under rigid copy)')

# ---------------- 6b3. derived journal source pointers (v62) -------------
# G1 and its release sibling compute source = (LBA << 9) + bias rather
# than embedding the journal address itself. Ghidra describes the derived
# MOVE-to-stack target, whose bytes contain no address to rewrite. Relocate
# the ADDI bias explicitly, keeping the sector arithmetic and copy lengths.
JOURNAL = 0x46F39CA0
JOURNAL_LBA = 0x005D80C0
JOURNAL_END_LBA = 0x005D8180
old_bias = (JOURNAL - (JOURNAL_LBA << 9)) & 0xFFFFFFFF
new_bias = (ram_map[JOURNAL] - (JOURNAL_LBA << 9)) & 0xFFFFFFFF
for entry, off in ((0x40155698, 0xD4), (0x401557AE, 0x8E)):
    buf = pieces[entry]
    expected = b'\x06\x80' + be(old_bias)  # addi.l #bias,D0
    if buf[off:off + 6] != expected:
        fail.append(f'v62 journal source bias mismatch at {entry:#x}+{off:#x}')
        continue
    buf[off + 2:off + 6] = be(new_bias)
    rewritten.add((entry, off + 2))
    rprint(f'v62 journal bias {entry:#x}+{off:#x}: '
           f'{old_bias:#x} -> {new_bias:#x}')
for old_pointer in (0x46F41CA0, 0x46F4DCB0):
    if ram_map[old_pointer] != ram_map[JOURNAL] + old_pointer - JOURNAL:
        fail.append(f'v62 journal interior target {old_pointer:#x} lost its offset')
if cluster_spans:
    for old_scratch in (0x405BD770, 0x405C5770, 0x405CD770):
        reservation = next((sp - (old_scratch - cs) for sp, ts, cs
                            in cluster_spans if old_scratch in ts), 0)
        if reservation < 0x8000:
            fail.append(f'v62 staging scratch {old_scratch:#x} has only {reservation:#x} bytes')

# Candidate: two native factory context expressions fold the object-ID bias
# into a literal rather than carrying a directly relocatable RAM address.
# Exact sites and opcodes are pinned by native-bulk-inventory.json.
for entry, off, opcode, target in (
        (0x4015AE12, 0xAC, b'\xD1\xFC', 0x47D73EDC),
        (0x4015B58C, 0x4C, b'\x06\x85', 0x47D73ED0)):
    buf = pieces[entry]
    old_factory_bias = (target - (0x01000000 * 0x80)) & 0xFFFFFFFF
    new_factory_bias = (ram_map[target] - (0x01000000 * 0x80)) & 0xFFFFFFFF
    if buf[off:off + 6] != opcode + be(old_factory_bias):
        fail.append(f'candidate factory bias mismatch at {entry:#x}+{off:#x}')
        continue
    buf[off + 2:off + 6] = be(new_factory_bias)
    rewritten.add((entry, off + 2))
    rprint(f'candidate factory bias {entry:#x}+{off:#x}: '
           f'{old_factory_bias:#x} -> {new_factory_bias:#x}')

# ---------------- 6c2. bulk-length clamp (v19) ----------------------------
# Hardware postmortem (v14 skew / v17 V0B / v18 V04, one root cause):
# grafted FUN_4015bfd4 (the big-buffer zeroer, called by the ekFS
# initializer) memsets DT2-sized extents -- 0x40000 and 0xE10000 (~15 MB!)
# -- from state-cluster bases that the cluster packing placed only 0x500
# apart. On hardware that smashes ~14.6 MB of live upper SDRAM (the
# allocator's regions), whose corrupted free lists then hand out wild
# pointers; writes through them scribble the graft at varying offsets.
# The emulator missed it: its stub malloc never walks real free lists
# and its upper SDRAM is empty. Clamp: any grafted `move.l #len,-(SP)`
# (2F3C) whose next instruction pea's/lea's a STATE-CLUSTER address
# gets len capped at that cluster's reserved span.
cluster_span = {}
for sp, ts, cs in cluster_spans:
    for t in ts:
        cluster_span[t] = (cs, sp)
clamped = 0
for entry in sorted(grafted):
    body = dt2[entry - BASE:grafted[entry] - BASE]
    inst_list = sorted(a for a in insts if entry <= a < grafted[entry])
    for ia in inst_list:
        off = ia - entry
        if off + 6 > len(body):
            continue
        if body[off:off + 2] != b'\x2f\x3c':
            continue
        ln = struct.unpack('>I', body[off + 2:off + 6])[0]
        j = inst_list.index(ia)
        if j + 1 >= len(inst_list):
            continue
        na = inst_list[j + 1]
        noff = na - entry
        tgt = None
        if body[noff:noff + 2] == b'\x48\x79':          # pea (abs).l
            tgt = struct.unpack('>I', body[noff + 2:noff + 6])[0]
        elif body[noff:noff + 2] in (b'\x41\xf9', b'\x45\xf9',
                                     b'\x47\xf9', b'\x49\xf9'):
            tgt = struct.unpack('>I', body[noff + 2:noff + 6])[0]
        if tgt is None or tgt not in cluster_span:
            continue
        cs, sp = cluster_span[tgt]
        if ln > sp:
            new_ln = sp
            buf = pieces[entry]
            buf[off + 2:off + 6] = be(new_ln)
            clamped += 1
            rewritten.add((entry, off + 2))
            rprint(f'  bulk-clamp fn {entry:#x}+{off:#x}: len {ln:#x} -> '
                   f'{new_ln:#x} (cluster {cs:#x} span)')
if clamped:
    rprint(f'bulk-clamp pass: {clamped} oversized state-cluster writes '
           'clamped to their cluster spans')
else:
    # Candidate fully reserves the two native factory clears. Prove the
    # formerly clamped operations now retain donor lengths inside the state.
    body = pieces[0x4015BFD4]
    for offset, target, length in ((2, 0x47D73ED0, 0x40000),
                                   (0x16, 0x46F63ED0, 0xE10000)):
        if body[offset:offset + 12] != b'\x2f\x3c' + be(length) + b'\x48\x79' + be(ram_map[target]):
            fail.append(f'candidate native clear bytes mismatch at 4015bfd4+{offset:#x}')
        cs, span = cluster_span[target]
        if target - cs + length > span:
            fail.append(f'candidate native clear exceeds reservation at {target:#x}')
    rprint('candidate: factory clears retain native 0x40000/0xE10000 lengths; reservations verified')
for a, w in pcrel_fb:
    # (d8,PC,Xn) brief-format switch: `move.w (PC,tbl,Dn)` loads a word
    # offset from the table that follows the `jmp (PC,Dn)` site, and the
    # jmp adds it to its own PC. Both the table and the targets live in
    # the same rigidly-copied function, so the mechanism self-relocates.
    # Verify by decoding the offset words after the jmp: every target
    # must stay inside the grafted function.
    ef = next((e for e in grafted if e <= a < grafted[e]), None)
    if ef is None:
        fail.append(f'pcrel full-format (0xFB) site at {a:#x} outside '
                    'any grafted function')
        continue
    if w == 0x4EFB:                      # the jmp: table follows at a+4
        tbl = a + 4
        words = []
        while tbl + 2 * len(words) + 2 <= grafted[ef]:
            v = struct.unpack(
                '>H', dt2[tbl + 2 * len(words) - BASE:
                          tbl + 2 * len(words) - BASE + 2])[0]
            if not 2 <= v <= 0x1000:      # implausible as a table word
                break
            tgt = a + 2 + v
            if not ef <= tgt < grafted[ef]:
                fail.append(f'switch table at {a:#x}: offset {v:#x} '
                             f'-> {tgt:#x} escapes {fns[ef][1]}')
                break
            words.append(v)
        rprint(f'  pcrel full-format jmp at {a:#x} in {fns[ef][1]}: '
               f'{len(words)} targets in-function '
               f'(max +{max(words):#x}) OK')
    else:
        rprint(f'  pcrel full-format site {w:#06x} at {a:#x} in '
               f'{fns[ef][1]}: shares the jmp switch table (OK)')

# ------------------- 6c. v8_3: skip the format's bulk erase ----------------
# v8_1 hardware: logo hang, no exception (a BLOCKED task, not a crash).
# v8_2 clamped the erase to 1 MiB -- STILL HUNG. Decompiled driver facts:
# the erase primitive (FUN_4012c4b2) sends controller cmds 0x23/0x24/0x26
# and then waits on the erase-done event 0x4461b6c0 -- which is posted by a
# SEPARATE callback (FUN_4012b968, registered via the init's indirect
# dispatcher at 0x4012bc28) -- NOT by the main IRQ handler that posts
# cmd-done/DMA-done/data-done. The read primitive (proven working on
# hardware in v7) waits on the SAME three events the write does
# (0x4461b6d8/0x4461b6c8/0x4461b6d0), so the write path is mechanically
# sound at this boot stage; the erase path is the only one relying on the
# second notification chain, and it has NO capacity validation (read/write
# check DAT_4461b6b0, the capacity read live from the eMMC EXT_CSD).
# v8_3: replace the format's `jsr erase` (6 B at FUN_4015a164+0x50) with
# `moveq #0,D0; nop; nop` -- the format sees "erase returned 0" and
# proceeds straight to the superblock/journal writes (proven-mechanism
# ops). eMMC writes go through the controller's FTL (no erase-before-write
# at the logical level); the format writes the superblock + journal wipes
# fresh; free blocks are written before they are ever read. The erase args
# (count, start) stay pushed on the stack -- the format's own cleanup
# accounts for them, so balance is preserved.
_esite = 0x4015a164 + 0x50      # jsr <erase> in FUN_4015a164
_eoff = _esite - 0x4015a164
_ebuf = pieces[0x4015a164]
if bytes(_ebuf[_eoff:_eoff + 6]) != b'\x4e\xb9' + be(0x4012C4B2):
    fail.append('v8_3 erase-jsr site mismatch in FUN_4015a164 '
                f'(got {bytes(_ebuf[_eoff:_eoff + 6]).hex()})')
else:
    _ebuf[_eoff:_eoff + 6] = b'\x70\x00\x4e\x71\x4e\x71'
    rprint('v8_3: format bulk erase SKIPPED (moveq #0,D0; nop; nop) -- '
           'format proceeds directly to the writes')

# ------------------- 6c2. v59: correct zero-divisor guard in udiv#2 ---
# v57's extra JSR shifted the helper's arguments and triggered its deliberate
# divide-by-zero branch. v58 restored the argument layout, but its guard
# encoded MOVEQ #1,D2 (74 01), leaving the divisor D5 unchanged. Use 7A 01
# for MOVEQ #1,D5. The correct caller supplies divisor 0xAAA, so the guard
# is separate from the unresolved silent stall; it does not prove success.
_UDIV_SITE = 0xE6                       # offset in FUN_40183E94
_udbuf = pieces[0x40183E94]
if bytes(_udbuf[_UDIV_SITE:_UDIV_SITE + 2]) != b'\x42\x85':
    fail.append(f'v59 udiv#2 zero-divisor site mismatch: '
                f'got {bytes(_udbuf[_UDIV_SITE:_UDIV_SITE + 2]).hex()}')
else:
    _udbuf[_UDIV_SITE:_UDIV_SITE + 2] = b'\x7a\x01'
    rprint('v59: udiv#2 zero-divisor guard targets D5 (7A 01 at +0xE6)')

# ------------------- 6d. v11: neutralize ALL erase calls -------------------
# v10 hardware: logo hang AGAIN, no exception -- the wrapper tail never ran,
# so the format BLOCKED. Postmortem scan of the shipped v10 graft found TWO
# more live `jsr <DN2 erase 0x4012C4B2>` sites: graft+0x60C (FUN_401557ae
# +0xce) and graft+0x692 (FUN_4015588e +0x74) -- the ekFS journal-area
# wipes (DT2 callers of the erase primitive inside the closure: 0x4015587c,
# 0x40155902, plus the bulk 0x4015a1b4 that 6c already skips). Every flash
# version has hung on its FIRST real erase call on this off-list eMMC
# (controller never completes cmd 0x23/0x24/0x26 -> erase-done event never
# posts -> task sleeps forever). The erase is never needed: eMMC writes go
# through the FTL (no logical erase-before-write; OS staging + MRAM mirrors
# prove writes on this exact chip), and the whole ekFS window is verified
# ALL-ZERO (v9 survey). Replace EVERY remaining retargeted erase call in
# grafted code with `moveq #0,D0; nop; nop` (= erase returned success).
ERASE_DN2 = 0x4012C4B2
_call = b'\x4e\xb9' + be(ERASE_DN2)
_skip6 = b'\x70\x00\x4e\x71\x4e\x71'
_neutralized = 0
for entry in list(grafted):
    buf = pieces[entry]
    off = 0
    while True:
        off = bytes(buf).find(_call, off)
        if off < 0:
            break
        buf[off:off + 6] = _skip6
        _neutralized += 1
        rprint(f'  v11: erase call in {fns[entry][1]} @{entry:#x}'
               f'+{off:#x} -> skipped')
        off += 6
rprint(f'v11: {_neutralized} remaining erase calls neutralized')
if bytes(pieces[0x4015a164]).find(_call) >= 0:
    fail.append('v11: erase call still present in the format body')
# belt-and-braces: none anywhere in any grafted piece
for entry in grafted:
    if bytes(pieces[entry]).find(_call) >= 0:
        fail.append(f'v11: erase call still present in {fns[entry][1]}')

# audit: re-encode every cross-function pcrel site in the final buffers and
# confirm it still lands on the mapped target (guards against a later pass
# overwriting displacement bytes)
for entry in sorted(grafted):
    buf = pieces[entry]
    for addr, w, target, new_to in pcrel_cross:
        if not (entry <= addr < grafted[entry]):
            continue
        off = addr - entry
        if (w & 0xF000) == 0x6000 or w in (0x4E80, 0x4EF8):
            d_off, d_size = ((off + 1, 1) if insts[addr] == 2
                            else (off + 2, 2))
        else:
            d_off, d_size = off + 2, 2
        if d_size == 1:
            got = struct.unpack('>b', buf[d_off:d_off + 1])[0]
        else:
            got = struct.unpack('>h', buf[d_off:d_off + 2])[0]
        if fn_new[entry] + off + 2 + got != new_to:
            fail.append(f'pcrel audit {addr:#x}: encoded target '
                        f'{fn_new[entry] + off + 2 + got:#x} != {new_to:#x}')

blob_bytes = []
for name, s, e, raw in blob_layout:
    b = bytearray(raw)
    hits = 0
    for i in range(0, len(b) - 3, 4):
        v = struct.unpack('>I', b[i:i + 4])[0]
        nv = map_addr(v)
        if nv is not None and nv != v:
            b[i:i + 4] = be(nv)
            hits += 1
    blob_bytes.append((name, s, e, bytes(b)))
    rprint(f'  blob {name}: {hits} pointers rewritten')

# --------------------------------------------------- 7. byte-scan check ---
# per-instruction: every genuine absolute operand sits at an even offset >= 2
# inside its own instruction; anything else is a cross-instruction phantom
suspects = 0
scratch = 0
for entry in grafted:
    buf = pieces[entry]
    for addr, ilen in insts.items():
        if not (entry <= addr < grafted[entry]):
            continue
        off = addr - entry
        for p in range(2, ilen - 2, 2):
            if off + p + 4 > len(buf):
                break
            v = struct.unpack('>I', buf[off + p:off + p + 4])[0]
            if GRAFT_BASE <= v < GRAFT_BASE + G:
                pass  # inside the relocated graft: expected post-rewrite
            elif 0x40000400 <= v < 0x48000000:
                if (entry, off + p) not in rewritten:
                    if suspects < 12:
                        rprint(f'  SUSPECT unmapped {v:#x} at fn '
                               f'{entry:#x}+{off + p:#x}')
                    suspects += 1
            elif 0x48000000 <= v < 0x80000000:
                if scratch < 6:
                    rprint(f'  NOTE scratch-window constant {v:#x} at fn '
                           f'{entry:#x}+{off + p:#x} (left as-is)')
                scratch += 1
if suspects:
    fail.append(f'{suspects} unmapped address-like dwords remain in graft '
                f'code')
if scratch:
    rprint(f'scratch-window constants: {scratch} (review NOTE lines)')

# -------------------------------------------------------- 8. assembly ---
wrapper = bytearray()
fmtcmd_stub_at = None
fmtcmd_str_at = None
if MOUNT_AT_BOOT and FMT_CMD:
    # v12 wrapper = v9's proven 56-B body: console flag, zero state,
    # helper2, premount, mount(0), rts. NO format tail -- the format runs
    # on demand from the console task (#FORMAT command).
    wrapper += b'\x70\x20'                               # moveq #0x20,D0
    wrapper += b'\x81\xb9' + be(0x40287520)              # or.l (flags),D0
    wrapper += b'\x23\xc0' + be(0x40287520)              # move.l D0,(flags)
    wrapper += b'\x20\x3c' + be((state_end - STATE_BASE) // 4)
    wrapper += b'\x20\x7c' + be(STATE_BASE)
    # v62: advance A0 after each clear. 4290 repeatedly cleared only the
    # first dword; 4298 matches the stock DN2 fast-SRAM clear at400004A4.
    wrapper += b'\x42\x98\x53\x80\x66\xfa'               # zero state
    wrapper += b'\x4e\xb9' + be(DN2_HOOK_TARGET)            # jsr helper2
    wrapper += b'\x4e\xb9' + be(map_addr(DT2_PREMOUNT))     # jsr premount
    wrapper += b'\x42\xa7'                                   # clr.l -(sp)
    wrapper += b'\x4e\xb9' + be(map_addr(DT2_MOUNT))        # jsr mount(0)
    wrapper += b'\x58\x8f'                                   # addq #4,sp
    wrapper += b'\x4e\x75'                                   # rts
    assert len(wrapper) == 56, len(wrapper)
    # "#FORMAT\0" string lives right after the wrapper in the graft; the
    # stock #REBOOT handler (16 B at its match site) is overwritten with:
    #   jsr format424; tst.l D0; beq.b +6 (fall through past the handler,
    #   into the next command's compare -> line discarded, console lives);
    #   move.l D0,-(SP); illegal (error -> V04 screen with the code); nop
    wrapper += b'#FORMAT\x00'
    fmtcmd_str_at = GRAFT_BASE + copyr_len + 56
    assert len(wrapper) == 56 + 8, len(wrapper)
    # v13: "#WRTEST\0" + a 68-B stub + a 512-B 16-aligned pattern follow.
    # The stub calls the STOCK DN2 write primitive (0x4012C780) directly,
    # twice, from the console task:
    #   1) 0x200 B from the 16-ALIGNED pattern -> LBA 0x5D80C0  (direct DMA)
    #   2) 0x200 B from pattern+4 (misaligned)  -> LBA 0x5D8400  (scratch path)
    # D0 = first error code (0 = both OK). Slot handler self-reports: error
    # -> V04 screen with the code; block -> console dies but the two-sector
    # #MMCDUMP after power-cycle discriminates the exact failure point.
    wrapper += b'#WRTEST\x00'
    wrtest_str_at = GRAFT_BASE + copyr_len + 56 + 8
    # layout: wrapper starts at graft+copyr_len(92); 56 body; 8 #FORMAT;
    # 8 #WRTEST (ends +164); stub 68 (ends +232); pad 8 -> pattern at +240
    pat_at = GRAFT_BASE + copyr_len + 56 + 8 + 8 + 68 + 8
    assert pat_at % 16 == 0, pat_at
    wrtest_stub_at = GRAFT_BASE + copyr_len + 56 + 8 + 8
    W = 0x4012C780
    stub = (b'\x48\x79' + be(pat_at)             # pea (pattern)      [6]
            + b'\x2f\x3c\x00\x00\x02\x00'        # move.l #0x200,-(SP)
            + b'\x2f\x3c\x00\x5d\x80\xc0'        # move.l #0x5D80C0,-(SP)
            + b'\x4e\xb9' + be(W)                # jsr write
            + b'\x4f\xef\x00\x0c'                # lea 0xc(SP),SP
            + b'\x4a\x80'                       # tst.l D0
            + b'\x66\x22'                       # bne.b -> rts
            + b'\x48\x79' + be(pat_at + 4)       # pea (pattern+4)
            + b'\x2f\x3c\x00\x00\x02\x00'        # move.l #0x200
            + b'\x2f\x3c\x00\x5d\x84\x00'        # move.l #0x5D8400
            + b'\x4e\xb9' + be(W)                # jsr write
            + b'\x4f\xef\x00\x0c'                # lea 0xc(SP),SP
            + b'\x4a\x80'                       # tst.l D0
            + b'\x66\x02'                       # bne.b -> moveq
            + b'\x70\x00'                       # moveq #0,D0
            + b'\x4e\x75')                      # rts
    assert len(stub) == 68, len(stub)
    wrapper += stub
    wrapper += b'\x00' * ((pat_at - GRAFT_BASE)
                          - (copyr_len + 56 + 8 + 8 + 68))
    wrapper += b'0123456789ABCDEF' * 32          # 512-B pattern @ pat_at
    # v14 trace: markers (6 x 8 B) + thunks (6 x 26 B). Each thunk:
    #   pea <marker>; jsr 0x400054b4 (print); jsr 0x400cd1f6 (newline);
    #   addq #4,SP; jmp <original target>   (tail-jump; the target's rts
    #   returns straight to the format body -- the stack stays balanced).
    # Print idiom byte-mirrors the stock #HELLO handler. The six jsr sites
    # in the grafted format body get their operands repointed to the
    # thunks; the ORIGINAL post-relocation targets (graft homes / stock
    # retargets) ride in the thunks' tail-jmps.
    TR_MARKS = [b'F2:VFS\x00\x00', b'F3:WIPE\x00', b'F4:ROOT\x00',
                b'F5:SB\x00\x00\x00', b'F6:RLS\x00\x00']
    # +0x248 (label registrar) is NOT traced: it is publish-excluded and
    # already NOP'd by the builder (PUBLISH set) -- never a live call.
    TR_SITES = [0xd2, 0xd8, 0x1cc, 0x1ec, 0x254]
    # v15: SP-parity instrument. Each thunk prints "MARK SPVAL\n" via the
    # variadic console printf (0x400054b4 -- #STATUS uses %s/%08x formats):
    #   move.l SP,D0; move.l D0,-(SP)  (arg: SP at entry)
    #   pea <marker>                  (arg: %s)
    #   pea <"%s %08x\n">             (fmt, last push = first arg)
    #   jsr printf; lea 0xc(SP),SP    (caller-cleanup varargs)
    #   jmp <orig target>             (tail; D0-D1/A0-A1 dead across the
    #                                 original call per ABI -- verified)
    # G1 repoints the format body's `lea <geo-parent>,A2` (indirect call
    # at +0xe2); G2 repoints 4015804a's `lea <40157d28>,A5`. Together with
    # F2-F6 the SP values bracket any 2-byte skew to one function.
    TR_FMT = b'%s %08x\n\x00'          # 10 B -> 16-B slot
    marks_base = pat_at + 512
    fmt_at = marks_base + 56            # 7 x 8-B marker slots
    thunk_base = fmt_at + 16            # 16-B fmt slot
    body = pieces[0x4015A164]
    origs = []
    for i, (mark, site) in enumerate(zip(TR_MARKS, TR_SITES)):
        assert len(mark) == 8, mark
        assert bytes(body[site:site + 2]) == b'\x4e\xb9', \
            f'trace site {site:#x} not a jsr abs.l'
        origs.append(struct.unpack('>I', body[site + 2:site + 6])[0])

    # v20: integrity checksums. Every marker thunk now ALSO prints
    # "CK <code-sum> <state-sum>" -- running ADD checksums over
    # [GRAFT_BASE, STATE_BASE) (all graft code+wrapper) and
    # [STATE_BASE, state_end). The hardware crash is deterministic in the
    # G2/D28 window with wild jumps into a fixed graft window; these
    # checksums reveal WHICH phase corrupts WHAT -- code bytes, state
    # bytes, or neither (pure wild jump).
    marks_base = pat_at + 512
    fmt_at = marks_base + 64                # 8 x 8-B marker slots
    ck_fmt_at = fmt_at + 16
    fmt2_at = ck_fmt_at + 16
    thunk_base = fmt2_at + 16
    heal_at = thunk_base + 8 * 40
    crc_print_at = heal_at + 32
    pool_dump_at = crc_print_at + 82
    code_longs = (STATE_BASE - GRAFT_BASE) // 4
    state_longs = (state_end - STATE_BASE) // 4

    c1 = (b'\xd0\x90'                        # add.l (A0),D0 [opmode 010!
                                            # slip #7: 0xD1D0 = adda.l
                                            # (empirically emu-proven),
                                            # and (An)+ is invalid for ADD
                                            # on ColdFire]
          + b'\x41\xe8\x00\x04'              # lea 4(A0),A0
          + b'\x53\x82')                     # subq.l #1,D2
    crc_print = (b'\x2f\x02'                  # move.l D2,-(SP)   [save]
                 + b'\x42\x80'                # clr.l D0 (sum; caller-saved)
                 + b'\x41\xf9' + be(GRAFT_BASE)
                 + b'\x24\x3c' + be(code_longs)   # move.l #code_longs,D2
                                            # (0x243C = D2; 0x263C = D3!
                                            # capstone-caught slip #6)
                 + c1
                 + b'\x66' + struct.pack('>b', -(len(c1) + 2))   # bne loop
                 + b'\x2f\x00'                # push code-sum [save]
                 + b'\x42\x80'                # clr.l D0
                 + b'\x41\xf9' + be(STATE_BASE)
                 + b'\x24\x3c' + be(state_longs)  # move.l #state_longs,D2
                 + c1
                 + b'\x66' + struct.pack('>b', -(len(c1) + 2))
                 + b'\x2f\x00'                # push arg2 = state-sum
                 + b'\x2f\x2f\x00\x04'        # push arg1 = code-sum (4,SP)
                 + b'\x48\x79' + be(ck_fmt_at)
                 + b'\x4e\xb9' + be(0x400054B4)
                 + b'\x4f\xef\x00\x0c'        # pop fmt + 2 args
                 + b'\x4f\xef\x00\x04'        # discard code-sum save
                 + b'\x24\x1f'                # move.l (SP)+,D2 [restore]
                 + b'\x4e\x75')               # rts
    assert len(crc_print) == 82, len(crc_print)
    rprint(f'  v20 crc_print @{crc_print_at:#x}: code {code_longs:#x} '
           f'longs, state {state_longs:#x} longs')

    # v61: each fixed 40-byte slot pushes only constants, then enters a
    # shared logger. Its synthetic tail target is consumed before the real
    # callee sees the original argument/return frame. The G2 callee has a
    # live output-buffer pointer in A0, so printf/CRC must not destroy it.
    SP_LOG_AT = pool_dump_at + 174

    def sp_thunk(mark_addr, orig):
        t = (b'\x48\x79' + be(orig)
             + b'\x48\x79' + be(mark_addr)
             + b'\x4e\xf9' + be(SP_LOG_AT)
             + b'\x4e\x71' * 11)
        assert len(t) == 40
        return t

    all_marks = (list(TR_MARKS) + [b'G1:GEO\x00\x00', b'G2:D28\x00\x00',
                                   b'G3:DIV\x00\x00'])
    thunk_bytes = bytearray()
    # F2..F6 thunks (0..4), then G1 (5), G2 (6), G3 (7)
    for i, orig in enumerate(origs):
        thunk_bytes += sp_thunk(marks_base + 8 * i, orig)
        rprint(f'  v20 trace {TR_MARKS[i][:-1].decode()}: '
               f'site +{TR_SITES[i]:#x} -> thunk '
               f'{thunk_base + 40 * i:#x} (jmp {orig:#x})')
    wrapper += b''.join(all_marks)
    wrapper += TR_FMT + b'\x00' * (16 - len(TR_FMT))
    wrapper += b'CK %08x %08x\n\x00'[:13] + b'\x00' * 3
    wrapper += b'%x %x %x %x\n\x00' + b'\x00' * 3
    wrapper += thunk_bytes
    for i, site in enumerate(TR_SITES):          # repoint body jsr sites
        body[site + 2:site + 6] = be(thunk_base + 40 * i)

    # G1: repoint the format body's `lea <geo-parent>,A2` (body +0x66)
    g1_pat = b'\x45\xf9' + be(fn_new[0x40155698])
    g1_off = bytes(body).find(g1_pat)
    if g1_off < 0:
        fail.append('v15: G1 lea pattern not found in format body')
    else:
        body[g1_off + 2:g1_off + 6] = be(thunk_base + 40 * 5)
        rprint(f'  v20 G1:GEO lea@body+{g1_off:#x} -> thunk '
               f'{thunk_base + 40 * 5:#x} (jmp {fn_new[0x40155698]:#x})')
    # G2: repoint FUN_4015804a's `lea <40157d28>,A5`
    g2_pat = b'\x4b\xf9' + be(fn_new[0x40157d28])
    g2_body = pieces[0x4015804A]
    g2_off = bytes(g2_body).find(g2_pat)
    if g2_off < 0:
        fail.append('v15: G2 lea pattern not found in FUN_4015804a')
    else:
        g2_body[g2_off + 2:g2_off + 6] = be(thunk_base + 40 * 6)
        rprint(f'  v20 G2:D28 lea@4015804a+{g2_off:#x} -> thunk '
               f'{thunk_base + 40 * 6:#x} (jmp {fn_new[0x40157d28]:#x})')
    wrapper += sp_thunk(marks_base + 8 * 5, fn_new[0x40155698])
    wrapper += sp_thunk(marks_base + 8 * 6, fn_new[0x40157d28])
    # v20 G3: the divide call inside FUN_40157d28 (+0x4a, the 0xAAA-arg
    # jsr to the SHARED 0x40178F0C) -- the last marker before the crash
    # window. Prints SP + both checksums, then jumps to the real divide.
    g3_body = pieces[0x40157D28]
    g3_pat = b'\x4e\xb9' + be(0x40178F0C)
    g3_off = bytes(g3_body).find(g3_pat)
    if g3_off < 0:
        fail.append('v20: G3 divide jsr pattern not found in 40157d28')
    else:
        g3_body[g3_off + 2:g3_off + 6] = be(thunk_base + 40 * 7)
        rprint(f'  v20 G3:DIV jsr@40157d28+{g3_off:#x} -> thunk '
               f'{thunk_base + 40 * 7:#x} (jmp 40178f0c)')
    wrapper += sp_thunk(marks_base + 8 * 7, 0x40178F0C)
    # v23: heal -- re-copy the graft's code from the image tail right
    # before each phase marker. The v22 hardware dump proved a
    # boot-time stock subsystem (allocator pool records: {0x80000Exx,
    # 0x2B1, 0, 0}) writes OVER the graft's udiv/4015bfd4 bytes
    # between markers (the F2 CK already differed from pristine, and
    # every crash PC sits inside those two functions). Heal restores
    # the bytes from the image tail (IMAGE_STORE, flash = read-only)
    # immediately before each marker, so the format always executes
    # pristine code even if the scribbler hit between phases.
    # Only the CODE is healed -- the RAM-only state block must keep
    # the format's accumulated state.
    HEAL_LONGS = (STATE_BASE - GRAFT_BASE) // 4
    rprint(f'  v23 heal @{heal_at:#x}: {HEAL_LONGS} longs '
           f'({HEAL_LONGS * 4:#x} B of code; state block NOT touched)')
    heal = (b'\x41\xf9' + be(IMAGE_STORE)   # lea (IMAGE_STORE).l,A0
            + b'\x43\xf9' + be(GRAFT_BASE)   # lea (GRAFT_BASE).l,A1
            + b'\x22\x3c' + be(HEAL_LONGS)   # move.l #HEAL_LONGS,D1
            + b'\x22\xd8'                     # move.l (A0)+,(A1)+
            + b'\x53\x81'                     # subq.l #1,D1
            + b'\x66\xfa'                     # bne.b loop
            + b'\x4e\xb9' + be(crc_print_at)  # jsr crc_print (post-heal CK)
            + b'\x4e\x75')                    # rts = 32 B
    assert len(heal) == 32, len(heal)
    # v17: pool_dump -- the allocator-pool table probe. The v16 hardware
    # V0B at the udiv home = graft bytes replaced at RUNTIME; prime
    # suspect = a stock heap pool reaching 0x466C0000+ (the emulator's
    # stub malloc never touches the graft, which is why emulation stayed
    # clean). Prints the 21 pool entries (16 B each) at 0x4464ABF0 (the
    # array pointed to by the static heap config 0x4029eba0) as
    # "%x %x %x %x" lines, then TAIL-JUMPS to format424 so the #FORMAT
    # handler needs no logic change (its jsr just points here instead).
    # All encodings verified against stock idioms + unicorn round-trip.
    # v18: extended dump. The v17 hardware run showed 0x4464ABF0 = the
    # 21 size-class BIN-HEAD table (live free-list pointers into SDRAM1
    # 0x80000Cxx, counts 0x724/0x725) -- NOT the pool table. The config's
    # third pointer (0x4029eba8 -> 0x4664ABF0) is the never-referenced
    # second array: prime candidate for the actual POOL DESCRIPTORS.
    # v18 prints: the live config dwords (1 line), the 0x4664ABF0 array
    # (21 lines), and the bins again (21 lines) for run-to-run diffing.
    # Same proven skeleton: callee-saved D2 counter, subroutine dump4.
    # (fmt2_at / pool_dump_at already set by the v20 layout block)
    pd_loop = (b'\x2f\x28\x00\x0c'           # move.l (0xC,A0),-(SP)
               + b'\x2f\x28\x00\x08'         # move.l (0x8,A0),-(SP)
               + b'\x2f\x28\x00\x04'         # move.l (0x4,A0),-(SP)
               + b'\x2f\x10'                 # move.l (A0),-(SP)
               + b'\x48\x79' + be(fmt2_at)   # pea "%x %x %x %x\n"
               + b'\x4e\xb9' + be(0x400054B4)   # jsr printf
               + b'\x4f\xef\x00\x14'         # lea 0x14(SP),SP (pop 5 args)
               + b'\x41\xe8\x00\x10'         # lea 0x10(A0),A0
               + b'\x53\x82')                # subq.l #1,D2
    dump4 = (pd_loop
             + b'\x66' + struct.pack('>b', -(len(pd_loop) + 2))  # bne dump4
             + b'\x4e\x75')                   # rts
    assert len(dump4) == 40, len(dump4)
    # v27: DAMAGE MAP.
    #
    # Two writers have been blamed for the graft damage -- the stock boot
    # scribbler and the ekFS allocator -- and every relocation since v14
    # has been chosen by extrapolating from single probes (0x466c1cbc)
    # plus two lucky 16-byte survivors. Stop guessing: sample the band.
    #
    # 32 B every 16 KB from the graft base across the whole code region
    # and on through the state block, plus the four addresses we already
    # have hard evidence about. pool_dump runs BEFORE it tail-jumps to
    # format424, so this isolates BOOT-time damage from anything the
    # format run itself allocates -- the two were never separable before.
    #
    # ekFS clusters live at 0x466f15fc / 0x466f16dc (state block), well
    # ABOVE the code that ends at 0x466d6cdc, so ekFS cluster allocation
    # cannot reach the graft by growing down. The 0x80000Exx records that
    # appear over udiv/bfd4 are therefore NOT ekFS clusters, which is why
    # this map has to be read before assuming a culprit.
    # v30: DENSE probe of the churn window.
    #
    # Two addresses are known-damaged and both sit inside 0x466c3000-0x466c3600:
    # 0x466c343c (v28) and 0x466c31e8 (v29). v28's 16 KB grid stepped over
    # that window entirely -- it probed 0x466c0000 and 0x466c4000, both
    # clean -- which is why the map looked 95% healthy and the damage kept
    # moving. Sample the suspect span at 0x100 instead, plus a handful of
    # whole-graft anchors to prove the rest of the band is still clean.
    #
    # The after-map is the point: it shows this window GROWING across the
    # format run, which is the eMMC write primitive's ~32 KB alloc/free
    # churn sharing one region with the 93 KB graft (v24's own note: "Our
    # code and the heap are fighting over one region"). No address is safe
    # by construction until that window's extent is measured.
    # v38: WRITE-PATH STATE MAP. The v37 checker named the failing write
    # -- and then #WRTEST (v13's PROVEN-GOOD 512-B write to LBA 0x5D80C0,
    # returned 0 on this very unit) failed with the SAME -10, at boot, on
    # a fresh power-cycle. The write path's boot state changed between
    # v13 and v37; every format phase since v24 advanced over unchecked
    # write failures, and the driver-task -2 crash (v36's V0B PC=FFFFFFFE)
    # is downstream of the same root.
    #
    # The write primitive's decision inputs are all plain RAM:
    #   0x4461b6b0  live capacity (EXT_CSD), the cmp in the validity check
    #   0x4461b6b8  status word the error ladder reads
    #   0x4461b6bc/b6c8/b6d0/b6d8  the event objects (waits the write does)
    #   0x405C5900/0x405C594C  the driver work-queue struct from the v36
    #                          crash stack (405C59xx)
    # The map runs pre-#FORMAT, so it photographs the write path's boot
    # state directly. Probe count held at exactly 28; layout byte-identical
    # to v37 (memcmp fix + write checker stay).
    MEMCMP = 0x4017E8A8
    WRITEPATH = [0x4461B6B0, 0x4461B6B8, 0x4461B6BC, 0x4461B6C8,
                 0x4461B6D0, 0x4461B6D8, 0x405C5900, 0x405C594C]
    HEAPV36 = [0x44670598, 0x44670630]        # from the v36 crash stack
    STATEPOP = [0x466D8000, 0x466DC000]      # boot-populated state block
    DENSE = [0x466C3000, 0x466C3C00]          # window canary
    ANCHOR = [0x466C0000, 0x466C4000, 0x466C8000, 0x466D0000]
    KEY = [fn_new[0x40189FF4],   # memcmp-GRAFT (fix verification)
           fn_new[0x40183E94],   # udiv
           fn_new[0x4015BFD4],   # bfd4
           fn_new[0x4015B4F0]]   # the write caller
    DRV = [0x4012C780, 0x4012C4B2, 0x4012C4EE, 0x40133EBC]
    pd_calls = [(0x4029EBA0, 1, 'config'),
                (0x4667AD00, 2, 'wrmutex')]
    pd_calls += [(a, 2, f'wp@{a:#x}') for a in WRITEPATH]
    pd_calls += [(a, 2, f'heap@{a:#x}') for a in HEAPV36]
    pd_calls += [(a, 2, f'sp@{a:#x}') for a in STATEPOP]
    pd_calls += [(a, 2, f'dense@{a:#x}') for a in DENSE]
    pd_calls += [(a, 2, f'anchor@{a:#x}') for a in ANCHOR]
    pd_calls += [(a, 2, f'key@{a:#x}') for a in KEY]
    pd_calls += [(a, 2, f'drv@{a:#x}') for a in DRV]
    assert len(pd_calls) == 28, f'v38: probe count must stay 28, got {len(pd_calls)}'
    # v61: preserve the record-read checkpoint and reuse nearby diagnostic
    # space for the earlier context lookup and shared preserving logger.
    # Keep the total pool size and relocated function homes unchanged.
    G5D_AT = pool_dump_at

    def g4_value_line(val_bytes, str_addr):
        # <push value>, pea marker, pea "%s %08x\n", printf, pop 12
        return (val_bytes
                + b'\x48\x79' + be(str_addr)          # pea <marker>
                + b'\x48\x79' + be(fmt_at)            # pea "%s %08x\n"
                + b'\x4e\xb9' + be(0x400054B4)        # jsr printf
                + b'\x4f\xef\x00\x0c')                # lea $c(SP),SP

    # v60: reuse the old G4/dead-H8 slots for lookup and read checkpoints.
    # Save volatile registers, then tail-JMP with the caller's frame intact.
    def build_record_probe(at, label, pushes, target):
        fmt = label + b' %08x %08x %08x\n\x00'
        code_len = 48 + len(pushes)
        c = (b'\x4f\xef\xff\xf0' + b'\x48\xd7\x03\x03'
             + pushes + b'\x48\x79' + be(at + code_len)
             + b'\x4e\xb9' + be(0x400054B4)
             + b'\x4f\xef\x00\x10'    # pop four printf args
             + b'\x20\x3c' + be(0x03000000)
             + b'\x53\x80\x66\xfc'    # console drain delay
             + b'\x4c\xd7\x03\x03'    # restore D0/D1/A0/A1
             + b'\x4f\xef\x00\x10'    # release save frame
             + b'\x4e\xf9' + be(target))
        assert len(c) == code_len and len(fmt) == 20
        return c, fmt

    g5d_code, g5d_str = build_record_probe(
        G5D_AT, b'G5D', b'\x2f\x02\x2f\x03\x2f\x04',
        fn_new[0x4015591A])               # logs D4,D3,D2 after reads
    assert len(g5d_code) == 54
    g5d_slot = g5d_code + g5d_str + b'\x4e\x71' * 7
    assert len(g5d_slot) == 88
    CTX_AT = G5D_AT + len(g5d_slot)
    ctx_str = b'CTX %08x %08x %08x\n\x00'
    # Caller-side probe AFTER B64E has returned. No extra return address
    # enters B64E's argument frame. Preserve its D0 context return, log the
    # original object ID and cache tail, then replay the displaced bytes.
    ctx_code = (b'\x4f\xef\xff\xf0' + b'\x48\xd7\x03\x03'
                + b'\x2f\x39' + be(map_addr(0x40962690))
                + b'\x2f\x00' + b'\x2f\x2e\x00\x08'
                + b'\x48\x79' + be(CTX_AT + 66)
                + b'\x4e\xb9' + be(0x400054B4)
                + b'\x4f\xef\x00\x10'
                + b'\x20\x3c' + be(0x03000000) + b'\x53\x80\x66\xfc'
                + b'\x4c\xd7\x03\x03' + b'\x4f\xef\x00\x10'
                + b'\x24\x04\x20\x6e\x00\x10'
                + b'\x4e\xf9' + be(fn_new[0x4015816C] + 0x2c))
    assert len(ctx_code) == 66 and len(ctx_str) == 20
    ctx_slot = ctx_code + ctx_str
    assert len(g5d_slot) + len(ctx_slot) == 174

    # v61: replace the superseded G5 entry marker with a shared logger for
    # every older checkpoint. On entry two stub constants precede the
    # original frame. Save all volatile registers before constructing printf
    # arguments, and report the original SP rather than the logging frame.
    G5_AT = CTX_AT + len(ctx_slot)
    assert G5_AT == SP_LOG_AT
    g5_code = (b'\x4f\xef\xff\xf0' + b'\x48\xd7\x03\x03'
               + b'\x41\xef\x00\x18' + b'\x2f\x08'
               + b'\x2f\x2f\x00\x14'
               + b'\x48\x79' + be(fmt_at)
               + b'\x4e\xb9' + be(0x400054B4)
               + b'\x4f\xef\x00\x0c'
               + b'\x4e\xb9' + be(crc_print_at)
               + b'\x20\x3c' + be(0x03000000) + b'\x53\x80\x66\xfc'
               + b'\x4c\xd7\x03\x03' + b'\x4f\xef\x00\x10'
               + b'\x4f\xef\x00\x04' + b'\x4e\x75')
    g5_str = b''
    assert len(g5_code) == 64

    # v47: G6/G7 -- bisect the post-G5 crash window (v46 verdict: G5
    # printed, G4 never did -> the derailment is between the sibling's
    # udiv#2 and the builder call at FUN_4015816c+0x158). The window's
    # indirect calls: jsr (A2) at +0x58/+0x90/+0xB6 (A2 loaded once by
    # `lea 40157ec2,A2` at +0x52) and the streaming jsr (A4) after
    # +0xBC. G7 repoints the +0x52 lea's operand (G1/G2 idiom) so every
    # jsr (A2) prints first; G6 wraps the +0x76 direct jsr 40155ca8
    # (G3 idiom), carrying the CK for the leg. Both print-then-delay
    # (the v46-learned flush window). Last marker printed before
    # silence pins the crash to a few instructions.
    G6_AT = G5_AT + len(g5_code) + len(g5_str)
    g6_code = sp_thunk(G6_AT + 48, fn_new[0x40155CA8]) + b'\x4e\x71' * 4
    g6_str = b'G6:CA8\x00\x00'
    assert len(g6_code) == 48 and len(g6_str) == 8
    # Combined candidate: reuse only the 22-byte unreachable NOP tail of
    # the G6 stub. Its PEA/PEA/JMP head ends at +18 and cannot fall through.
    LRU_GUARD_AT = G6_AT + 18
    LRU_SITE = fn_new[0x401559F4] + 0xC4
    _lru_displaced = bytes.fromhex('246800102668000c')
    _lru_body = pieces[0x401559F4]
    assert bytes(_lru_body[0xC4:0xCC]) == _lru_displaced
    assert g6_code[18:40] == b'\x4e\x71' * 11
    assert g6_code[12:18] == b'\x4e\xf9' + be(SP_LOG_AT)
    LRU_GUARD = (bytes.fromhex('b3c866042268000c') + _lru_displaced
                 + b'\x4e\xf9' + be(LRU_SITE + 8))
    assert len(LRU_GUARD) == 22 and LRU_GUARD_AT % 2 == 0
    g6_code = g6_code[:18] + LRU_GUARD + g6_code[40:]
    _lru_body[0xC4:0xCC] = b'\x4e\xf9' + be(LRU_GUARD_AT) + b'\x4e\x71'
    rprint(f'combined native LRU guard @{LRU_GUARD_AT:#x}: 22 image bytes; '
           f'hook @{LRU_SITE:#x}, resume {LRU_SITE + 8:#x}')
    G7_AT = G6_AT + len(g6_code) + len(g6_str)
    g7_code = sp_thunk(G7_AT + 42, fn_new[0x40157EC2]) + b'\x4e\x71'
    g7_str = b'G7:EC2\x00\x00'
    assert len(g7_code) == 42 and len(g7_str) == 8
    assert G7_AT % 2 == 0
    # v46: non-zero pad (v32 lesson: zero holes in this band invite the
    # boot scribbler; v45/v46's CK flipped 0x47->0x00 hereabouts)
    #
    # v50 fd_entry: the #FORMAT dispatch entry + return reporter. v49
    # hardware PROVED (exception PC 0x400CE1DE = the handler's own
    # `illegal`) that the format body RETURNS; the old `tst.l d0; bne ->
    # illegal` self-report then killed the unit on a value that is NOT a
    # status -- the body's epilogue returns D4, which callees' count-down
    # loops leave at 0xFFFFFFFF (DT2's own callers ignore D0 entirely).
    # v50 prints instead of halting:  FD <SP> on entry (print-then-delay,
    # so it drains even if the format then derails), then jsr format424,
    # then FR <D0>, then RETURN -- control falls through the handler slot
    # into the next command's compare: the console SURVIVES and the
    # return code is readable over USB. FR 000000FF identifies the body's
    # unmount-error path (d4 = 0xFF at +0x2a); anything else = it ran on.
    # v50: fd_entry goes right after the zone's own pieces and BEFORE the
    # filler -- so its offset is the sum of the pieces, NOT pool+386
    # (386 is the OLD zone total, filler included). Getting this wrong
    # (v50 first attempt) put the handler's jsr 46 bytes into fd_entry:
    # the emu caught it at PC=0x46800696. The placement asserts below
    # pin the emitted bytes to FD_AT.
    _pre = (len(g5d_slot) + len(ctx_slot)
            + len(g5_code) + len(g5_str) + len(g6_code) + len(g6_str)
            + len(g7_code) + len(g7_str))
    FD_AT = pool_dump_at + _pre
    assert FD_AT % 2 == 0, hex(FD_AT)

    _delay = (b'\x20\x3c' + be(0x03000000)           # print-then-delay
              + b'\x53\x80' + b'\x66\xfc')

    def build_fd(strs):
        c = bytearray()
        c += g4_value_line(b'\x20\x0f\x2f\x00', strs[0])  # FD <A7>
        c += _delay
        c += b'\x4e\x71' * 3                   # v55: heal NOP'd (the
        #                                   tail is zeroed at runtime)
        # v52+ head probe: the body's FIRST real call is the unmount,
        # run against our ZEROED FS object -- call it here, bracketed,
        # mirroring the body exactly (pea obj; jsr lock; jsr unmount;
        # addq #4,a7). v54 proved the probe's value: its crash at the
        # unmount's first word exposed the zeroed-tail heal bug.
        c += g4_value_line(b'\x20\x0f\x2f\x00', strs[2])  # U0 <A7>
        c += _delay
        c += b'\x48\x79' + be(map_addr(0x46F4DEB0))   # pea <FS object>
        c += b'\x4e\xb9' + be(0x400015A0)             # v54: jsr lock (as the
        c += b'\x4e\xb9' + be(fn_new[0x4015BCE8])     #   body does) -> unmount
        c += b'\x58\x8f'                             # addq.l #4,a7
        c += g4_value_line(b'\x2f\x00', strs[3])      # U1 <D0>
        c += _delay
        # v56: CLEAR the unmount-scan region [obj+0x20, obj+0x100) --
        # all-zero IS the "unmounted" state FUN_4015bce8 tests for; the
        # boot mount leaves a non-zero field there, so the format would
        # take its error path (moveq #$ff,d4 = 0xFFFFFFFF) and never run.
        c += b'\x48\x78' + struct.pack('>H', 0xE0)    # pea #$E0 (the len)
        c += b'\x48\x79' + be(map_addr(0x46F4DED0))   # pea <dst = obj+0x20>
        c += b'\x4e\xb9' + be(0x40133EBC)             # jsr memset (DN2's)
        c += b'\x58\x8f'                             # addq.l #8,a7
        c += b'\x4e\xb9' + be(map_addr(0x4015A424))   # jsr format424
        c += g4_value_line(b'\x2f\x00', strs[1])     # FR <D0>
        c += _delay
        c += b'\x4e\x75'                             # rts (NEVER illegal)
        return c

    _f0 = build_fd([0, 0, 0, 0])
    _fs = FD_AT + len(_f0)
    fd_code = build_fd([_fs, _fs + 8, _fs + 16, _fs + 24])
    fd_strs = (b'FD'.ljust(8, b'\x00') + b'FR'.ljust(8, b'\x00')
               + b'U0'.ljust(8, b'\x00') + b'U1'.ljust(8, b'\x00'))
    assert len(fd_code) == len(_f0) == FD_CODE_LEN, len(fd_code)
    assert len(fd_strs) == FD_STRS_LEN, len(fd_strs)
    rprint(f'v50 fd_entry @{FD_AT:#x}: {len(fd_code)} B + '
           f'{len(fd_strs)} B strs; jsr format424 '
           f'({map_addr(0x4015A424):#x}), FR line, rts')
    # v59: probe the CALLER after udiv has returned. Preserve both halves of
    # its result and printf's volatile address registers. The caller's original
    # stack cleanup and MOVE restore NZVC; the next LSL overwrites the dead X.
    # No additional return address is put in the helper's argument frame.
    G5R_AT = FD_AT + len(fd_code) + len(fd_strs)
    g5r_str = b'G5R %08x %08x\r\n\x00'   # DN2 printf supports lowercase x
    g5r_code = (b'\x4f\xef\xff\xf0'       # lea -16(SP),SP
                + b'\x48\xd7\x03\x03'    # movem D0/D1/A0/A1,(SP)
                + b'\x2f\x0b\x2f\x01'    # push A3; push D1
                + b'\x48\x79' + be(G5R_AT + 58)
                + b'\x4e\xb9' + be(0x400054B4)
                + b'\x4f\xef\x00\x0c'    # pop printf arguments
                + _delay
                + b'\x4c\xd7\x03\x03'    # restore D0/D1/A0/A1
                + b'\x4f\xef\x00\x10'    # release save frame
                + b'\x4f\xef\x00\x10'    # original caller cleanup
                + b'\x20\x01'             # original MOVE D1,D0 (flags)
                + b'\x4e\xf9' + be(fn_new[0x40157D28] + 0x76))
    assert len(g5r_code) == 58 and len(g5r_str) == 16
    assert G5R_AT % 2 == 0
    _used = (len(g5d_slot) + len(ctx_slot)
             + len(g5_code) + len(g5_str) + len(g6_code) + len(g6_str)
             + len(g7_code) + len(g7_str) + len(fd_code) + len(fd_strs)
             + len(g5r_code) + len(g5r_str))
    _POOL = 386 + 44 + FD_CODE_LEN + FD_STRS_LEN   # v57: +44 (G5 grew)
    _filler = (b'G4PADG4PAD' * 20)[:_POOL - _used]
    assert _POOL - _used >= 0, (_POOL, _used)
    pool_dump = (g5d_slot + ctx_slot
                 + g5_code + g5_str + g6_code + g6_str + g7_code + g7_str
                 + fd_code + fd_strs + g5r_code + g5r_str + _filler)
    assert len(pool_dump) == _POOL, len(pool_dump)
    # v50 PLACEMENT GATE: the emitted bytes at FD_AT must be fd_entry's
    # start, and its strings must sit at FD_AT+len(fd_code) (the addresses
    # the code itself pushes).
    _off = FD_AT - pool_dump_at
    assert bytes(pool_dump[_off:_off + 4]) == b'\x20\x0f\x2f\x00', \
        pool_dump[_off:_off + 4].hex()
    assert bytes(pool_dump[_off + len(fd_code):
                           _off + len(fd_code) + 2]) == b'FD'
    assert bytes(pool_dump[_off + len(fd_code) + 8:
                           _off + len(fd_code) + 10]) == b'FR'
    assert _off + len(fd_code) + len(fd_strs) <= _POOL
    _g5r_off = G5R_AT - pool_dump_at
    assert pool_dump[_g5r_off:_g5r_off + 58] == g5r_code
    assert pool_dump[_g5r_off + 58:_g5r_off + 74] == g5r_str
    rprint(f'  v59 G5R @{G5R_AT:#x}: 58 B code + 16 B string '
           f'(D1/A3, preserve volatile regs, replay caller+0x70)')
    # v61: decode executable checkpoint bytes independently of strings.
    import capstone as _cs45
    _md45 = _cs45.Cs(_cs45.CS_ARCH_M68K, _cs45.CS_MODE_M68K_040
                     | _cs45.CS_MODE_BIG_ENDIAN)
    for _at, _code in ((G5D_AT, g5d_code), (CTX_AT, ctx_code),
                       (SP_LOG_AT, g5_code)):
        _decoded = list(_md45.disasm(_code, _at))
        assert sum(i.size for i in _decoded) == len(_code)
        assert _decoded[1].op_str == 'd0-d1/a0-a1, (a7)'
        _restores = [i for i in _decoded if i.mnemonic == 'movem.l'
                     and i.op_str == '(a7), d0-d1/a0-a1']
        assert len(_restores) == 1
    assert ctx_code[-12:-6] == b'\x24\x04\x20\x6e\x00\x10'
    assert ctx_code[-6:] == b'\x4e\xf9' + be(fn_new[0x4015816C] + 0x2c)
    assert g5_code[-6:] == b'\x4f\xef\x00\x04\x4e\x75'
    rprint(f'  v61 CTX @{CTX_AT:#x}: object/context/cache-tail; '
           f'G5D @{G5D_AT:#x}: record values; SP logger @{SP_LOG_AT:#x}')
    # v52 fd gate: decode + exact immediates + NO illegal anywhere
    _seqf, _i = [], 0
    while _i < len(fd_code):
        _ins = next(_md45.disasm(bytes(fd_code[_i:_i + 12]), FD_AT + _i),
                    None)
        assert _ins is not None, ('v52 fd undecodable at +%#x' % _i)
        _seqf.append(_ins.mnemonic)
        _i += _ins.size
    assert _seqf == ['move.l', 'move.l', 'pea.l', 'pea.l', 'jsr', 'lea.l',
                     'move.l', 'subq.l', 'bne.b', 'nop', 'nop', 'nop',
                     'move.l', 'move.l', 'pea.l', 'pea.l', 'jsr', 'lea.l',
                     'move.l', 'subq.l', 'bne.b', 'pea.l', 'jsr', 'jsr',
                     'addq.l', 'move.l', 'pea.l', 'pea.l', 'jsr', 'lea.l',
                     'move.l', 'subq.l', 'bne.b', 'pea.l', 'pea.l', 'jsr',
                     'addq.l', 'jsr', 'move.l', 'pea.l', 'pea.l', 'jsr',
                     'lea.l', 'move.l', 'subq.l', 'bne.b', 'rts'], _seqf
    assert bytes(fd_code[0:4]) == b'\x20\x0f\x2f\x00'      # FD value = A7
    assert bytes(fd_code[36:42]) == b'\x4e\x71' * 3  # v55: heal NOP'd
    assert bytes(fd_code[42:46]) == b'\x20\x0f\x2f\x00'    # U0 value = A7
    assert bytes(fd_code[78:84]) == (b'\x48\x79'
                                     + be(map_addr(0x46F4DEB0)))
    assert bytes(fd_code[84:90]) == b'\x4e\xb9' + be(0x400015A0)  # lock
    assert bytes(fd_code[90:96]) == (b'\x4e\xb9'
                                     + be(fn_new[0x4015BCE8]))
    assert bytes(fd_code[96:98]) == b'\x58\x8f'            # arg popped
    assert bytes(fd_code[98:100]) == b'\x2f\x00'           # U1 value = D0
    # v56: the unmount-state clear (memset of the scan region)
    assert bytes(fd_code[132:136]) == b'\x48\x78\x00\xe0'        # pea #0xE0
    assert bytes(fd_code[136:142]) == (b'\x48\x79'
                                       + be(map_addr(0x46F4DED0)))
    assert bytes(fd_code[142:148]) == b'\x4e\xb9' + be(0x40133EBC)
    assert bytes(fd_code[148:150]) == b'\x58\x8f'
    assert bytes(fd_code[150:156]) == (b'\x4e\xb9'
                                       + be(map_addr(0x4015A424)))
    assert bytes(fd_code[190:192]) == b'\x4e\x75'          # rts
    assert b'\x4a\xfc' not in bytes(fd_code)               # never halt

    # Fixed wrapper slots retain their original homes; G6/G7 now share
    # the preserving logger too. No legacy printf/CRC path remains live.
    assert g6_code[:18] == sp_thunk(G6_AT + 48, fn_new[0x40155CA8])[:18]
    assert g6_code[18:40] == LRU_GUARD
    assert g6_code[40:] == b'\x4e\x71' * 4
    assert g7_code[:40] == sp_thunk(G7_AT + 42, fn_new[0x40157EC2])
    rprint(f'  v61 preserving checkpoint slots; fmt {fmt_at:#x}, '
           f'crc {crc_print_at:#x}, remaining filler {len(_filler)} B')

    # v60: retain the original builder call, retiring its unused G4 probe.
    _builder = pieces[0x4015816C]
    assert bytes(_builder[0x158:0x15e]) == b'\x4e\xb9' + be(fn_new[0x40157B6E])

    # v61: the second divide is called directly; G5R still captures its
    # return. The retired entry checkpoint made space for the shared logger.
    g5_body = pieces[0x40157D28]
    assert bytes(g5_body[0x6a:0x70]) == b'\x4e\xb9' + be(fn_new[0x40183E94])
    assert bytes(g5_body[0x58:0x5e]) == b'\x4e\xb9' + be(fn_new[0x401559F4])
    # Trace the earlier context-lookup return before it reaches D28.
    assert bytes(_builder[0x26:0x2c]) == b'\x24\x04\x20\x6e\x00\x10'
    _builder[0x26:0x2c] = b'\x4e\xf9' + be(CTX_AT)
    rprint(f'  v61 builder+0x26 JMP {CTX_AT:#x}; replay and resume +0x2c')

    # The first six bytes AFTER the divide are one four-byte LEA and a
    # two-byte MOVE. Replace both with a JMP; the thunk replays them after
    # logging. The original G5 tail-JMP and the helper's stack args stay intact.
    _g5r_original = b'\x4f\xef\x00\x10\x20\x01'
    if bytes(g5_body[0x70:0x76]) != _g5r_original:
        fail.append('v59 caller return-probe site mismatch: '
                    + bytes(g5_body[0x70:0x76]).hex())
    else:
        g5_body[0x70:0x76] = b'\x4e\xf9' + be(G5R_AT)
        rprint(f'  v59 G5R site: FUN_40157d28+0x70 JMP {G5R_AT:#x}; '
               f'resume {fn_new[0x40157D28] + 0x76:#x}')

    # Retain the post-read JSR checkpoint with the original frame intact.
    for _off, _callee, _probe, _name in (
            (0x8C, 0x4015591A, G5D_AT, 'G5D'),):
        _expected = b'\x4e\xb9' + be(fn_new[_callee])
        if bytes(g5_body[_off:_off + 6]) != _expected:
            fail.append(f'v60 {_name} call-site mismatch at caller+{_off:#x}')
        else:
            g5_body[_off + 2:_off + 6] = be(_probe)
            rprint(f'  v60 {_name} caller+{_off:#x} -> {_probe:#x}; '
                   f'tail-JMP {fn_new[_callee]:#x}')

    # v47: patch G6 -- FUN_4015816c+0x76, the direct
    # `jsr 40155ca8.l` between the 1st and 2nd jsr (a2).
    g6_body = pieces[0x4015816C]
    g6_pat = b'\x4e\xb9' + be(fn_new[0x40155CA8])
    g6_off = bytes(g6_body).find(g6_pat)
    if g6_off < 0:
        fail.append('v47: G6 site (jsr fn_new[40155ca8]) not found '
                    'in FUN_4015816c')
    else:
        assert g6_off == 0x76, hex(g6_off)
        g6_body[g6_off + 2:g6_off + 6] = be(G6_AT)
        rprint(f'  v47 G6 site: FUN_4015816c+{g6_off:#x} jsr -> '
               f'{G6_AT:#x} (marker, jmp {fn_new[0x40155CA8]:#x})')

    # v47: patch G7 -- FUN_4015816c+0x52, repoint the
    # `lea 40157ec2.l, A2` OPERAND (the G1/G2 idiom). Every
    # jsr (a2) (+0x58/+0x90/+0xb6) then enters the G7 thunk,
    # which prints and tail-jmps into 40157ec2's real home.
    g7_pat = b'\x45\xf9' + be(fn_new[0x40157EC2])
    g7_off = bytes(g6_body).find(g7_pat)
    if g7_off < 0:
        fail.append('v47: G7 site (lea fn_new[40157ec2]) not found '
                    'in FUN_4015816c')
    else:
        assert g7_off == 0x52, hex(g7_off)
        g6_body[g7_off + 2:g7_off + 6] = be(G7_AT)
        rprint(f'  v47 G7 site: FUN_4015816c+{g7_off:#x} lea -> '
               f'{G7_AT:#x} (a2-thunk, jmp {fn_new[0x40157EC2]:#x})')
    # emission order must match the address plan: heal @heal_at,
    # crc_print @crc_print_at, pool_dump @pool_dump_at
    wrapper += heal
    wrapper += crc_print
    wrapper += pool_dump
    # total = 56 (v9 body) + 8 (#FORMAT) + 8 (#WRTEST) + 68 (stub)
    #       + 8 (pad) + 512 (pattern) + marks + TR_FMT slot + ck_fmt
    #       + fmt2 + 8 thunks + heal + crc_print + pool_dump
    _marks_n = 8 * 8
    _total = (56 + 8 + 8 + 68 + 8 + 512 + _marks_n + 16 + 16 + 16
              + 8 * 40 + len(heal) + len(crc_print) + len(pool_dump))
    if len(wrapper) != _total:
        print(f'WRAPLEN MISMATCH: {len(wrapper)} vs {_total}')
    assert len(wrapper) == _total, len(wrapper)
    # v27 GUARD: wrapper_len is the RESERVED space before the first
    # relocated function (cur = wrapper_at + wrapper_len). If the wrapper
    # outgrows it the functions are silently emitted on top of the
    # wrapper's own strings/pattern/thunks -- which is exactly how v26
    # put udiv into the diagnostic trampolines and died before F2.
    # Checked against the real wrapper, not just the formula.
    assert len(wrapper) <= wrapper_len, (
        f'wrapper {len(wrapper)} B exceeds reserved wrapper_len '
        f'{wrapper_len} B -- raise the wrapper_len formula')
elif MOUNT_AT_BOOT:
    if CONSOLE:
        # v10 console prefix (hardware-proven in v9): set boot-flags bit
        # 0x20 in RAM. The flags dword 0x40287520 is written ONCE at OS
        # entry (0x400004EC) and only ever read afterwards (moveq/and.l
        # tests -- never masked); our hook runs BEFORE the console gate at
        # 0x400CF086 in the same master-init function, so the stock service
        # console (channel setup 0x4011F34C, '#' router FUN_4011F364,
        # console task 0x400CEA6E, boot mode 4) comes up after our format
        # finishes. Encodings byte-proven in stock: or.l @0x400F2070,
        # move.l D0,(abs).l 9 sites.
        wrapper += b'\x70\x20'                               # moveq #0x20,D0
        wrapper += b'\x81\xb9' + be(0x40287520)              # or.l (flags),D0
        wrapper += b'\x23\xc0' + be(0x40287520)              # move.l D0,(flags)
    wrapper += b'\x20\x3c' + be((state_end - STATE_BASE) // 4)
    wrapper += b'\x20\x7c' + be(STATE_BASE)
    wrapper += b'\x42\x98\x53\x80\x66\xfa'               # zero state
    wrapper += b'\x4e\xb9' + be(DN2_HOOK_TARGET)            # jsr helper2
    wrapper += b'\x4e\xb9' + be(map_addr(DT2_PREMOUNT))     # jsr premount
    wrapper += b'\x42\xa7'                                   # clr.l -(sp)
    wrapper += b'\x4e\xb9' + be(map_addr(DT2_MOUNT))        # jsr mount(0)
    wrapper += b'\x58\x8f'                                   # addq #4,sp
    # v8_3 tail: mount failure -> grafted format (NO erase -- this chip's
    # bulk-erase never completes; eMMC FTL needs none); format error ->
    # push the code and force the V04 screen (self-reporting); success ->
    # boot continues (into console mode if CONSOLE).
    wrapper += b'\x4a\x80\x67\x0e'                          # tst D0; beq +14
    wrapper += b'\x4e\xb9' + be(map_addr(0x4015A424))     # jsr format
    wrapper += b'\x4a\x80\x67\x04'                          # tst D0; beq +4
    wrapper += b'\x2f\x00\x4a\xfc'                          # push code; ILLEGAL
    wrapper += b'\x4e\x75'                                   # rts
rprint(f'wrapper_len (actual) = {wrapper_len}')
# v27: compare against the SAME wrapper_len the layout used to place the
# first relocated function. This used to re-derive the formula inline with
# its own hardcoded pool_dump size (130), which silently drifted out of
# step with wrapper_len above -- exactly the class of bug that let v26
# emit functions on top of the wrapper.
assert len(wrapper) == wrapper_len, (len(wrapper), wrapper_len)

# copyr: the ONLY code that runs from the image tail. Entered via the
# bss-clear jmp (file 0xB2) at its IMAGE address, after DDR-restore and
# before anything uses bss. Copies the graft (itself included) to
# GRAFT_BASE, then runs the stock clear over the FULL stock range -- the
# graft's image storage becomes ordinary zeroed bss again. All encodings
# are byte-for-byte patterns verified against the stock reset code.
copyr = bytearray()
copyr += b'\x2f\x09'                              # move.l A1,-(SP)
copyr += b'\x2f\x0a'                              # move.l A2,-(SP)
copyr += b'\x22\x3c' + be(G // 4)                 # move.l #G/4,D1
copyr += b'\x45\xf9' + be(IMAGE_STORE)            # lea <src>,A2
copyr += b'\x43\xf9' + be(GRAFT_BASE)             # lea <dst>,A1
copyr += b'\x22\x9a'                              # copy: move.l (A2)+,(A1)
copyr += b'\x41\xe9\x00\x04'                      #   lea 4(A1),A0
copyr += b'\x53\x81'                              #   subq.l #1,D1
copyr += b'\x22\x48'                              #   movea.l A0,A1
copyr += b'\x66\xf4'                              #   bne.b copy
copyr += b'\x24\x5f'                              # movea.l (SP)+,A2
copyr += b'\x22\x5f'                              # movea.l (SP)+,A1
copyr += b'\x4f\xef\xff\xf0'                      # stock clear:
copyr += b'\x48\xd7\x00\xf0'                      #   lea -16(SP),SP
copyr += b'\x20\x7c' + be(0x402FC000)             #   movem.l {D4-D7},(SP)
copyr += b'\x22\x3c' + be(BSS_CLEAR_END)          #   movea.l #bss,A0
copyr += b'\x92\x88'                              #   move.l #end,D1
copyr += b'\xe8\x81'                              #   sub.l A0,D1
copyr += b'\x42\x84\x42\x85\x42\x86\x42\x87'      #   asr.l #4,D1
copyr += b'\x48\xd0\x00\xf0'                      #   clr.l D4-D7
copyr += b'\x41\xe8\x00\x10'                      #   movem.l {D4-D7},(A0)
copyr += b'\x53\x81'                              #   lea 16(A0),A0
copyr += b'\x66\xf4'                              #   subq.l #1,D1
copyr += b'\x4c\xd7\x00\xf0'                      #   bne.b clear
copyr += b'\x4f\xef\x00\x10'                      #   movem.l (SP),{D4-D7}
copyr += b'\x4e\x75'                              #   lea 16(SP),SP; rts
assert len(copyr) == copyr_len, len(copyr)

graft = bytearray(copyr)
graft += wrapper                  # sits at GRAFT_BASE+copyr_len == wrapper_at
assert len(graft) == copyr_len + wrapper_len, len(graft)
# place each unit at its exact layout address (alignment pads are zeros)
for entry in order:          # v25: MUST match the fn_new placement order
    addr = fn_new[entry] - GRAFT_BASE
    if len(graft) > addr:
        fail.append(f'layout drift before fn {entry:#x}')
        break
    graft += b'\x00' * (addr - len(graft))
    graft += pieces[entry]
for name, s, e, b in blob_bytes:
    addr = blob_new[name][2] - GRAFT_BASE
    if len(graft) > addr:
        fail.append(f'layout drift before blob {name}')
        break
    graft += b'\x00' * (addr - len(graft))
    graft += b
# v16: state block NOT emitted -- it is zeroed RAM at boot (the image
# tail ends with the last blob; G only 16-byte-aligns the copy length)
if len(graft) > G:
    fail.append(f'layout drift: graft {len(graft):#x} > G {G:#x}')
graft += b'\x00' * (G - len(graft))

# v37: WRITE-ERROR INSTRUMENTATION.
#
# v36's two crashes (identical, deterministic): V0B PC=0xFFFFFFFE -- a
# driver error code (-2) became a jump target, in the driver-task context
# (405C59xx struct, 447CF700/446705xx heap, callback 0x401C99A0), minutes
# into the format's write phases. Decode of the DN2 write primitive
# 0x4012C780 shows an error ladder at its tail:
#     moveq #-10/-11/-12/-13/-2,D2 ; jsr 0x401326aa (report) ;
#     pea 0x4667ad00 (write mutex) ; jsr 0x400016d2 (unlock) ;
#     move.l D2,D0 ; movem ; rts
# -- the write's error code, INCLUDING -2, is a legitimate return value,
# and DT2's primitive (0x4012E0C0) carries the identical ladder. Something
# downstream turns that -2 into a PC. Static analysis cannot say which
# write fails or why, so: INSTRUMENT. Every `jsr/jmp 0x4012C780` in the
# graft (the format's writes -- the wipe's 0x14010-B write at 0x5D80C0,
# F4:ROOT's structure writes, F5:SB's superblock write, the wrtest stub)
# is redirected to the 32-B checker in the dead-heal slot (see v40 block
# below for the byte-by-byte). The checker pops the caller's return into
# A2 first -- a plain jsr-into-jsr would shift the write primitive's
# argument frame by +4 and feed it the return address as the LBA, which
# is exactly the v37-v39 -10 bug. A failing write traps IMMEDIATELY with
# the error code on the stack and the driver's mailbox line printed;
# the success path tail-jmps (A2), stack-balanced to the byte.
STUB_AT = heal_at             # v37: the DEAD v23 heal routine (32 B, uncalled
# since v24 switched the marker thunks to jsr crc_print directly). 16 B of
# the 32 B hold the checker; crc_print at heal_at+32 is untouched; NOTHING
# in the layout moves.
_heal_pos = heal_at - GRAFT_BASE
assert bytes(graft[_heal_pos:_heal_pos + 2]) == b'\x41\xf9' \
    and bytes(graft[_heal_pos + 6:_heal_pos + 8]) == b'\x43\xf9', \
    'v37: expected the dead heal prologue at heal_at'
# belt-and-braces: nothing may reference heal_at
for _ref in (b'\x4e\xb9' + be(heal_at), b'\x4e\xf9' + be(heal_at)):
    assert bytes(graft).find(_ref) < 0, 'v37: heal is not dead -- referenced!'
_stub_pos = _heal_pos
# v45: the v39 DUMP4_AT asserts are RETIRED -- dump4 (and the whole
# probe map) were removed from the dead pool_dump zone, which now holds
# the G4 entry-probe thunk (234 B code + 24 B strings + zero pad).
# Nothing referenced dump4 since v42 (the v42 checker dropped the
# mailbox diag; the stub below is fully self-contained).
# v40: FRAME-CORRECT CHECKER. The v37-v39 checker added one extra
# return address between the caller's args and the write primitive:
# caller jsr'd the checker (push ret_caller), checker jsr'd the write
# (push ret_checker) -- so the primitive read its args at [SP+0x18/1C/20]
# one word HIGH: d4 = ret_caller (0x466C40B0), d2 = lba, d3 = len. The
# capacity check (0x4012c7fc: cmp capacity,d4; bls -> moveq #-10,D2) then
# compared the RETURN ADDRESS against capacity 0x2E1A000 -> -10 every
# time. Every v37/v38/v39 "write failure" -- #WRTEST included -- was this
# frame shift, NOT the driver. The v39 diag line proves it: [b6b8]=0 and
# [b6bc]=0 at failure = the primitive exited via validation WITHOUT ever
# submitting (the submit path sets b6bc=1/b6b8=1 at 0x4012c8fa-0x4012c906
# before the waits). The v37 wrtest screen even showed the corrupted "LBA":
# slot 2 = 466C00BC = the return into the wrtest stub.
#
# v42 Fix: the checker must PRESERVE A2. DT2's ekfs_format holds a LIVE
# callee in A2 across its sub-calls -- after the F3 phase it executes
# `jsr (A2)` (the geometry fn, loaded PC-relatively BEFORE the F3 write)
# and the whole DT2 chain preserves A2 (the write primitive's own
# movem d2-d5/a2 is exactly why A2 looked "safe"). The v40/v41 checker
# clobbered it with the popped return: the emu flight recorder caught the
# post-F3 jsr (A2) jumping into FUN_40155624+0x2a, its lea 0x14 popping
# a word too many, and FUN_401554ec's rts returning into the mirror.
# v42: save A2 to CHECKER_SCRATCH, pop the return into A2, call the
# write, then push the return, RESTORE the caller's A2, rts. D0 (the
# write's return code) flows through untouched; D2-D5 untouched; the
# failure path keeps the error-code push + illegal (the 32-byte budget
# no longer fits the mailbox dump4 diag).
# 32 bytes exactly -- the whole dead-heal slot, ZERO layout movement.
_write_stub = (b'\x23\xca' + be(CHECKER_SCRATCH)   # save caller's A2  (0)
               + b'\x24\x5f'                        # movea.l (a7)+,a2  (6)
               + b'\x4e\xb9' + be(0x4012C780)      # jsr the real write (8)
               + b'\x4a\x80'                        # tst.l D0         (14)
               + b'\x67\x04'                        # beq.b -> tail    (16)
               + b'\x2f\x00'                        # push D0: the code (18)
               + b'\x4a\xfc'                        # illegal           (20)
               + b'\x2f\x0a'                        # push A2: return  (22)
               + b'\x24\x79' + be(CHECKER_SCRATCH)  # restore caller A2 (24)
               + b'\x4e\x75')                       # rts              (30)
assert len(_write_stub) == 32, len(_write_stub)
assert _write_stub[16:18] == b'\x67\x04'          # beq lands on the tail
# v42: capstone-verify EVERY instruction at BUILD time. Hand encodings
# self-certified bugs in v40 (2A5C, 4E92) because a byte template cannot
# check semantics. The disassembler is the authority.
import capstone as _cs
_md = _cs.Cs(_cs.CS_ARCH_M68K, _cs.CS_MODE_M68K_040 | _cs.CS_MODE_BIG_ENDIAN)
_seq = [('%s %s' % (i.mnemonic, i.op_str)).strip()
        for i in _md.disasm(_write_stub, STUB_AT)]
assert _seq == ['move.l a2, $%x.l' % CHECKER_SCRATCH,
                'movea.l (a7)+, a2',
                'jsr $4012c780.l',
                'tst.l d0',
                'beq.b $%x' % (STUB_AT + 22),
                'move.l d0, -(a7)',
                'illegal #$4afc',
                'move.l a2, -(a7)',
                'movea.l $%x.l, a2' % CHECKER_SCRATCH,
                'rts'], _seq
graft[_stub_pos:_stub_pos + 32] = _write_stub
_patch_calls = 0
for _op, _name in ((b'\x4e\xb9', 'jsr'), (b'\x4e\xf9', 'jmp'),
                   (b'\x48\x79', 'shared logger tail')):
    _pat = _op + be(0x4012C780)
    _off = 0
    while True:
        _off = graft.find(_pat, _off, len(graft))
        if _off < 0:
            break
        if _op == b'\x48\x79':
            # v61's shared logger takes its original callee as a pushed
            # constant. Patch only the exact fixed-slot stub, so its write
            # still passes through the same checker as the older JMP did.
            assert (graft[_off + 6:_off + 8] == b'\x48\x79'
                    and graft[_off + 12:_off + 18] == b'\x4e\xf9' + be(SP_LOG_AT)
                    and graft[_off + 18:_off + 40] == b'\x4e\x71' * 11)
        # v42: skip the checker's OWN jsr write -- it sits at _stub_pos+8
        # (behind the A2-save + pop), and the whole 32-B stub must survive
        # the patch loop untouched.
        if _stub_pos <= _off < _stub_pos + 32:
            _off += 6
            continue                      # the stub's own jsr -- keep
        graft[_off:_off + 6] = _op + be(STUB_AT)
        _patch_calls += 1
        rprint(f'  v37: write {_name} @'
               f'{GRAFT_BASE + _off:#x} -> checker stub')
        _off += 6
rprint(f'v37: {_patch_calls} write calls instrumented, checker stub @'
       f'{STUB_AT:#x}')
assert _patch_calls >= 3, 'v37: expected the wipe/F4/F5/wrtest write calls'

# v43: FLASH-OP SECTOR ALIGNMENT. Hardware postmortem (v36 x2, v42): the
# DRIVER TASK dies (V0B, PC=0xFFFFFFFE = the -2 error code as a jump
# target; driver-task stack: 405C59xx work queue, 446705xx heap,
# callback 401C99A0) on any flash op whose byte length is not a whole
# number of sectors. The write primitive chunks at 0x10000 (aligned)
# and hands the remainder to the single-op path, which CEIL-ROUNDS the
# sector count ((len+0x1ff)>>9, 0x4012c818) -- a 16-byte tail becomes
# a sub-sector op the DN2 driver cannot execute. Every sector-exact op
# this unit has ever run succeeds (0x200, 0x8000, 0xB000, 0x10000
# staging); the ONLY failures are the two 0x14010 ops (160 sectors +
# 16 B): the F3 wipe WRITE and the journal read-back READ -- three
# deterministic driver deaths on the write. DT2's own driver handles
# the tail (different ColdFire OS code -- only the primitive matched
# for retargeting), which is why the same 0x14010 works on DT2.
# Fix: round grafted flash-op LEN immediates DOWN to sector multiples.
# The F3 memset keeps 0x14010 (RAM work, no driver); the disk tail
# (0x5EC0C0..0x5EC0D0, 16 B) is already zeros on the virgin region.
_flash_targets = (STUB_AT, 0x4012C59A)
_align_fixed = []
for _op in (b'\x4e\xb9', b'\x4e\xf9', b'\x4e\xba', b'\x4e\xfa'):
    _off = 0
    while True:
        _off = graft.find(_op, _off, len(graft))
        if _off < 0:
            break
        if _op in (b'\x4e\xb9', b'\x4e\xf9'):
            _tgt = int.from_bytes(graft[_off + 2:_off + 6], 'big')
        else:
            _d = int.from_bytes(graft[_off + 2:_off + 4], 'big', signed=True)
            _tgt = GRAFT_BASE + _off + 2 + _d
        if (_tgt in _flash_targets and _off >= 12
                and bytes(graft[_off - 12:_off - 10]) == b'\x2f\x3c'
                and bytes(graft[_off - 6:_off - 4]) == b'\x2f\x3c'):
            _ln = int.from_bytes(graft[_off - 10:_off - 6], 'big')
            if _ln % 512:
                _new = _ln & ~0x1FF
                rprint(f'  v43: align flash-op len {_ln:#x} -> {_new:#x} '
                       f'at {GRAFT_BASE + _off - 12:#x}')
                graft[_off - 10:_off - 6] = _new.to_bytes(4, 'big')
                _align_fixed.append((GRAFT_BASE + _off - 12, _ln, _new))
        _off += 2
assert _align_fixed, 'v43: no unaligned flash-op length found'
for _a, _old, _new in _align_fixed:
    assert 0 < _old - _new < 512 and _new % 512 == 0, (_a, hex(_old))
rprint(f'v43: {len(_align_fixed)} flash-op lengths aligned to sector '
       f'multiples (checker @{STUB_AT:#x} unchanged)')

new_image = bytearray(dn2)
assert len(new_image) == APPEND_AT, (len(new_image), APPEND_AT)
new_image += graft

# ------------------------------------------------------- 9. DN2 patches ---
# v2: NO stock constants change -- the image tail, reset block, _sbss and
# allocator-pool config all stay exactly as shipped. Only two call targets
# are redirected:

# 1) bss-clear body -> jmp to the copy+clear routine AT ITS IMAGE ADDRESS.
#    (it runs pre-copy from the image tail; sole caller is os_entry's
#    pc-relative jsr at file 0x142, untouched; 6-byte jmp + nop keeps size)
if bytes(new_image[DN2_BSSCLEAR_FILE:DN2_BSSCLEAR_FILE + 2]) != b'\x4f\xef':
    fail.append('bss-clear prologue mismatch at file 0xB2')
else:
    new_image[DN2_BSSCLEAR_FILE:DN2_BSSCLEAR_FILE + 8] = \
        b'\x4e\xf9' + be(IMAGE_STORE) + b'\x4e\x71'  # jmp; nop
    rprint(f'bss-clear body jmp -> copy+clear at image {IMAGE_STORE:#x}')

# v2 sanity: stock bytes [0, APPEND_AT) must be identical except the two
# redirected call sites -- see the authoritative diff gate below (after
# both patches are applied).

if MOUNT_AT_BOOT:
    if bytes(new_image[DN2_MASTER_JSR_FILE:DN2_MASTER_JSR_FILE + 6]) \
            != b'\x4e\xb9' + be(DN2_HOOK_TARGET):
        fail.append('master init jsr site mismatch (want jsr helper2)')
    else:
        new_image[DN2_MASTER_JSR_FILE + 2:DN2_MASTER_JSR_FILE + 6] = \
            be(wrapper_at)
        rprint(f'helper2 jsr redirected to wrapper {wrapper_at:#x}')
else:
    rprint('no-mount mode: no master-init hook; graft is inert')

if MOUNT_AT_BOOT and FMT_CMD:
    # 3) v12 console-command patch, on the stock #REBOOT slot:
    #    a) pea "#REBOOT" (0x4021acb1) -> "#FORMAT" string in the graft
    #    b) its 16-B handler (watchdog write) -> jsr format424; tst D0;
    #       beq.b +6 (fall past the handler into the next command's
    #       compare -- line discarded, console survives); move.l D0,-(SP);
    #       illegal (V04 screen with the format's error code); nop
    # Pattern-located (immune to +-2 listing drift):
    #   pea (0x4021acb1).l ; move.l D2,-(SP) ; jsr (A4) ; addq #8,SP ;
    #   tst.l D0 ; bne.b +0x4e ; <16 handler bytes>
    pat = (b'\x48\x79' + be(0x4021acb1) + b'\x2f\x02\x4e\x94\x50\x8f'
           + b'\x4a\x80\x66\x4e')
    site = bytes(new_image).find(pat)
    if site < 0:
        fail.append('v12: #REBOOT handler pattern not found')
    else:
        new_image[site + 2:site + 6] = be(fmtcmd_str_at)
        # v44: the handler jsr's format424 DIRECTLY -- no probe map.
        # v43 postmortem: the worker's dispatch machinery (COW string
        # records, virtual calls) is fragile under sustained printf load:
        # EVERY crash since v36 (v36 x2, v42, v43) hit during heavy
        # dump/format printf traffic, and the post-v43 12-min idle watch
        # + read-only MMCDUMPs of the dirty sectors were STABLE -- the
        # dirty-eMMC theory is retired. The diagnostic era is complete
        # (25/26 MATCH, constant CK code-sums); the 28-probe map's
        # rapid-fire dump4 print storm is now pure risk with no value.
        # pool_dump/dump4 stay emitted as DEAD code (zero layout
        # movement); the marker ladder stays (2 short printfs per phase,
        # spread across minutes of real format work).
        # v50: the handler jsr's fd_entry, which prints FD <SP>, calls
        # format424, prints FR <D0>, and RETURNS -- control falls through
        # the 16-B slot into the next command's compare (line discarded,
        # console SURVIVES). v49 postmortem: the old
        # `tst.l d0; bne -> move.l d0,-(sp); illegal` self-report HALTED
        # the unit (exception PC 0x400CE1DE = exactly that illegal) on a
        # D0 that is not a status -- the body's epilogue returns D4,
        # which callees leave at 0xFFFFFFFF (DT2 ignores D0).
        # v53: the handler must NOT fall through. The stock bytes after the
        # slot are the #REBOOT action's tail -- nops, then
        # `move.b #0x80,0xEC090000` (the RESET trigger) and `bra $400CD4E0`.
        # Falling into it REBOOTS the unit (hardware-confirmed: v50/v51
        # rebooted with no exception screen). Instead the handler branches
        # to the DISPATCH-LOOP HEAD 0x400CD4E0 -- the same target the stock
        # #REBOOT tail uses, and the same one the v13/v14 #WRTEST slot's
        # success path uses (its v14 postmortem: the bra.w reference is the
        # EXTENSION WORD, so disp = target - (opcode_addr + 2)).
        hsite = site + len(pat)
        LOOP_HEAD = 0x400CD4E0
        # jsr fd_entry; bra.w LOOP_HEAD; nops  (16 B exactly)
        h = (b'\x4e\xb9' + be(FD_AT)              # jsr fd_entry
             + b'\x60\x00' + struct.pack('>h',
                                         LOOP_HEAD - (BASE + hsite + 8))
             + b'\x4e\x71' * 3)                   # nop pad -> 16 B
        assert len(h) == 16, len(h)
        hsite = site + len(pat)
        if bytes(new_image[hsite:hsite + 16]) != \
                bytes.fromhex('203cb0b0dada23c0480000004e714e71'):
            fail.append(f'v12: #REBOOT handler bytes mismatch at '
                        f'{BASE + hsite:#x}: '
                        f'{bytes(new_image[hsite:hsite + 16]).hex()}')
        else:
            new_image[hsite:hsite + 16] = h
            # positive post-patch verification of both edits
            assert bytes(new_image[hsite:hsite + 16]) == h
            assert bytes(new_image[site + 2:site + 6]) == be(fmtcmd_str_at)
            rprint(f'v12: #REBOOT -> "#FORMAT" (string {fmtcmd_str_at:#x}); '
                   f'handler @ {BASE + hsite:#x} -> jsr format424 '
                   f'+ self-report')

if MOUNT_AT_BOOT and FMT_CMD:
    # 4) v13 write-primitive test on the #REBOOT_INTO_MAINTENANCE_MODE slot:
    #    pea (0x4021acb9) -> "#WRTEST" string in the graft; its 74-B
    #    self-contained handler block (watchdog write + nop wall) gets an
    #    18-B head: jsr wrtest_stub; tst D0; beq.b +4; move.l D0,-(SP);
    #    illegal (error -> V04 with the code); bra.w dispatch-loop head
    #    (success -> line consumed, console lives; the nop wall + trailing
    #    stock bytes become dead code).
    patm = (b'\x48\x79' + be(0x4021acb9) + b'\x2f\x02'
            + b'\x47\xf9' + be(0x4017e8a8) + b'\x4e\x93'
            + b'\x50\x8f\x4a\x80\x66\x4e')
    ms = bytes(new_image).find(patm)
    if ms < 0:
        fail.append('v13: maintenance-slot pattern not found')
    else:
        new_image[ms + 2:ms + 6] = be(wrtest_str_at)
        mhs = ms + len(patm)
        if bytes(new_image[mhs:mhs + 18]) != bytes.fromhex(
                '203cb0b0dada23c048000000 4e714e714e71'.replace(' ', '')):
            fail.append(f'v13: maintenance handler head mismatch: '
                        f'{bytes(new_image[mhs:mhs + 18]).hex()}')
        else:
            bra_disp = 0x400CD4E0 - (BASE + mhs + 16)
            # v14 fix: bra.w target = (opcode_addr + 2) + disp -- the
            # reference is the EXTENSION WORD, not the instruction end.
            # v13 used +18 -> landed at loop_head-2 (0x400CD4DE) -> V0B
            # F-line exception on the #WRTEST success path (which also
            # proved both test writes returned 0 = the driver WORKS).
            hh = (b'\x4e\xb9' + be(wrtest_stub_at)   # jsr wrtest_stub
                  + b'\x4a\x80'                     # tst.l D0
                  + b'\x67\x04'                     # beq.b +4 -> bra
                  + b'\x2f\x00'                     # move.l D0,-(SP)
                  + b'\x4a\xfc'                     # illegal
                  + b'\x60\x00' + struct.pack('>h', bra_disp))  # bra.w loop
            assert len(hh) == 18, len(hh)
            new_image[mhs:mhs + 18] = hh
            assert bytes(new_image[mhs:mhs + 18]) == hh
            assert bytes(new_image[ms + 2:ms + 6]) == be(wrtest_str_at)
            rprint(f'v13: maintenance slot -> "#WRTEST" (string '
                   f'{wrtest_str_at:#x}); handler @ {BASE + mhs:#x} -> '
                   f'jsr wrtest {wrtest_stub_at:#x} + self-report')

diff_sites = [i for i in range(APPEND_AT)
              if new_image[i] != dn2[i]]
expect_sites = set(range(DN2_BSSCLEAR_FILE, DN2_BSSCLEAR_FILE + 8))
if MOUNT_AT_BOOT:
    expect_sites |= {DN2_MASTER_JSR_FILE + 2, DN2_MASTER_JSR_FILE + 3,
                     DN2_MASTER_JSR_FILE + 4, DN2_MASTER_JSR_FILE + 5}
if MOUNT_AT_BOOT and FMT_CMD and fmtcmd_str_at is not None:
    pat3 = (b'\x48\x79' + be(0x4021acb1) + b'\x2f\x02\x4e\x94\x50\x8f'
            + b'\x4a\x80\x66\x4e')
    s3 = dn2.find(pat3)
    if s3 >= 0:
        expect_sites |= {s3 + 2, s3 + 3, s3 + 4, s3 + 5}          # pea op
        expect_sites |= set(range(s3 + len(pat3), s3 + len(pat3) + 16))  # h
    patm2 = (b'\x48\x79' + be(0x4021acb9) + b'\x2f\x02'
             + b'\x47\xf9' + be(0x4017e8a8) + b'\x4e\x93'
             + b'\x50\x8f\x4a\x80\x66\x4e')
    sm = dn2.find(patm2)
    if sm >= 0:
        expect_sites |= {sm + 2, sm + 3, sm + 4, sm + 5}           # pea op
        expect_sites |= set(range(sm + len(patm2), sm + len(patm2) + 18))  # h
bad = [i for i in diff_sites if i not in expect_sites]
if bad:
    fail.append(f'unexpected stock-byte changes at {[hex(i) for i in bad[:8]]}')
if set(expect_sites) - set(diff_sites):
    # expected sites whose NEW bytes coincidentally equal the stock bytes
    # (e.g. a nop landing on a nop) -- allowed; report only
    pass
rprint(f'stock-byte changes: {len(diff_sites)} (expected up to '
       f'{len(expect_sites)}, subset-check OK)')

# ------------------------------------------------------ 10. finalize ---
rprint(f'\nimage: {len(dn2)} -> {len(new_image)} B '
       f'(graft {G:#x}; DT2 ships {len(dt2)})')
for label, dt2addr in [('copyr_image', None), ('wrapper_run', None),
                       ('premount', DT2_PREMOUNT),
                       ('mount', DT2_MOUNT),
                       ('format424', 0x4015A424),
                       ('ekfs_format', 0x4015A164),
                       ('initializer', 0x4002CD6A),
                       ('manifest_check', 0x4002CCD0)]:
    if dt2addr is None:
        addr = {'copyr_image': IMAGE_STORE,
                'wrapper_run': wrapper_at}[label]
        rprint(f'  {label}: {addr:#x}')
    elif dt2addr in fn_new:
        rprint(f'  {label}: {fn_new[dt2addr]:#x} (was {dt2addr:#x})')
blob_addr = {n: blob_new[n][2] for n, _, _, _ in blob_layout}
for n, a in blob_addr.items():
    rprint(f'  blob {n}: {a:#x}')
rprint(f'  state block: {STATE_BASE:#x}..{state_end:#x}')
open('@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/candidate/graft_report.txt', 'w').write('\n'.join(report) + '\n')
# v14 debug: full old->new placement map (identifies fault PCs in graft)
with open('@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/candidate/fn_new_map.txt', 'w') as _m:
    for _e in sorted(fn_new):
        _m.write(f'{_e:#x} {fn_new[_e]:#x} {fns[_e][1]}\n')
# v15 debug: DT2-RAM -> graft-state map (identifies state slots)
with open('@WORKSPACE@/firmware/ghidra/storage-proof/combined-vfs-lru-candidate/candidate/ram_map.txt', 'w') as _r:
    for _t in sorted(ram_map):
        _r.write(f'{_t:#x} {ram_map[_t]:#x}\n')

if fail:
    print('\nBUILD FAILURES:')
    for f in fail:
        print('  ' + f)
    sys.exit(1)
if '--write' in sys.argv:
    open(OUT, 'wb').write(new_image)
    print(f'\nwrote {OUT} ({len(new_image)} bytes)')
else:
    print('\ndry-run OK (use --write to emit)')
