"""Fail-closed memory observation around the ONESHOT adapter and donor render.

    gate = install(dk, final_section7, bank_entries=entries)
    gate.begin("block-0")       # hook at the adapter entry, before its first step
    gate.end()                  # hook at TYPE5_RESUME, before stock resumes
    gate.assert_clean(require_pcm_reads=True)
    report = gate.report()

The caller must also check that execution returned normally. This gate does not
model interrupts, DMA, instruction validity, or silicon timing. It audits only
explicitly bracketed execution, using the final image's loaded bytes and this
path's writes. Ordinary PM transfers unsupported by the runner fail the gate;
its concrete combined-PX 48-bit reads are checked separately. No broad stock
initializer exemptions are used. A raised MemoryGateError gives a nonzero exit
when not caught by the integrating command.
"""

from __future__ import annotations

import collections
import sys

from dnfw.image import bootstream
from dnfw.oneshot import bank

ALIAS = 0x28000000
# Physical byte domains, excluding the 16 KiB caches in L1 blocks 1-3.
L1 = ((0x240000, 0x270000), (0x2C0000, 0x2EC000),
      (0x300000, 0x31C000), (0x380000, 0x39C000))
CACHES = ((0x2EC000, 0x2F0000), (0x31C000, 0x320000), (0x39C000, 0x3A0000))
L2 = (0x20000000, 0x20100000)
DDR = (0x80000000, 0xA0000000)
MMR = ((0x30000, 0x40000), (0x31000000, 0x32000000), (0x3000000, 0x3100000))
STACK = (0x2FFE00, 0x300000)
UNPACK_LOCAL = (0x284800, 0x284840)
# Only the transplanted render's short-word DM loads are sample reads. Helpers
# use normal-word coefficient/state loads; adapter short/byte fields are separate.
PCM_CODE = ((0x185000, 0x185465),)
PX_NW = (0xE0000, 0xE8000)
PX_SW_BASE = 0x1C0000


class MemoryGateError(RuntimeError):
    pass


def _integer(value):
    result = getattr(value, "value", value)
    return result if isinstance(result, int) and not isinstance(result, bool) else None


def _inside(start, width, domains):
    return any(lo <= start and start + width <= hi for lo, hi in domains)


def _overlap(start, width, domain):
    lo, hi = domain
    return start < hi and lo < start + width


def _physical(address):
    return address - ALIAS if ALIAS <= address < ALIAS + 0x3A0000 else address


class MemoryGate:
    def __init__(self, stream: bytes, *, bank_entries, pcm_code_spans=PCM_CODE):
        if not bootstream.walk(stream).complete:
            raise ValueError("memory gate requires a complete final section-7 boot stream")
        self.loaded = tuple((at, at + len(data)) for at, data in bootstream.load_regions(stream))
        self.pcm_code_spans = tuple(pcm_code_spans)
        self.active = False
        self.window = None
        self.windows_started = self.windows_completed = 0
        self.counts = collections.Counter()
        self.violations = []
        self._seen = set()
        self._px_reads = set()
        self.samples = []
        if not bank_entries:
            raise ValueError("bank_entries must describe the actual guarded sample bank")
        for slot, entry in enumerate(bank_entries):
            pointer, length = _integer(entry["pointer"]), _integer(entry["length"])
            if pointer is None or length is None or pointer % 4 or length <= 0:
                raise ValueError(f"invalid bank entry {slot}")
            logical_end = pointer + bank.BYTES_PER_SAMPLE * length
            guard_end = logical_end + (-length * bank.BYTES_PER_SAMPLE % 4) + bank.GUARD_BYTES
            guard_start = pointer - bank.GUARD_BYTES
            if not _inside(guard_start, guard_end - guard_start, L1):
                raise ValueError(f"sample {slot} guards leave usable L1 memory")
            if not self._loaded(ALIAS + guard_start, guard_end - guard_start):
                raise ValueError(f"sample {slot} PCM and guards are not fully loaded")
            self.samples.append({"slot": slot, "pointer": pointer, "length": length,
                                 "guard_start": guard_start, "logical_end": logical_end,
                                 "guard_end": guard_end, "reads": collections.Counter()})

    def _loaded(self, address, width):
        # Consecutive loader blocks may jointly cover an access.
        return all(any(lo <= b < hi for lo, hi in self.loaded)
                   for b in range(address, address + width))

    def _flag(self, kind, state, address=None, width=0, detail=""):
        pc = getattr(state, "pc_sw", None)
        key = (kind, pc, address, width, self.window)
        self.counts["violation_accesses"] += 1
        if key not in self._seen:
            self._seen.add(key)
            self.violations.append({"kind": kind, "pc": pc, "address": address,
                                    "width": width, "window": self.window, "detail": detail})

    def begin(self, name="adapter"):
        if self.active:
            raise MemoryGateError("memory gate window already open")
        self.active, self.window = True, name
        self.windows_started += 1
        self._px_reads.clear()

    def end(self):
        if not self.active:
            raise MemoryGateError("memory gate window is not open")
        self.windows_completed += 1
        self.active = False
        self._px_reads.clear()

    @staticmethod
    def _canonical(state, address):
        # Match digikit memory._canonical_dm_address's width-independent family
        # choice. Validation must also see missing reads that its explicit model
        # would otherwise serve as zero.
        backing = getattr(state, "concrete", None)
        direct = address in state.overlay or (backing is not None and backing.read(address, 1) is not None)
        return ALIAS + address if not direct and 0 <= address < ALIAS else address

    def _check_range(self, state, canonical, width, *, write, overlay_ok=True, alignment=None):
        physical = _physical(canonical)
        domains = (*L1, L2, DDR, STACK, UNPACK_LOCAL)
        if not _inside(physical, width, domains):
            kind = "cache" if any(_overlap(physical, width, d) for d in CACHES) else "outside"
            self._flag(kind, state, physical, width, "entire access must fit one safe byte domain")
            return
        align = alignment if alignment is not None else min(width, 4)
        if physical % align:
            self._flag("misaligned", state, physical, width)
        if not write:
            for b in range(canonical, canonical + width):
                if not (overlay_ok and b in state.overlay) and not self._loaded(b, 1):
                    self._flag("unwritten", state, physical, width, f"byte {b:#x} was neither loaded nor written")
                    break

    def _pcm_read(self, state, physical, width):
        pc = getattr(state, "pc_sw", None)
        is_pcm = width == 2 and isinstance(pc, int) and _inside(pc, 1, self.pcm_code_spans)
        if not is_pcm:
            return
        self.counts["pcm_reads"] += 1
        for sample in self.samples:
            if _inside(physical, width, ((sample["guard_start"], sample["guard_end"]),)):
                sample["reads"]["total"] += 1
                if physical + width <= sample["pointer"]:
                    kind = "leading_guard"
                elif physical >= sample["logical_end"]:
                    kind = "trailing_guard"
                elif sample["pointer"] <= physical and physical + width <= sample["logical_end"]:
                    kind = "logical_pcm"
                else:
                    kind = "logical_boundary"
                sample["reads"][kind] += 1
                return
        self._flag("pcm_outside_guards", state, physical, width)

    def check_dm(self, state, address, width, *, write=False):
        if not self.active:
            return
        self.counts["dm_writes" if write else "dm_reads"] += 1
        raw = _integer(address)
        if raw is None:
            self._flag("unresolved_address", state, detail="DM address is not concrete")
            return
        if width not in (1, 2, 4, 8):
            self._flag("unsupported_width", state, raw, width)
            return
        if _inside(raw, width, MMR):
            if width != 4 or (not write and raw not in getattr(state, "mmrs", {})):
                self._flag("unmodeled_mmr", state, raw, width)
            return
        canonical = self._canonical(state, raw)
        self._check_range(state, canonical, width, write=write)
        if not write:
            self._pcm_read(state, _physical(canonical), width)
        elif any(_overlap(_physical(canonical), width, (s["guard_start"], s["guard_end"]))
                 for s in self.samples):
            self._flag("bank_write", state, _physical(canonical), width, "PCM and guards are read-only")

    def check_fetch(self, runner, pc, insn):
        if not self.active:
            return
        self.counts["instruction_fetches"] += 1
        pc, width = _integer(pc), getattr(insn, "length_bytes", None)
        if pc is None or width not in (2, 4, 6):
            self._flag("invalid_fetch", runner.state, pc, width or 0)
            return
        primary = ALIAS + 2 * pc
        if self._loaded(primary, width):
            canonical = primary
        elif pc >= 0xB80000:
            canonical = L2[0] + 2 * (pc - 0xB80000)
        else:
            canonical = primary
        physical = _physical(canonical)
        if not _inside(physical, width, (*L1, L2)):
            self._flag("fetch_outside_code", runner.state, physical, width)
        if not self._loaded(canonical, width) or runner.data.read_sw(pc, width) is None:
            self._flag("fetch_unloaded", runner.state, physical, width)

    def check_px48(self, state, address):
        if not self.active:
            return
        raw = _integer(address)
        self.counts["px48_reads"] += 1
        if raw is None or not _inside(raw, 1, (PX_NW,)):
            self._flag("unsupported_px48", state, raw, 6)
            return
        canonical = ALIAS + 2 * PX_SW_BASE + 6 * (raw - PX_NW[0])
        self._check_range(state, canonical, 6, write=False, overlay_ok=False, alignment=2)

    def check_event(self, state, action, extra):
        if not self.active or extra.get("space") != "PM" or action not in ("load", "store"):
            return
        self.counts["pm_transfers"] += 1
        raw = _integer(extra.get("address"))
        key = (id(state), getattr(state, "pc_sw", None), raw)
        if action == "load" and key in self._px_reads:
            self._px_reads.remove(key)
            return
        self._flag("unsupported_pm", state, raw, detail="runner did not perform a checked concrete PM transfer")

    def assert_clean(self, *, require_pcm_reads=False):
        if self.active:
            raise MemoryGateError("memory gate window never reached its resume hook")
        if not self.windows_started or self.windows_started != self.windows_completed:
            raise MemoryGateError("no completed memory gate execution window")
        if self.violations:
            first = self.violations[0]
            raise MemoryGateError(f"{len(self.violations)} memory violations; first: {first}")
        if require_pcm_reads and not self.counts["pcm_reads"]:
            raise MemoryGateError("no PCM reads were observed")

    def report(self):
        return {"active": self.active, "windows_started": self.windows_started,
                "windows_completed": self.windows_completed, "counts": dict(self.counts),
                "violations": list(self.violations),
                "samples": [{**s, "reads": dict(s["reads"])} for s in self.samples],
                "harness_stack": STACK, "harness_unpack_local": UNPACK_LOCAL,
                "limits": "bracketed execution only; no interrupts, DMA, encoding or timing model; unsupported PM fails"}


def _patch_bindings(original, replacement):
    replacement.__oneshot_gate_original__ = original
    for module in list(sys.modules.values()):
        if module is None:
            continue
        for name, current in tuple(vars(module).items()):
            if current is original or getattr(current, "__oneshot_gate_original__", None) is original:
                setattr(module, name, replacement)


def install(dk, stream: bytes, *, bank_entries, pcm_code_spans=PCM_CODE):
    """Install process-wide hooks; return an initially inactive MemoryGate.

    Import/bind digikit and DN2 fixups first. Installing another gate replaces
    these hooks; do not interleave two images in one active window. Execution
    halts still need a separate caller verdict. assert_clean() is mandatory.
    """
    import sharc_core.memory as memory
    import sharc_core.state as state_module

    gate = MemoryGate(stream, bank_entries=bank_entries, pcm_code_spans=pcm_code_spans)

    def original(fn):
        return getattr(fn, "__oneshot_gate_original__", fn)

    read, write = original(memory._dm_read), original(memory._dm_write)
    px48, event = original(memory._read_px48), original(state_module._event)
    decode = original(dk.run.Runner._decode)

    def checked_read(state, address, width, *args, **kwargs):
        gate.check_dm(state, address, width)
        result = read(state, address, width, *args, **kwargs)
        if gate.active and result is None:
            gate._flag("unmodeled_read", state, _integer(address), width)
        return result

    def checked_write(state, address, width, value):
        gate.check_dm(state, address, width, write=True)
        result = write(state, address, width, value)
        if gate.active and not result:
            gate._flag("unmodeled_write", state, _integer(address), width)
        return result

    def checked_px48(state, address):
        gate.check_px48(state, address)
        result = px48(state, address)
        if gate.active and result is not None:
            gate._px_reads.add((id(state), getattr(state, "pc_sw", None), _integer(address)))
        elif gate.active:
            gate._flag("unmodeled_px48", state, _integer(address), 6)
        return result

    def checked_event(state, insn, action, **extra):
        gate.check_event(state, action, extra)
        return event(state, insn, action, **extra)

    def checked_decode(runner, pc):
        insn = decode(runner, pc)
        gate.check_fetch(runner, pc, insn)
        return insn

    for old, new in ((read, checked_read), (write, checked_write), (px48, checked_px48), (event, checked_event)):
        _patch_bindings(old, new)
    checked_decode.__oneshot_gate_original__ = decode
    dk.run.Runner._decode = checked_decode
    return gate
