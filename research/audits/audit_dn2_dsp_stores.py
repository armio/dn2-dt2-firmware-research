#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Conservative SHARC indirect-store address/caller-clobber audit.

Method adapted from naturarum/dn2-cfw tools/dspsplice/store_trace.py,
commit eb1cfa7d4fc3cd0a77a430e9e9226c5d9cc10979 (GPL-2.0-or-later).
No upstream import, VM, binary changes or device access.

Input: generated SHARC assembly or address-prefixed mnemonic disassembly.
Optional ranges are [{"name": ..., "start": PC, "end": exclusive_PC}]; PCs
are SHARC short-word addresses, not byte offsets. Numeric JSON strings may
use 0x. This audits supplied text, NOT its correspondence to firmware bytes.

Only address-register dependencies are traced. A resolved dependency is not
a valid-address, bounds, alias, SIMD, ABI-conformance or real-time proof.
Branches, arbitrary labels, unknown instructions and unsupported call ABIs
remain unresolved. The default call contract is selcc's R0-R7 clobbered,
R8-R15 preserved, R0 returned. I/M/B/L/S/system registers have no implicit
call-preservation contract. Configure the ABI for other generated bridges.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

REG = re.compile(r"\b(?:[RFSIMBL](?:1[0-5]|[0-9])|ASTAT[XY]|MODE[12]|LCNTR|PCSTK)\b")
CALLER = frozenset(f"R{i}" for i in range(8))
PRESERVED = frozenset(f"R{i}" for i in range(8, 16))
MEM = re.compile(r"\b(?:DM|PM)\s*\(([^()]*)\)")
STORE = re.compile(r"\b(?:DM|PM)\s*\(([^()]*)\)\s*(?:\(LW\)\s*)?=(?!=)")
CALL = re.compile(r"^(?:CALL|CJUMP)\b")
CONTROL = re.compile(r"\b(?:IF|JUMP|RTS|RTI|RFRAME|DO|UNTIL|IDLE)\b")
EXPR_WORDS = set("DM PM LSHIFT ASHIFT BY AND OR XOR NOT ABS PASS FLOAT FIX TRUNC SAT CLIP MIN MAX NEG RECIPS RSQRTS FEXT FDEP SIGN COPYSIGN SCALE EXP MANT LW".split())


@dataclass
class Line:
    number: int
    text: str
    pc: int | None = None
    label: bool = False
    function: str = "<text>"
    effect: bool = False
    delay: bool = False


def registers(text):
    return {r.replace("F", "R", 1) if r.startswith("F") else r for r in REG.findall(text.upper())}


def _integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _parts(text):
    return [p.strip() for p in re.split(r",(?![^()]*\))", text.rstrip(";"))]


def _expr_known(text):
    if not text.strip() or '=' in text or re.search(r'[^A-Z0-9_+\-*/<>&|()~^.,\s]', text):
        return False
    text = REG.sub("", text)
    text = re.sub(r"\b0X[0-9A-F]+\b|\b\d+(?:\.\d+)?(?:E[+-]?\d+)?\b", "", text)
    return set(re.findall(r"[A-Z_][A-Z_0-9.]*", text)) <= EXPR_WORDS


def _semantics(text):
    """Per-destination inputs; parallel assignments see pre-instruction state."""
    defs = {}
    if CALL.match(text) or CONTROL.search(text):
        return defs, True
    for part in _parts(text):
        if part in ("NOP", "NOP (DB)") or re.fullmatch(r"COMP\([^()]+\)", part):
            continue
        if "=" not in part:
            return {}, False
        lhs, rhs = (p.strip() for p in part.split("=", 1))
        if not _expr_known(rhs):
            return {}, False
        if REG.fullmatch(lhs):
            defs[next(iter(registers(lhs)))] = registers(rhs)
        elif not re.fullmatch(r"(?:DM|PM)\s*\([^()]*\)\s*(?:\(LW\))?", lhs):
            return {}, False
        # DAG post-modification affects subsequent addresses. Pre-offset
        # DM(k,I) does not modify I; DM(I,M/k) does.
        for m in MEM.finditer(part):
            if not _expr_known(m.group(1)):
                return {}, False
            args = [a.strip() for a in m.group(1).split(",")]
            if len(args) == 2 and re.fullmatch(r"I(?:1[0-5]|[0-9])", args[0]):
                defs[args[0]] = registers(m.group(1))
    return defs, True


def _parse(text, ranges):
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), text, flags=re.S)
    lines, excluded = [], 0
    function = "<text>"
    for number, raw in enumerate(text.splitlines(), 1):
        raw = raw.split("//", 1)[0].strip()
        if not raw:
            continue
        pc = None
        addr = re.match(r"^(?:0x)?([0-9a-fA-F]{4,16})(?::|\s{2,})\s*(.*)$", raw)
        if addr:
            pc, raw = int(addr.group(1), 16), addr.group(2)
            raw = re.sub(r"^(?:(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{4}|[0-9a-fA-F]{8}|[0-9a-fA-F]{12})\s+)+", "", raw)
        if ranges:
            matches = [r for r in ranges if pc is not None and _integer(r['start']) <= pc < _integer(r['end'])]
            if not matches:
                excluded += 1
                continue
            function = matches[0]['name']
        for part in raw.split(";"):
            part = part.strip().upper()
            if not part or re.match(r"^\.(?:SECTION|GLOBAL|EXTERN|TYPE|SIZE|FILE|ALIGN)\b", part):
                continue
            label = bool(re.fullmatch(r"[A-Z_.$][A-Z_0-9.$]*:", part))
            if label and not ranges and not part.startswith(".L"):
                function = part[:-1]
            lines.append(Line(number, part, pc, label, function))
    # Calls act AFTER their two delay slots. Treat slot stores before callee
    # execution; never accidentally prove an address defined there survives it.
    output, delayed = [], None
    for item in lines:
        if delayed and not item.label:
            item.delay = True
        output.append(item)
        if delayed and not item.label:
            call, left = delayed
            delayed = (call, left - 1)
            if left == 1:
                output.append(Line(call.number, call.text, call.pc, function=call.function, effect=True))
                delayed = None
        if CALL.match(item.text):
            if "(DB)" in item.text:
                if delayed:
                    output.append(Line(item.number, "UNSUPPORTED NESTED DELAYED CALL", item.pc, function=item.function))
                delayed = (item, 2)
            else:
                output.append(Line(item.number, item.text, item.pc, function=item.function, effect=True))
    if delayed:
        output.append(Line(delayed[0].number, "UNRESOLVED TRUNCATED DELAYED CALL"))
    return output, excluded


def _trace(lines, index, need, *, entry, preserved, caller, returns):
    trail, origins = [], []
    for j in range(index - 1, -1, -1):
        if not need:
            break
        line = lines[j]
        if line.effect:
            bad = need & caller - returns
            if bad:
                return "caller_clobber", f"address needs caller-clobbered {sorted(bad)} across call", trail, sorted(need), line.number
            returned = need & returns
            if returned:
                origins.append("call return " + ",".join(sorted(returned)))
                need -= returned
            unknown = need - preserved
            if unknown:
                return "unresolved", f"call preservation unknown for {sorted(unknown)}", trail, sorted(need), line.number
            trail.append(dict(line=line.number, instruction=line.text, preserved=sorted(need)))
            continue
        if line.label:
            # Recognize only a selcc local continuation immediately after a
            # real call effect. Arbitrary labels remain possible merge points.
            if line.text.startswith(".L_RET_") and j and lines[j - 1].effect:
                target = line.text[:-1]
                if not any(CONTROL.search(x.text) and target in x.text for x in lines):
                    continue
            if j == 0 and need <= entry:
                origins.append("declared entry registers " + ",".join(sorted(need)))
                need.clear()
                break
            return "unresolved", f"control-flow label {line.text}", trail, sorted(need), line.number
        if CALL.match(line.text):
            continue  # actual call effects are represented separately
        if CONTROL.search(line.text):
            return "unresolved", "control-flow boundary", trail, sorted(need), line.number
        defs, known = _semantics(line.text)
        if not known:
            return "unresolved", "unsupported instruction semantics", trail, sorted(need), line.number
        hits = need & defs.keys()
        if hits:
            required = set().union(*(defs[r] for r in hits))
            # The contents of a literal address or declared stack slot are
            # origins, not a claim about pointer validity or memory ownership.
            need = (need - hits) | required
            trail.append(dict(line=line.number, instruction=line.text, traced=sorted(hits), inputs=sorted(required)))
    if need <= entry:
        if need:
            origins.append("declared entry registers " + ",".join(sorted(need)))
        return "resolved_dependency", "; ".join(origins) or "address dependency defined within straight-line block", trail, [], None
    return "unresolved", "input boundary without declared register origins", trail, sorted(need), None


def audit_text(text, *, source="<memory>", ranges=None, entry_registers=(),
               preserved_registers=PRESERVED, caller_clobbered=CALLER,
               return_registers=("R0",)):
    """Return JSON-serializable findings and honest source-only coverage.

    Register lists are explicit assumptions, not facts inferred from firmware.
    Ranges may select functions from mnemonic disassembly; overlapping/empty
    ranges are rejected. Unknown outside-range code is explicitly excluded.
    """
    ranges = ranges or []
    for i, r in enumerate(ranges):
        if not isinstance(r['name'], str) or _integer(r['end']) <= _integer(r['start']):
            raise ValueError("invalid function range")
        if any(_integer(r['start']) < _integer(q['end']) and _integer(q['start']) < _integer(r['end']) for q in ranges[:i]):
            raise ValueError("overlapping function ranges")
    def regset(values):
        if any(not REG.fullmatch(v.upper()) for v in values):
            raise ValueError("invalid ABI register")
        return registers(" ".join(values))
    entry, preserved, caller, returns = map(regset, (entry_registers, preserved_registers, caller_clobbered, return_registers))
    if preserved & caller or not returns <= caller:
        raise ValueError("contradictory call contract")
    lines, excluded = _parse(text, ranges)
    findings, opaque, controls = [], [], []
    direct = 0
    for index, line in enumerate(lines):
        if line.label or line.effect:
            continue
        defs, known = _semantics(line.text)
        if not known:
            opaque.append(dict(line=line.number, pc=line.pc, instruction=line.text))
        if CONTROL.search(line.text) or CALL.match(line.text):
            controls.append(dict(line=line.number, pc=line.pc, instruction=line.text))
        for store in STORE.finditer(line.text):
            need = registers(store.group(1))
            if not need:
                direct += 1
                continue
            # Do not walk into a preceding user-declared function range.
            start = index
            while start and lines[start - 1].function == line.function:
                start -= 1
            if not known or CONTROL.search(line.text):
                result = ("unresolved", "conditional or unsupported store instruction", [], sorted(need), line.number)
            else:
                result = _trace(lines[start:index + 1], index - start, need, entry=entry,
                                preserved=preserved, caller=caller, returns=returns)
            verdict, reason, trace, remaining, boundary = result
            findings.append(dict(line=line.number, pc=line.pc, function=line.function,
                                 instruction=line.text, address=store.group(1), verdict=verdict,
                                 reason=reason, remaining_registers=remaining,
                                 boundary_line=boundary, trace=trace, before_call=line.delay))
    counts = Counter(f['verdict'] for f in findings)
    selected = sum(not l.label and not l.effect for l in lines)
    empty_ranges = [r['name'] for r in ranges if not any(
        not l.label and not l.effect and l.function == r['name'] for l in lines)]
    unresolved_control = [c for c in controls if not CALL.match(c['instruction'])]
    status = ("hazards" if counts['caller_clobber'] else "incomplete" if
              counts['unresolved'] or opaque or unresolved_control or empty_ranges or not selected else "resolved_for_scope")
    return dict(schema_version=1, source=source, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                status=status, binary_bound=False,
                coverage=dict(selected_instructions=selected, excluded_lines=excluded,
                              indirect_stores=len(findings), direct_stores_not_traced=direct,
                              resolved_dependency=counts['resolved_dependency'], caller_clobber=counts['caller_clobber'],
                              unresolved_stores=counts['unresolved'], unsupported_instructions=len(opaque),
                              control_instructions=len(controls), unresolved_control_flow=len(unresolved_control),
                              function_ranges=ranges, empty_ranges=empty_ranges),
                abi_assumptions=dict(entry_registers=sorted(entry), caller_clobbered=sorted(caller),
                                     preserved_registers=sorted(preserved), return_registers=sorted(returns)),
                findings=findings, unsupported=opaque, control_flow=controls,
                limitations=["Source/disassembly text only; no firmware-byte binding or full-program coverage.",
                             "Resolved means address dependency explained, not address validity or bounds safety.",
                             "Straight-line slicing only; branches/loops/merges and unknown semantics are unresolved.",
                             "Call preservation and incoming register origins are caller-supplied assumptions.",
                             "Does not prove SIMD partner, circular DAG, alias, interrupt or timing safety."])


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('sources', type=Path, nargs='+')
    p.add_argument('--ranges', type=Path, help='JSON function ranges for address-prefixed disassembly')
    p.add_argument('--entry-registers', default='', help='comma-separated incoming address origins, e.g. I6,I7,M7')
    p.add_argument('--preserved-registers', default=','.join(sorted(PRESERVED)))
    p.add_argument('--caller-clobbered', default=','.join(sorted(CALLER)))
    p.add_argument('--return-registers', default='R0')
    p.add_argument('--out', type=Path)
    a = p.parse_args(argv)
    inputs = [*a.sources, *([a.ranges] if a.ranges else [])]
    if a.out and any(a.out.resolve() == path.resolve() or
                     (a.out.exists() and path.exists() and a.out.samefile(path)) for path in inputs):
        p.error('output must not overwrite an input source or ranges file')
    lists = {key: [x.strip() for x in getattr(a, key).split(',') if x.strip()]
             for key in ('entry_registers', 'preserved_registers', 'caller_clobbered', 'return_registers')}
    try:
        ranges = json.loads(a.ranges.read_text()) if a.ranges else None
        reports = [audit_text(path.read_text(), source=str(path), ranges=ranges, **lists) for path in a.sources]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.error(str(exc))
    result = dict(schema_version=1, reports=reports)
    rendered = json.dumps(result, indent=2) + '\n'
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(rendered)
    else:
        print(rendered, end='')
    return 1 if any(r['status'] == 'hazards' for r in reports) else 2 if any(r['status'] == 'incomplete' for r in reports) else 0


if __name__ == '__main__':
    raise SystemExit(main())
