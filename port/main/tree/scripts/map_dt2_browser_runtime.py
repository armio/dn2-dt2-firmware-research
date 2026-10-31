#!/usr/bin/env python3
"""Find complete native DN2 twins for SampleListView's shared dependencies.

Only decoded absolute address operands are masked. Local branch encodings,
field offsets, stack adjustments and all other bytes must match. A unique
match is evidence of a code twin, not proof of object/global compatibility.
"""
from pathlib import Path
import collections
import hashlib
import json
import re
import struct
import sys

import stage_dt2_sample_browser as S

BASE = S.BASE
RECIPIENT = S.ROOT/'firmware/dn2-1.11/section_3_MAIN_OS.bin'
OUT = S.ROOT/'output/dn2-research/dt2-browser-runtime-map-20261009'
BRANCHES = {'bra','bhi','bls','bcc','bcs','bne','beq','bvc','bvs','bpl','bmi','bge','blt','bgt','ble'}


def function(raw, entry):
    """Reachable instruction graph through local branches, stopping at tails.

    Indirect dispatch and backward branches below the entry require explicit
    extents rather than guessed function boundaries. No calls are descended.
    """
    todo, decoded = [entry], {}
    while todo:
        pc = todo.pop()
        if pc in decoded:
            continue
        if not entry <= pc < entry+8192:
            raise ValueError(f'nonlocal branch at {pc:#x}')
        row = next(S.disasm(raw,BASE,pc,pc+16))
        at,hx,mn,ops = row
        op = mn.split('.')[0]
        if op == '.word' or mn == '.word':
            raise ValueError(f'undecoded at {pc:#x}')
        decoded[pc] = row
        end = pc+len(bytes.fromhex(hx))
        if op in ('rts','rte'):
            continue
        if op == 'jmp':
            if 'pc,' in ops:
                raise ValueError(f'indirect dispatch at {pc:#x}')
            continue  # tail call; operand is included in twin matching
        if op in BRANCHES or op.startswith('db'):
            dest = re.search(r'\$([0-9a-f]{8})',ops)
            if not dest:
                raise ValueError(f'unknown branch at {pc:#x}')
            target = int(dest[1],16)
            # An unconditional branch below the entry is a sibling tail call.
            # Its relative encoding still has to match in the recipient.
            if op == 'bra' and target < entry:
                continue
            todo.append(target)
            if op == 'bra':
                continue
        todo.append(end)
    rows = sorted(decoded.values())
    end = max(a+len(bytes.fromhex(h)) for a,h,_,_ in rows)
    # Reject unvisited gaps: a complete contiguous function must be proved.
    cursor = entry
    for a,h,_,_ in rows:
        if a != cursor:
            raise ValueError(f'unvisited bytes at {cursor:#x}')
        cursor += len(bytes.fromhex(h))
    return end, rows


def operands(rows, extra_ranges=()):
    for a,h,m,o in rows:
        code = bytes.fromhex(h)
        for match in re.finditer(r'\$([0-9a-f]{8})',o):
            value = int(match[1],16)
            if 0x40000000 <= value < 0x48000000 or any(lo<=value<hi for lo,hi in extra_ranges):
                off = code.find(struct.pack('>I',value))
                if off >= 0:
                    yield a+off,value,m,o


def main():
    donor,recipient = S.DONOR.read_bytes(),RECIPIENT.read_bytes()
    assert hashlib.sha256(donor).hexdigest() == S.SHA
    OUT.mkdir(exist_ok=True)
    # Entire browser class, including lambda managers and native list builder.
    rows = list(S.disasm(donor,BASE,0x4001dd9c,0x4001ebf8))
    rows += list(S.disasm(donor,BASE,0x4001ec16,0x4001efac))
    refs = list(operands(rows))
    # Include the class's main, secondary and embedded model vtables.
    for at in range(0x401ee4b0,0x401ee5e0,4):
        val = struct.unpack_from('>I',donor,at-BASE)[0]
        if 0x40000400 <= val < 0x401ed000:
            refs.append((at,val,'vtable',''))
    todo = sorted({v for _,v,_,_ in refs if 0x40020000 <= v < 0x401ed000} | {0x40061464})
    results, data_map = [],collections.defaultdict(set)
    for entry in todo:
        row = dict(donor=hex(entry))
        try:
            end, instructions = function(donor,entry)
            blob = donor[entry-BASE:end-BASE]
            mask = bytearray(b'\1'*len(blob))
            ops = list(operands(instructions))
            for at,_,_,_ in ops:
                mask[at-entry:at-entry+4] = bytes(4)
            pattern = b''.join(re.escape(bytes([b])) if keep else b'.' for b,keep in zip(blob,mask))
            hits = [m.start() for m in re.finditer(pattern,recipient,re.DOTALL) if m.start()%2==0]
            row.update(end=hex(end),bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest(),
                       dn2_twins=[hex(BASE+x) for x in hits])
            if len(hits)==1:
                pairs=[]
                for at,old,mn,op in ops:
                    new=struct.unpack_from('>I',recipient,hits[0]+at-entry)[0]
                    pairs.append(dict(operand=hex(at),donor=hex(old),dn2=hex(new),mnemonic=mn))
                    data_map[old].add(new)
                row['operands']=pairs
            (OUT/f'{entry:08x}.asm').write_text('\n'.join(f'{a:08x} {h:24s} {m:10s} {o}' for a,h,m,o in instructions)+'\n')
        except ValueError as exc:
            row['needs_explicit_extent']=str(exc)
        results.append(row)
    report=dict(donor_sha256=S.SHA,recipient=str(RECIPIENT),
                recipient_sha256=hashlib.sha256(recipient).hexdigest(),functions=results,
                inferred_operand_map={hex(k):[hex(x) for x in sorted(v)] for k,v in sorted(data_map.items())},
                limits=['No inferred operand mapping is automatically installed',
                        'Matching code does not prove recipient object or global lifetime compatibility'])
    (OUT/'map.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(functions=len(results),unique_twins=sum(len(x.get('dn2_twins',[]))==1 for x in results),
                          no_twins=[x['donor'] for x in results if x.get('dn2_twins')==[]],
                          explicit=[x for x in results if 'needs_explicit_extent' in x]),indent=2))


if __name__=='__main__':
    main()
