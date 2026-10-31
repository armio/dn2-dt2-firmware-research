#!/usr/bin/env python3
"""Compile donor Machine controls for the forthcoming expanded DN2 table.

Produces a relocatable component, not a flash image. The DN2's parameter
accessors need the companion integration before these new IDs can be used.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/ghidra/oneshot-proof/v7-source/src'))
from dnfw.transplant import cfplan, cfspec as C, oneshot_cf

EXTRA = (
    C.FormatterTwin('slice_length', 0x400e1656, 0x400e30fe, 14),
    C.FormatterTwin('bars', 0x400e1742, 0x400e31ea, 34, ((14, 'str32'),)),
    C.FormatterTwin('segment', 0x400e1764, 0x400e320c, 38, ((18, 'str32'),)),
    C.FormatterTwin('slice', 0x400e17b4, 0x400e325c, 56,
                    ((16, 'str32'), (38, 'str32'))),
    C.FormatterTwin('grid', 0x400e17ec, 0x400e3294, 34, ((14, 'str32'),)),
)
SHA = lambda b: hashlib.sha256(b).hexdigest()
U32 = lambda b, off: struct.unpack_from('>I', b, off)[0]
# Complete native record groups include controls absent from the eight-knob
# page: SLOT/BANK, REPITCH TUNE and SLICE CFADE. ONESHOT's visible records
# already exist in the recipient, but its browser records do not.
RECORD_GROUPS = {'GRID': range(237,246), 'REPITCH': range(228,237),
                 'SLICE': range(246,255), 'WERP': range(210,219),
                 'STRETCH': range(219,228), 'ONESHOT': range(200,202)}
DONOR_RECORD0 = 0x4020f18c


def compile_controls(donor, recipient, inventory, base, first_entry):
    if SHA(donor) != inventory['dt2_main_sha256']:
        raise ValueError('Donor identity mismatch')
    if base % 4 or first_entry < 321:
        raise ValueError('Use an aligned component base and new, non-stock IDs')
    twins = (*oneshot_cf.TWINS, *EXTRA)
    checked = cfplan.CfPlan(oneshot_cf.SPEC, donor, recipient)
    for twin in twins:
        cfplan._check_twin(checked, twin)
    if not checked.ok:
        raise ValueError('; '.join(checked.refusals))
    twin_map = {f.donor: f.recipient for f in twins}
    # Reserve records and descriptors before allocating names. No native
    # parameter semantics (slots, ranges, defaults, flags) are rewritten.
    count = sum(len(ids) for ids in RECORD_GROUPS.values())
    descriptor_offset = count * C.RECORD
    blob = bytearray(descriptor_offset + 44 * len(inventory['machines']))
    strings = {}

    def string(text):
        data = text.encode('ascii') + b'\0'
        if data not in strings:
            strings[data] = base + len(blob)
            blob.extend(data)
        return strings[data]

    def donor_string(ptr):
        value = cfplan._string(donor, ptr)
        if value is None:
            raise ValueError(f'Invalid donor string {ptr:#x}')
        return value

    machines, patches, n = [], [], 0
    groups = [*inventory['machines'],
              {'machine':'ONESHOT', 'type':0, 'selector':0, 'parameters':[]}]
    for mi, machine in enumerate(groups):
        mapped, rows = {}, []
        visible = {p['id']:p for p in machine['parameters'] if p is not None}
        for donor_id in RECORD_GROUPS[machine['machine']]:
            at = DONOR_RECORD0 + donor_id*C.RECORD - cfplan.BASE
            original = donor[at:at+C.RECORD]
            if donor_id in visible:
                p = visible[donor_id]
                if SHA(original) != p['sha256'] or at != int(p['address'],16)-cfplan.BASE:
                    raise ValueError(f"Changed {machine['machine']} record {donor_id}")
            assert len(original) == C.RECORD
            assert U32(original,C.PAGE) == machine['type']
            rec = bytearray(original)
            entry = first_entry + n
            replacements = {C.PAGE: 1, C.CC: C.UNSET, C.NRPN: C.UNSET,
                            C.ORDINAL: entry,
                            C.FORMATTER: twin_map[U32(original, C.FORMATTER)],
                            C.SUFFIX: string(donor_string(U32(original, C.SUFFIX)))}
            for off in (C.LONG_NAME, C.PAGE_LABEL, C.SHORT_NAME):
                replacements[off] = string(donor_string(U32(original, off)))
            for off, value in replacements.items():
                struct.pack_into('>I', rec, off, value)
            # Preserve every byte outside the enumerated identity/address adaptations.
            allowed = {i for off in replacements for i in range(off, off+4)}
            assert all(a == b or i in allowed for i,(a,b) in enumerate(zip(original, rec)))
            blob[n*C.RECORD:(n+1)*C.RECORD] = rec
            mapped[donor_id] = entry
            rows.append({'donor_id':donor_id, 'entry':entry, 'slot':U32(original,C.SLOT),
                         'record_va':hex(base+n*C.RECORD),
                         'short':donor_string(U32(original,C.SHORT_NAME)),
                         'visible':donor_id in visible, 'donor_record_sha256':SHA(original)})
            patches.append({'machine':machine['machine'], 'entry':entry,
                            'operands':{hex(k):hex(v) for k,v in replacements.items()}})
            n += 1
        entries = [mapped[p['id']] if p else 0 for p in machine['parameters']]
        if not entries:
            machines.append({'machine':machine['machine'], 'donor_type':machine['type'],
                             'descriptor_va':None, 'page_entries':[], 'records':rows,
                             'note':'Browser records only; existing ONESHOT descriptor retained'})
            continue
        desc = descriptor_offset + 44*mi
        # SOURCE/ONESHOT descriptor tag 10 belongs to the shared source page.
        # Machine-specific title and eight native knob positions come from
        # the actual donor parameter records, including all blank controls.
        title = string(machine['machine'])
        struct.pack_into('>11I',blob,desc,title,string(''),*entries,10)
        machines.append({'machine':machine['machine'], 'donor_type':machine['type'],
                         'dsp_selector':machine['selector'], 'descriptor_va':hex(base+desc),
                         'page_entries':entries, 'records':rows})
    blob.extend(bytes((-len(blob))%4))
    return bytes(blob), {'donor_sha256':SHA(donor),'recipient_sha256':SHA(recipient),
                        'base':hex(base),'first_entry':first_entry,'record_count':count,
                        'machines':machines,'patches':patches,'formatter_checks':checked.checks,
                        'component_sha256':SHA(blob),'bytes':len(blob),'flash_ready':False,
                        'remaining_integration':['Integrate expanded parameter accessors and companion routing',
                          'Machine registration, ownership, defaults and persistence',
                          'DSP dispatch and native GUI/browser integration'],
                        'descriptor_note':'Native knob order and tag retained; titles use Machine names. Full SourcePageView is a separate port.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=lambda s:int(s,0),default=0x46910000)
    p.add_argument('--first-entry',type=int,default=321)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    donor=(ROOT/'output/dn2-research/dt2-donor-main/section_3_MAIN_OS.bin/section_3_MAIN_OS.bin').read_bytes()
    recipient=(ROOT/'output/dn2-research/oneshot-drive-v3-m3b-rev3-stackfix-20261009/main-os.bin').read_bytes()
    inventory=json.loads((ROOT/'output/dn2-research/oneshot-native-machine-inventory-20261008/inventory.json').read_text())
    blob,report=compile_controls(donor,recipient,inventory,args.base,args.first_entry)
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'controls.bin').write_bytes(blob)
    (args.output/'controls.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('record_count','bytes','component_sha256','flash_ready')},indent=2))


if __name__=='__main__':
    main()
