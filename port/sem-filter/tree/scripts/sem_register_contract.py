"""Fail-closed register-write census for the scalar SEM adapter and kernel."""
from collections import Counter

import build_dt2_dsp_l1_code_fix as F


def writes(k, ins):
    """Decode destinations, including address updates and CJUMP frame setup.

    Only the qualified 48-bit forms are accepted. PEYEN must already be clear;
    SIMD companion writes are deliberately outside this scalar contract.
    """
    st, f, kind = k.st, dict(ins.fields), ins.type_name
    if ins.kind != 'confident' or ins.length_bytes != 6:
        raise ValueError('SEM register audit requires decoded 48-bit instructions')
    field = lambda name: st._field(f, name)
    changed = set()

    def ureg(code):
        name = st.UREG_NAMES[code]
        changed.add(name)
        if name.startswith('B') and name[1:].isdigit():
            changed.add('I'+name[1:])  # Hardware base writes also replace I.

    def compute():
        if 'compute' in f:
            value = f['compute']
            f['compute[22:16]'], f['compute[15:0]'] = value >> 16, value & 0xffff
        result = st._compute(f, False, {}, approx_recips=True)
        if result is None:
            return
        target, _, operation, _ = result
        changed.add('ASTATX')
        if operation in ('compare', 'bit-test', 'float-compare'):
            return
        for item in target if isinstance(target, tuple) else (target,):
            if not isinstance(item, int) or not 0 <= item < 16:
                raise ValueError(f'unsupported SEM compute destination: {item}')
            ureg(item)

    if kind in ('2a', '5a_move', '3a', '4a', '9a_abs'):
        compute()
    if kind == '2a':
        pass
    elif kind == '5a_move':
        ureg(field('dstureg'))
    elif kind == '17a':
        ureg(field('ureg'))
    elif kind in ('14a', '15a', '3a'):
        if field('l'):
            raise ValueError('SEM register audit does not permit paired memory transfers')
        if not field('d'):
            ureg(field('ureg'))
        if kind == '3a' and field('u'):
            ureg(16 + field('i') + (8 if field('g') else 0))
    elif kind == '4a':
        if not field('d'):
            ureg(field('dreg'))
        if field('u'):
            ureg(16 + field('i') + (8 if field('g') else 0))
    elif kind == '16a':
        if field('by') or field('sl'):
            raise ValueError('unsupported SEM immediate memory transfer')
        ureg(16 + field('i') + (8 if field('g') else 0))
    elif kind == '19a_scaled':
        ureg(16 + (field('is') ^ field('idis')) + (8 if field('g') else 0))
    elif kind == '6b_shiftimm':
        result = st._shift_immediate(f, {})
        ureg(result[0])
        changed.add('ASTATX')
    elif kind == '18a':
        if field('bop') not in (0, 1, 2):
            raise ValueError('unsupported SEM system bit operation')
        ureg(st.UREG_CODES['USTAT1'] + field('sreg'))
    elif kind == '25a_direct':
        changed.update(('R2', 'I6'))
    elif kind in ('8a_abs', '21a', '12a_imm', '12a_ureg', '9a_abs'):
        pass  # Counted loops use their hardware loop stack, not the UREG ABI.
    else:
        raise ValueError(f'unsupported SEM register-audit instruction: {kind}')
    return changed


def audit(k, memory, adapter, kernel, saved):
    labels = {name: int(value, 16) for name, value in adapter['labels'].items()}
    entries, regions = [], {}
    kernel_start = int(kernel['code'], 16)
    kernel_end = kernel_start + kernel['code_bytes']//2
    for name, cfg in (('adapter', adapter), ('kernel', kernel)):
        start = int(cfg['code'], 16)
        offsets = cfg['instruction_offsets'] + [cfg['code_bytes']]
        for a, b in zip(offsets, offsets[1:]):
            pc = start + a//2
            if name == 'adapter' and not labels['sem_audio.'] <= pc < labels['sem_init.']:
                continue
            ins = F.decode_fixed(k, memory, pc, b-a)
            changed = writes(k, ins)
            if name == 'kernel' and 'MODE1' in changed:
                raise ValueError(f'SEM kernel must not change MODE1 at {pc:#x}')
            field = lambda key: k.st._field(ins.fields, key)
            if ins.type_name in ('8a_abs', '25a_direct'):
                target = (field('addr[23:16]') << 16) | field('addr[15:0]')
                permitted = kernel_start <= target < kernel_end
                if name == 'adapter':
                    permitted |= (labels['sem_audio.'] <= target < labels['sem_init.'] or
                                  target in (0x1c98b9, 0xbcd000 + 0x1c98b9 - 0x1c8ef1))
                if not permitted:
                    raise ValueError(f'unaudited SEM branch target at {pc:#x}: {target:#x}')
            if ins.type_name == '9a_abs':
                pmi = (field('pmi[2:2]') << 2) | field('pmi[1:0]')
                if field('b') or field('a') or field('ci') or pmi != 4 or field('pmm') != 6:
                    raise ValueError(f'unaudited SEM indirect transfer at {pc:#x}')
            omitted = changed - set(saved)
            if omitted:
                raise ValueError(f'unsaved SEM register writes at {pc:#x}: {sorted(omitted)}')
            entries.append((name, pc, ins, changed))
        regions[name] = dict(instructions=sum(row[0] == name for row in entries),
                             writes=sorted(set().union(*(row[3] for row in entries if row[0] == name))))
    forms = Counter(ins.type_name for _, _, ins, _ in entries)
    return dict(passed=True, regions=regions, forms=dict(sorted(forms.items())),
                saved_registers=list(saved), scalar_only=True,
                limitation='Register-write proof; hardware loop stack and silicon timing require separate checks.')
