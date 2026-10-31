"""Pure SHARC checks on caller-classified instructions; addresses are short words.

Method informed by complex-ping/digitone-2-modding-skill scripts/hwrules.py,
commit 84c8cd359470c648d55bac6075bd6778ba9e69f0. No upstream runtime dependency.
Rule qualifications: ADI SHARC+ PRM rev1.5 ch4 (loop/branch restrictions),
ch13/15 (UREG versus UREGXDAG addressing). Late calls require return-context
review, not automatic rejection. No baseline suppression or inferred filler.

Upstream method license: MIT, Copyright (c) 2026 Julian Kominiak.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from bisect import bisect_right
import re

LOOPS = {'12a_imm', '12a_ureg', '13a'}
DAG_FORMS = {'3a', '3b', '3d', '15a', '15b'}
BRANCH_FORMS = {'8a_abs', '8a_rel', '9a_abs', '9a_rel', '9b_abs', '9b_rel',
                '11a', '11c', '25a_direct', '25a_pcrel'}


def _flow(row):
    kind, fields = row['type'], row['fields']
    if kind in {'25a_rframe', '25c_rframe'}:
        # RFRAME restores the frame in a return delay slot; it is not itself
        # a branch. The renderer's '(return-frame ...)' text is an annotation.
        return None
    if kind in {'25a_direct', '25a_pcrel'}:
        return 'call'
    if kind in {'11a', '11c'}:
        return 'return'
    if kind in BRANCH_FORMS:
        return 'call' if fields.get('b') == 1 else 'branch'
    match = re.search(r'\b(CALL|CJUMP|JUMP|RTS|RTI|RETURN|IDLE)\b', row['text'], re.I)
    if match:
        word = match[1].upper()
        return 'call' if word in {'CALL', 'CJUMP'} else 'idle' if word == 'IDLE' else 'branch'
    if kind in {'22a', '22c'}:
        return 'idle'
    return None


def _unknown(row):
    return row['type'].lower() in {'', 'unknown', 'invalid', 'undecoded'} or '!!UNDECODED!!' in row['text']


def check_rows(rows):
    """Return JSON-safe findings/coverage; malformed row schema raises ValueError.

    Required row keys: pc (SW), size (bytes), text, type, fields (merged),
    region (physical boot-region identity), origin, raw. Context must be
    supplied explicitly; gaps and uncertain semantics produce review findings.
    """
    rows = list(rows)
    for row in rows:
        if not isinstance(row, dict) or any(k not in row for k in
                ('pc', 'size', 'text', 'type', 'fields', 'region', 'origin', 'raw')):
            raise ValueError('instruction row missing required fields')
        if (type(row['pc']) is not int or row['pc'] < 0 or type(row['size']) is not int
                or row['size'] not in (2, 4, 6) or type(row['raw']) is not int
                or not 0 <= row['raw'] < 1 << (row['size'] * 8)
                or not isinstance(row['fields'], dict)
                or any(not isinstance(row[k], str) for k in ('text', 'type', 'region', 'origin'))):
            raise ValueError('invalid instruction row fields or units')
    rows = sorted(rows, key=lambda r: r['pc'])
    if any(a['pc'] + a['size']//2 > b['pc'] for a, b in zip(rows, rows[1:])):
        raise ValueError('duplicate or overlapping instruction rows; resolve in adapter')
    by_pc = {r['pc']: r for r in rows}
    pcs = [r['pc'] for r in rows]
    findings = []
    coverage = dict(rows=len(rows), bytes=sum(r['size'] for r in rows),
                    regions=len({r['region'] for r in rows}), loops=0,
                    complete_loops=0, partial_loops=0, dag_forms=0,
                    ambiguous_dag=0, branches=0, complete_runways=0,
                    partial_runways=0, continuous_72byte_spans=0,
                    partial_72byte_spans=0, whole_image_certified=False)

    def add(rule, severity, row, message, **context):
        findings.append(dict(rule=rule, severity=severity, pc=row['pc'], message=message,
                             region=row['region'], origin=row['origin'], **context))

    if not rows:
        findings.append(dict(rule='COVERAGE-EMPTY', severity='review', pc=0,
                             message='No classified instructions supplied.'))
    loops = []
    for row in rows:
        if _unknown(row):
            add('INSTRUCTION-UNKNOWN', 'review', row, 'Instruction semantics are unavailable.')
            continue
        f, kind = row['fields'], row['type']
        # Decode DAG bank/direction from fields, not renderer argument order.
        if kind in DAG_FORMS:
            coverage['dag_forms'] += 1
            required = {'ureg', 'i', 'g', 'd'} | ({'u'} if kind.startswith('3') else set())
            valid = (required <= f.keys() and all(type(f[k]) is int for k in required)
                     and 0 <= f['ureg'] < 128 and 0 <= f['i'] < 8
                     and f['g'] in (0, 1) and f['d'] in (0, 1)
                     and (not kind.startswith('3') or f['u'] in (0, 1)))
            if not valid:
                coverage['ambiguous_dag'] += 1
                add('DAG-CONTEXT', 'review', row, 'Incomplete DAG bank/direction/update fields.')
            elif 1 <= f['ureg'] >> 4 <= 4:
                number = f['ureg'] & 15
                same = (number >= 8) == bool(f['g'])
                postmodify = f['u'] if kind.startswith('3') else 0
                if same and (f['d'] or postmodify):
                    add('DAG-SAME', 'error', row,
                        'Same-DAG register store or postmodify load uses a forbidden operand.',
                        register='IMLB'[(f['ureg'] >> 4)-1] + str(number),
                        index=f['i'] + 8*f['g'], direction='store' if f['d'] else 'load')
        elif re.search(r'\b[IMLB]\d+\s*=\s*(?:DM|PM)\([^)]*\bI\d+|'
                       r'\b(?:DM|PM)\([^)]*\bI\d+[^)]*\)(?:\s+u=[01])?\s*=\s*[IMLB]\d+', row['text']):
            coverage['ambiguous_dag'] += 1
            add('DAG-CONTEXT', 'review', row, 'DAG transfer form is not covered by field-based rules.')

        if kind not in LOOPS and not re.search(r'\bDO\b', row['text']):
            continue
        coverage['loops'] += 1
        if kind in LOOPS and f.get('mode') not in (0, 1):
            add('LOOP-MODE', 'review', row, 'Loop E2/F1 activity mode is unavailable.')
        match = re.search(r'\bDO\s+(0x[0-9a-fA-F]+)', row['text'])
        target = int(match[1], 16) if match else None
        if kind in LOOPS and type(f.get('reladdr')) is int and 0 <= f['reladdr'] < 1 << 23:
            displacement = f['reladdr'] - (1 << 23) if f['reladdr'] & (1 << 22) else f['reladdr']
            encoded_target = row['pc'] + displacement
            if target is not None and target != encoded_target:
                add('LOOP-CONTEXT', 'review', row, 'Rendered and encoded loop endpoints disagree.')
                coverage['partial_loops'] += 1
                continue
            target = encoded_target
        if target is None or kind not in LOOPS:
            add('LOOP-CONTEXT', 'review', row, 'Loop form or endpoint is unresolved.')
            coverage['partial_loops'] += 1
            continue
        start = row['pc'] + row['size']//2
        if target < start:
            add('LOOP-END', 'error', row, 'Loop endpoint precedes its first body instruction.', end=target)
            coverage['partial_loops'] += 1
            continue
        containing = bisect_right(pcs, target)-1
        if containing >= 0:
            part = rows[containing]
            if part['pc'] < target < part['pc'] + part['size']//2:
                add('LOOP-END-ALIGN', 'error', row, 'Loop endpoint is inside an instruction.', end=target)
                coverage['partial_loops'] += 1
                continue
        loops.append((row, start, target))
        body, cursor = [], start
        while cursor <= target:
            item = by_pc.get(cursor)
            if item is None or item['region'] != row['region'] or _unknown(item):
                add('LOOP-COVERAGE', 'review', row,
                    'Loop body crosses missing, undecoded or different-region context.', missing_pc=cursor, end=target)
                coverage['partial_loops'] += 1
                break
            body.append(item)
            cursor += item['size']//2
        else:
            coverage['complete_loops'] += 1
            counter = kind in {'12a_imm', '12a_ureg'}
            for item in body[-11:]:
                if item['size'] != 6:
                    add('LOOP-ISA', 'error', item, 'Last eleven loop instructions must use legacy 48-bit ISA.', loop_pc=row['pc'])
                elif not re.match(r'(?:[1-9]|1\d|2[0-6])[ad](?:_|$)', item['type']):
                    add('LOOP-ISA-CONTEXT', 'review', item, '48-bit form is not classified as legacy ISA.', loop_pc=row['pc'])
                if counter and (item['fields'].get('cond') == 15 or re.search(r'\bNOT\s+LCE\b', item['text'])):
                    add('LOOP-LCE', 'review', item, 'Late NOT LCE condition needs deterministic-loop review.', loop_pc=row['pc'])
                if counter and f.get('mode') == 1 and _flow(item):
                    add('LOOP-F1-FLOW', 'review', item,
                        'F1 loop tail contains flow/IDLE; SLOWLOOP or automatic E2 behavior is unknown.', loop_pc=row['pc'])
            for item in body[-5:]:
                if _flow(item) == 'call':
                    add('LOOP-CALL', 'review', item,
                        'Late loop call requires callee return/loop-reentry context; it is not automatically illegal.', loop_pc=row['pc'])

    # Only actual syntactic nesting, never a global repeated-end count.
    for n, (outer, start, end) in enumerate(loops):
        for inner, _, inner_end in loops[n+1:]:
            if inner['pc'] > end:
                break
            if start <= inner['pc'] <= end and inner_end == end:
                if outer['region'] == inner['region']:
                    add('LOOP-SHARED-END', 'error', inner, 'Nested hardware loops share an endpoint.', outer_pc=outer['pc'], end=end)
                else:
                    add('LOOP-CONTEXT', 'review', inner, 'Possible nesting crosses region identity.', outer_pc=outer['pc'])

    previous = None
    for row in rows:
        if _unknown(row) or _flow(row) in (None, 'idle'):
            continue
        coverage['branches'] += 1
        if previous and row['region'] == previous['region'] and row['pc'] - previous['pc'] < 3:
            add('BRANCH-SPACING', 'review', row,
                'Branch starts are less than one 48-bit window apart; fetch-window interpretation needs review.', previous_pc=previous['pc'])
        previous = row
        cursor = row['pc'] + row['size']//2
        span_cursor, span_end = cursor, cursor + 36
        while span_cursor < span_end:
            item = by_pc.get(span_cursor)
            if item is None or item['region'] != row['region'] or _unknown(item):
                coverage['partial_72byte_spans'] += 1
                break
            span_cursor += item['size']//2
        else:
            # Byte continuity alone does NOT prove the twelve-48-bit rule.
            coverage['continuous_72byte_spans'] += 1
        for n in range(12):
            item = by_pc.get(cursor)
            if item is None or item['region'] != row['region'] or _unknown(item):
                add('BRANCH-RUNWAY', 'review', row,
                    'Twelve following 48-bit instructions in the same region are not fully covered.',
                    reason='missing_context', missing_pc=cursor, covered_instructions=n)
                coverage['partial_runways'] += 1
                break
            if item['size'] != 6:
                add('BRANCH-RUNWAY', 'review', row, 'Branch runway contains a non-48-bit instruction; mixed-VISA applicability needs review.',
                    reason='mixed_width', at_pc=cursor, covered_instructions=n)
                coverage['partial_runways'] += 1
                break
            cursor += 3
        else:
            coverage['complete_runways'] += 1
    return dict(findings=findings, coverage=coverage)
