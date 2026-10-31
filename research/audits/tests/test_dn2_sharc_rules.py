"""Synthetic, hardware-free tests of the explicit-row SHARC rules."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dn2_sharc_rules import check_rows


def row(pc, size=6, text='NOP', kind='21a', fields=None, region='block0'):
    return dict(pc=pc, size=size, text=text, type=kind, fields=fields or {},
                region=region, origin='synthetic', raw=0)


def loop(pc, end, *, mode=0, kind='12a_imm'):
    return row(pc, text=f'DO {end:#x} UNTIL LCE', kind=kind,
               fields=dict(mode=mode, reladdr=(end-pc) & 0x7fffff, data=32))


def nops(pc, count, *, size=6, region='block0'):
    return [row(pc+i*(size//2), size, kind='21a' if size == 6 else '21c', region=region)
            for i in range(count)]


def dag(pc=100, *, ureg=0x24, index=0, bank=0, store=0, post=1, kind='3a'):
    return row(pc, text='M4 = DM(I0, M6) u=0', kind=kind,
               fields=dict(ureg=ureg, i=index, g=bank, d=store, u=post))


def rules(rows, severity=None):
    return [f['rule'] for f in check_rows(rows)['findings']
            if severity is None or f['severity'] == severity]


class SharcRuleTests(unittest.TestCase):
    def test_empty_input_is_explicitly_incomplete(self):
        self.assertEqual(rules([]), ['COVERAGE-EMPTY'])

    def test_invalid_units_and_overlaps_rejected(self):
        for bad in [row(-1), row(1, 3), dict(row(1), raw=-1), dict(row(1), pc=True)]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check_rows([bad])
        with self.assertRaises(ValueError):
            check_rows([row(100), row(101)])

    def test_input_is_unchanged_and_result_json_safe(self):
        rows = [row(103), loop(100, 103)]
        before = copy.deepcopy(rows)
        json.dumps(check_rows(rows))
        self.assertEqual(rows, before)

    def test_single_instruction_loop_endpoint_is_inclusive(self):
        result = check_rows([loop(100, 103), row(103)])
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['coverage']['complete_loops'], 1)

    def test_only_last_eleven_must_be_48bit(self):
        body = [row(103, 2, kind='21c')] + nops(104, 11)
        rows = [loop(100, body[-1]['pc'])] + body
        self.assertNotIn('LOOP-ISA', rules(rows))
        body = nops(103, 10) + [row(133, 2, kind='21c')]
        self.assertIn('LOOP-ISA', rules([loop(100, 133)] + body, 'error'))

    def test_loop_endpoint_in_middle_of_instruction(self):
        self.assertIn('LOOP-END-ALIGN', rules([loop(100, 104), row(103)], 'error'))

    def test_loop_target_before_body(self):
        self.assertIn('LOOP-END', rules([loop(100, 99)], 'error'))

    def test_loop_gap_and_region_change_are_review(self):
        for body in ([row(106)], [row(103, region='another')]):
            result = check_rows([loop(100, 106)] + body)
            self.assertIn('LOOP-COVERAGE', [f['rule'] for f in result['findings']])
            self.assertFalse([f for f in result['findings'] if f['severity'] == 'error'])
            self.assertEqual(result['coverage']['partial_loops'], 1)

    def test_nested_shared_end_and_sequential_loops(self):
        self.assertIn('LOOP-SHARED-END', rules(
            [loop(100, 109), loop(103, 109), row(106), row(109)], 'error'))
        self.assertNotIn('LOOP-SHARED-END', rules(
            [loop(100, 103), row(103), loop(106, 109), row(109)]))

    def test_missing_or_disagreeing_loop_target_is_review(self):
        unresolved = row(100, text='DO (M0,I0) UNTIL LCE', kind='unhandled_loop')
        self.assertIn('LOOP-CONTEXT', rules([unresolved], 'review'))
        conflict = loop(100, 103)
        conflict['fields']['reladdr'] = 6
        self.assertIn('LOOP-CONTEXT', rules([conflict, row(103)], 'review'))

    def test_fallback_type13_uses_fields(self):
        r = loop(100, 103, kind='13a')
        r['text'] = '[13a] mode=0 reladdr=3 term=6'
        r['fields']['term'] = 6
        self.assertEqual(check_rows([r, row(103)])['findings'], [])

    def test_missing_loop_mode_is_review_without_hiding_width_error(self):
        r = loop(100, 103)
        del r['fields']['mode']
        found = rules([r, row(103, 2, kind='21c')])
        self.assertIn('LOOP-MODE', found)
        self.assertIn('LOOP-ISA', found)

    def test_late_call_review_not_hardware_failure(self):
        call = row(103, text='CALL target=0x200', kind='8a_abs', fields={'b': 1})
        rows = [loop(100, 103), call] + nops(106, 12)
        self.assertIn('LOOP-CALL', rules(rows, 'review'))
        self.assertEqual(rules(rows, 'error'), [])
        self.assertNotIn('LOOP-F1-FLOW', rules(rows))
        rows[0] = loop(100, 103, mode=1)
        self.assertIn('LOOP-F1-FLOW', rules(rows, 'review'))

    def test_late_not_lce_advice_is_review(self):
        r = row(103, text='IF NOT LCE R0 = R0 + 1', kind='2a', fields={'cond': 15})
        self.assertEqual(rules([loop(100, 103), r], 'error'), [])
        self.assertIn('LOOP-LCE', rules([loop(100, 103), r], 'review'))

    def test_known_d_forms_are_not_rejected_as_compressed(self):
        r = row(103, text='R0 = DM(0x20000000)', kind='14d')
        self.assertEqual(rules([loop(100, 103), r]), [])
        r['type'] = 'unclassified_48bit'
        self.assertIn('LOOP-ISA-CONTEXT', rules([loop(100, 103), r], 'review'))

    def test_same_dag_postload_and_all_stores_fail(self):
        for r in [dag(), dag(store=1, post=0), dag(kind='15a', store=1), dag(kind='15b', store=1)]:
            with self.subTest(r=r):
                self.assertIn('DAG-SAME', rules([r], 'error'))

    def test_same_dag_premodify_and_immediate_loads_allowed(self):
        for r in [dag(post=0), dag(kind='15a'), dag(kind='15b')]:
            self.assertNotIn('DAG-SAME', rules([r]))

    def test_pm_bank_uses_fields_not_renderer_index(self):
        # Encoded index0+g1 means I8 even if a renderer prints I0.
        self.assertIn('DAG-SAME', rules([dag(ureg=0x18, bank=1)], 'error'))
        self.assertNotIn('DAG-SAME', rules([dag(ureg=0x10, bank=1)]))
        self.assertNotIn('DAG-SAME', rules([dag(ureg=0x18, bank=0)]))

    def test_data_register_load_is_not_dag_hazard(self):
        self.assertNotIn('DAG-SAME', rules([dag(ureg=0x04)]))

    def test_immediate_store_annotation_is_not_a_dag_transfer(self):
        r = row(0x1c010f, text='DM(I7, M7) = 0x1c0111  [also I7 += M7]',
                kind='16a', fields=dict(i=7, m=7, g=0, data=0x1c0111))
        self.assertEqual(rules([r]), [])

    def test_ambiguous_dag_never_assumes_postmodify(self):
        r = dag()
        del r['fields']['u']
        self.assertEqual(rules([r], 'error'), [])
        self.assertIn('DAG-CONTEXT', rules([r], 'review'))
        r['type'] = 'unhandled_transfer'
        self.assertIn('DAG-CONTEXT', rules([r], 'review'))

    def test_equal_count_different_hazard_is_not_suppressed(self):
        a = check_rows([dag(100)])['findings']
        b = check_rows([dag(200)])['findings']
        self.assertEqual(len(a), len(b))
        self.assertEqual(a[0]['pc'], 100)
        self.assertEqual(b[0]['pc'], 200)

    def test_branch_runway_requires_twelve_48bit_rows(self):
        branch = row(100, text='JUMP target=0x200', kind='8a_abs', fields={'b': 0})
        self.assertEqual(rules([branch] + nops(103, 12)), [])
        self.assertIn('BRANCH-RUNWAY', rules([branch] + nops(103, 11), 'review'))
        self.assertIn('BRANCH-RUNWAY', rules([branch] + nops(103, 36, size=2), 'review'))
        result = check_rows([branch] + nops(103, 36, size=2))
        self.assertEqual(result['coverage']['continuous_72byte_spans'], 1)
        self.assertEqual(result['coverage']['complete_runways'], 0)
        self.assertEqual(result['findings'][0]['reason'], 'mixed_width')

    def test_branch_runway_gap_or_region_transition_is_review(self):
        branch = row(100, text='JUMP', kind='8a_abs')
        for rows in [nops(104, 12), nops(103, 12, region='other')]:
            self.assertIn('BRANCH-RUNWAY', rules([branch] + rows, 'review'))

    def test_return_fallback_type_and_branch_spacing(self):
        ret = row(100, 2, text='[11c] cond=31 j=0 lr=0', kind='11c')
        second = row(101, 2, text='RTS', kind='11c')
        self.assertIn('BRANCH-SPACING', rules([ret, second] + nops(102, 12), 'review'))
        first = row(100, text='JUMP', kind='8a_abs')
        second = row(103, text='JUMP', kind='8a_abs')
        self.assertNotIn('BRANCH-SPACING', rules([first, second] + nops(106, 12)))

    def test_rframe_annotation_is_not_a_second_branch(self):
        ret = row(100, 4, text='RETURN', kind='9b_abs', fields={'b': 0, 'j': 1})
        rframe = row(102, 2, text='(return-frame delay slot: 25c_rframe)', kind='25c_rframe')
        report = check_rows([ret, rframe] + nops(103, 12))
        self.assertEqual(report['coverage']['branches'], 1)
        self.assertNotIn('BRANCH-SPACING', [f['rule'] for f in report['findings']])
        self.assertEqual(check_rows([rframe])['coverage']['branches'], 0)

    def test_unknown_row_cannot_supply_runway(self):
        branch = row(100, text='JUMP', kind='8a_abs')
        unknown = row(103, text='!!UNDECODED!!', kind='unknown')
        found = rules([branch, unknown] + nops(106, 11), 'review')
        self.assertIn('INSTRUCTION-UNKNOWN', found)
        self.assertIn('BRANCH-RUNWAY', found)


if __name__ == '__main__':
    unittest.main()
