"""Offline SHARC address-provenance regressions; no binaries or device needed."""
import json
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_dn2_dsp_stores as audit


class StoreAuditTests(unittest.TestCase):
    def finding(self, text, **kwargs):
        return audit.audit_text(text, **kwargs)['findings'][-1]

    def test_caller_saved_address_crossing_call_is_hazard(self):
        r = audit.audit_text('R4 = 0x200F8000; CALL helper; I0 = R4; DM(0, I0) = R2;')
        self.assertEqual(r['status'], 'hazards')
        self.assertEqual(r['findings'][0]['verdict'], 'caller_clobber')
        self.assertIn('R4', r['findings'][0]['reason'])

    def test_callee_preserved_address_is_traced_to_definition(self):
        r = audit.audit_text('R8 = 0x200F8000; CALL helper; I0 = R8; DM(0, I0) = R2;')
        self.assertEqual(r['status'], 'resolved_for_scope')
        self.assertFalse(r['binary_bound'])
        self.assertEqual(r['findings'][0]['verdict'], 'resolved_dependency')

    def test_unknown_index_register_call_contract_is_not_safe(self):
        r = self.finding('I0 = 0x200F8000; CALL helper; DM(0, I0) = R2;')
        self.assertEqual(r['verdict'], 'unresolved')
        self.assertIn('preservation unknown', r['reason'])

    def test_explicit_preserved_register_case(self):
        r = self.finding('I0 = 0x200F8000; CALL helper; DM(0, I0) = R2;', preserved_registers=['I0'])
        self.assertEqual(r['verdict'], 'resolved_dependency')

    def test_memory_reload_after_call_reestablishes_address(self):
        r = self.finding('R4 = 0x200F8000; DM(0x200F8100) = R4; CALL helper; R4 = DM(0x200F8100); I0 = R4; DM(0,I0) = R2;')
        self.assertEqual(r['verdict'], 'resolved_dependency')

    def test_return_value_origin_is_explicit(self):
        r = self.finding('CALL allocator; I0 = R0; DM(0, I0) = R2;')
        self.assertEqual(r['verdict'], 'resolved_dependency')
        self.assertIn('call return R0', r['reason'])

    def test_float_alias_does_not_hide_caller_clobber(self):
        r = self.finding('F4 = F8; CALL helper; I0 = R4; DM(0, I0) = R2;')
        self.assertEqual(r['verdict'], 'caller_clobber')

    def test_delay_slot_definition_does_not_survive_callee(self):
        r = self.finding('CJUMP helper (DB); R4 = 0x200F8000; NOP; I0 = R4; DM(0, I0) = R2;')
        self.assertEqual(r['verdict'], 'caller_clobber')

    def test_delay_slot_store_occurs_before_call(self):
        r = audit.audit_text('I0=0x200F8000; CJUMP helper (DB); DM(0,I0)=R2; NOP;')
        self.assertEqual(r['findings'][0]['verdict'], 'resolved_dependency')
        self.assertTrue(r['findings'][0]['before_call'])

    def test_selcc_return_label_requires_actual_call(self):
        bad = 'R4=0x200F8000; CJUMP helper (DB); NOP; NOP;\n.L_ret_0:\nI0=R4; DM(0,I0)=R2;'
        self.assertEqual(self.finding(bad)['verdict'], 'caller_clobber')
        missing = 'R4=0x200F8000;\n.L_ret_0:\nI0=R4; DM(0,I0)=R2;'
        self.assertEqual(self.finding(missing)['verdict'], 'unresolved')

    def test_return_label_branch_target_remains_unresolved(self):
        text = 'IF EQ JUMP .L_ret_0; CALL helper;\n.L_ret_0:\nI0=R4; DM(0,I0)=R2;'
        self.assertEqual(self.finding(text)['verdict'], 'unresolved')

    def test_branch_and_merge_never_report_clean(self):
        text = 'I0=0x200F8000; IF EQ JUMP .L_merge;\n.L_merge:\nDM(0,I0)=R2;'
        r = audit.audit_text(text)
        self.assertEqual(r['status'], 'incomplete')
        self.assertEqual(r['coverage']['unresolved_control_flow'], 1)
        self.assertEqual(r['findings'][0]['verdict'], 'unresolved')

    def test_parallel_assignment_uses_old_source_value(self):
        text = 'CALL helper; R8=0x200F8000, R4=R8; I0=R4; DM(0,I0)=R2;'
        self.assertEqual(self.finding(text)['verdict'], 'unresolved')

    def test_parallel_store_uses_old_index(self):
        text = 'CALL helper; I0=0x200F8000, DM(0,I0)=R2;'
        self.assertEqual(self.finding(text)['verdict'], 'unresolved')

    def test_dag_postmodify_requires_modify_register(self):
        r = self.finding('I0=0x200F8000; R1=DM(I0,M0); DM(0,I0)=R2;')
        self.assertEqual(r['verdict'], 'unresolved')
        self.assertIn('M0', r['remaining_registers'])

    def test_unknown_instructions_and_raw_encodings_are_incomplete(self):
        for instruction in ('MAGIC R4', 'R4=WEIRD R8', '.BYTE 0x01', '??', 'DM(SYMBOL)=R0', 'R4=', 'R4==R8'):
            with self.subTest(instruction=instruction):
                r = audit.audit_text(instruction + '; I0=0x200F8000; DM(0,I0)=R2;')
                self.assertEqual(r['status'], 'incomplete')
                self.assertGreater(r['coverage']['unsupported_instructions'], 0)

    def test_ranges_use_pc_and_do_not_inherit_previous_function(self):
        text = '001000: 1111 2222 R4=0x200F8000;\n001003: I0=R4;\n001006: DM(0,I0)=R2;'
        r = audit.audit_text(text, ranges=[dict(name='partial', start='0x1003', end='0x1009')])
        self.assertEqual(r['coverage']['excluded_lines'], 1)
        self.assertEqual(r['findings'][0]['pc'], 0x1006)
        self.assertEqual(r['findings'][0]['verdict'], 'unresolved')

    def test_requested_missing_range_is_reported_even_with_other_coverage(self):
        r = audit.audit_text('001000: I0=0x200F8000;\n001003: DM(0,I0)=R2;',
                             ranges=[dict(name='found', start=0x1000, end=0x1006),
                                     dict(name='missing', start=0x2000, end=0x2006)])
        self.assertEqual(r['coverage']['empty_ranges'], ['missing'])
        self.assertEqual(r['status'], 'incomplete')

    def test_stack_entry_origins_are_opt_in(self):
        text = 'bridge.:\n I4=DM(-32,I6); DM(1,I4)=R0;'
        self.assertEqual(self.finding(text)['verdict'], 'unresolved')
        r = self.finding(text, entry_registers=['I6'])
        self.assertEqual(r['verdict'], 'resolved_dependency')

    def test_empty_scope_and_truncated_call_are_not_clean(self):
        for text in ('', '.SECTION/PM seg_pmco;', 'CJUMP helper (DB); NOP;'):
            self.assertEqual(audit.audit_text(text)['status'], 'incomplete')

    def test_reject_invalid_abi_and_ranges(self):
        for kwargs in (dict(preserved_registers=['R4']), dict(entry_registers=['whatever']),
                       dict(ranges=[dict(name='a', start=3, end=3)]),
                       dict(ranges=[dict(name='a', start=1, end=5), dict(name='b', start=4, end=7)])):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                audit.audit_text('', **kwargs)

    def test_cli_json_and_hazard_exit(self):
        with tempfile.TemporaryDirectory() as td:
            source, out = Path(td) / 'bad.asm', Path(td) / 'result.json'
            source.write_text('CALL helper; I0=R4; DM(0,I0)=R2;')
            self.assertEqual(audit.main([str(source), '--out', str(out)]), 1)
            self.assertEqual(json.loads(out.read_text())['reports'][0]['status'], 'hazards')

    def test_cli_cannot_overwrite_source_through_alias(self):
        with tempfile.TemporaryDirectory() as td:
            source, link = Path(td) / 'bridge.asm', Path(td) / 'alias.json'
            source.write_text('I0=1; DM(0,I0)=R0;')
            link.symlink_to(source)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                audit.main([str(source), '--out', str(link)])
            self.assertEqual(source.read_text(), 'I0=1; DM(0,I0)=R0;')


if __name__ == '__main__':
    unittest.main()
