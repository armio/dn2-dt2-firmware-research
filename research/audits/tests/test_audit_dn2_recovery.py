"""Synthetic recovery-audit checks; no vendor firmware or device needed."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_dn2_recovery as audit
from dnfw.container.section import compress


class RecoveryAuditTests(unittest.TestCase):
    def test_cursor_decode_matches_existing_codec(self):
        section = compress(3, audit.BASE, b'ABCD' * 1000)
        result, profile = audit.decode_with_margin(section.stored)
        self.assertEqual(result, section.unpack())
        self.assertEqual(result, b'ABCD' * 1000)
        self.assertEqual(profile['consumed'], section.declared_length)
        self.assertEqual(profile['overlap_witnesses'], {})

    def test_bad_compressed_streams_fail_closed(self):
        section = compress(3, audit.BASE, b'ABCD' * 1000)
        bad_length = bytearray(section.stored)
        bad_length[:4] = (section.declared_length - 1).to_bytes(4, 'big')
        bad_sum = bytearray(section.stored)
        bad_sum[7] ^= 1
        for stored in (b'', b'1234567', bytes(bad_length), bytes(bad_sum)):
            with self.subTest(stored_bytes=len(stored)), self.assertRaises(ValueError):
                audit.decode_with_margin(stored)

    def test_large_output_reports_actual_unread_source_collision(self):
        section = compress(3, audit.BASE, b'ABCD' * (0x220000 // 4))
        result, profile = audit.decode_with_margin(section.stored)
        self.assertEqual(len(result), 0x220000)
        witness = profile['overlap_witnesses']['0x40200000']
        self.assertGreater(witness['unread_bytes'], 0)
        self.assertLess(max(int(witness['write_start'], 16), int(witness['unread_start'], 16)),
                        min(int(witness['write_end_exclusive'], 16), int(witness['unread_end_exclusive'], 16)))
        self.assertNotIn('0x40400000', profile['overlap_witnesses'])

    def test_each_protected_range_detects_single_byte_change(self):
        original = bytes(max(hi for _, _, hi in audit.PROTECTED) - audit.BASE)
        for name, lo, hi in audit.PROTECTED:
            with self.subTest(name=name):
                candidate = bytearray(original)
                candidate[lo - audit.BASE] = 1
                failed = [s['name'] for s in audit.protected_ranges(original, candidate) if not s['ok']]
                self.assertEqual(failed, [name])

    def test_overlapping_sections_fail_before_depack(self):
        stream = bytearray(136)
        struct.pack_into('>I', stream, 0, 128)
        stream[8:12] = b'ELE3'
        struct.pack_into('>I', stream, 36, 2)
        struct.pack_into('>4I', stream, 40, 2, 64, 16, 0)
        struct.pack_into('>4I', stream, 56, 3, 64, 16, 0)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            audit.section_layout(stream)

    def test_missing_or_unsupported_stock_never_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / 'unsupported.syx'
            fake.write_bytes(b'unsupported')
            for stock in (Path(td) / 'absent', fake):
                report = audit.audit(fake, stock)
                self.assertFalse(report['ok'])
                self.assertEqual(report['findings'][-1]['check'], 'input_or_structure')

    def test_cli_refuses_input_as_output(self):
        with tempfile.TemporaryDirectory() as td:
            candidate = Path(td) / 'input.syx'
            candidate.write_bytes(b'untouched')
            result = subprocess.run([sys.executable, str(Path(audit.__file__)),
                '--candidate', str(candidate), '--stock', str(candidate), '--out', str(candidate)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('must not overwrite', result.stderr)
            self.assertEqual(candidate.read_bytes(), b'untouched')


if __name__ == '__main__':
    unittest.main()
