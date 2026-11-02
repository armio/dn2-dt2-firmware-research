import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'research/diagnostics'))
import capture_dn2_r008_diagnostic as C


def record(kind=0, sequence=7):
    values = [0]*28
    values[0] = sequence
    if kind < 2:
        values[1:4] = [19, 1 if kind == 0 else 21, 3]
        values[4:8] = [0x2c08e8, 0x2c49d0, 0x2c10e8, 0x2c59d0]
        values[26] = 1 if kind == 0 else 63
    else:
        values[1:7] = [4000, 100, 10, 5, 13000, 1 if kind == 2 else 21]
        values[7:27] = list(range(20))
    values[27] = C.checksum(values[:27], kind)
    return values


def header(values, field, cycle=0, kind=0, sequence=None, phase=15):
    marker = C.MARKER | kind << 8 | cycle << 5 | field
    return struct.pack('>7I', 0, marker, phase << 10,
                       values[0] if sequence is None else sequence, values[field % 28], 0, 0)


def feed(values, cycles=(0,), kind=0, banks=None):
    banks = {} if banks is None else banks
    for cycle in cycles:
        for i in range(28):
            C.add_chunk(banks, C.decode(header(values, i, cycle, kind)), f'{cycle}:{i}')
    return banks


class R008DecoderTests(unittest.TestCase):
    def test_single_checked_and_two_matching_cycles(self):
        values = record()
        bank = next(iter(feed(values).values()))
        checked = C.assess(bank)
        self.assertTrue(checked['valid'])
        self.assertEqual(checked['quality'], 'single_checked')
        self.assertTrue(checked['event_available'])
        bank = next(iter(feed(values, (0, 1)).values()))
        self.assertEqual(C.assess(bank)['quality'], 'repeated_matching')

    def test_union_can_span_cycles_but_is_not_two_complete_cycles(self):
        values, banks = record(), {}
        for i in range(28):
            C.add_chunk(banks, C.decode(header(values, i, int(i >= 14))), str(i))
        result = C.assess(next(iter(banks.values())))
        self.assertTrue(result['valid'])
        self.assertEqual(result['quality'], 'single_checked')

    def test_partial_and_duplicate_held_field_are_not_full_repeats(self):
        values, banks = record(), {}
        for _ in range(100):
            C.add_chunk(banks, C.decode(header(values, 0)), 'a')
        result = C.assess(next(iter(banks.values())))
        self.assertFalse(result['valid'])
        self.assertEqual(result['quality'], 'incomplete')

    def test_conflict_is_retained_even_if_later_correct_value_returns(self):
        values = record()
        banks = feed(values)
        wrong = list(values)
        wrong[8] ^= 4
        C.add_chunk(banks, C.decode(header(wrong, 8, 1)), 'bad')
        C.add_chunk(banks, C.decode(header(values, 8, 1)), 'correct')
        result = C.assess(next(iter(banks.values())))
        self.assertFalse(result['valid'])
        self.assertEqual(result['conflicts'], 1 << 8)

    def test_torn_payload_and_wrong_checksum_rejected(self):
        for index in (3, 8, 22, 27):
            values = record()
            values[index] ^= 1
            result = C.assess(next(iter(feed(values).values())))
            self.assertFalse(result['valid'])
            self.assertIn('record checksum', result['rejected_because'])

    def test_echoed_sequence_and_record_identity_must_match(self):
        values, banks = record(), {}
        for i in range(28):
            C.add_chunk(banks, C.decode(header(values, i, sequence=8)), str(i))
        result = C.assess(next(iter(banks.values())))
        self.assertFalse(result['valid'])
        self.assertIn('word0 differs from echoed sequence', result['rejected_because'])

    def test_snapshot_sequences_and_kinds_never_merge(self):
        banks = feed(record(0, 7))
        feed(record(0, 8), banks=banks)
        feed(record(1, 7), kind=1, banks=banks)
        self.assertEqual(set(banks), {'0:7', '0:8', '1:7'})

    def test_empty_journal_not_reported_as_fault(self):
        values = [7]+[0]*26
        values.append(C.checksum(values))
        result = C.assess(next(iter(feed(values).values())))
        self.assertTrue(result['valid'])
        self.assertFalse(result['event_available'])
        values[2] = 1
        values[27] = C.checksum(values[:27])
        self.assertFalse(C.assess(next(iter(feed(values).values())))['valid'])

    def test_bad_size_phase_field_sequence_and_reserved_bits(self):
        values = record()
        raws = [b'', bytes(27), bytes(29), header(values, 0, phase=14),
                header(values, 28), header(values, 0, sequence=0)]
        reserved = bytearray(header(values, 0))
        reserved[7] |= 64
        raws.append(bytes(reserved))
        for raw in raws:
            d = C.decode(raw)
            self.assertFalse(d['checks_passed'])
            self.assertIsNone(C.add_chunk({}, d, 'a'))

    def test_counter_banks_keep_independent_identity_and_reason_ranges(self):
        banks = feed(record(2, 7), kind=2)
        feed(record(3, 8), kind=3, banks=banks)
        summary = C.summarize([], banks)
        self.assertEqual(summary['kinds_observed'], ['counter_a', 'counter_b'])
        self.assertEqual(summary['kinds_missing'], ['post', 'reject'])
        a, b = summary['journals']
        self.assertEqual(set(a['reason_counts']), {str(i) for i in range(1, 21)})
        self.assertEqual(set(b['reason_counts']), {str(i) for i in range(21, 41)})
        self.assertNotEqual(a['sequence'], b['sequence'])
        values = record(2)
        values[6] = 21
        values[27] = C.checksum(values[:27], 2)
        self.assertFalse(C.assess(next(iter(feed(values, kind=2).values())))['valid'])

    def test_legacy_tags_still_decoded(self):
        raw = struct.pack('>7I', 0, 0x4f53dc20, 15 << 10, 100, 2, 0, 0)
        d = C.decode(raw)
        self.assertFalse(d.get('journal', False))
        self.assertTrue(d['checks_passed'])
        self.assertEqual(d['fields']['usb_guard_accepted'], 100)

    def test_elapsed_only_post_is_valid_but_unavailable_tuples_hidden(self):
        values = record(1)
        values[2], values[25], values[26] = 0, 4, 0x27
        values[8:16] = [0xdeadbeef]*8
        values[20] = 1234
        values[27] = C.checksum(values[:27], 1)
        result = C.assess(next(iter(feed(values, kind=1).values())))
        self.assertTrue(result['valid'])
        self.assertEqual(result['reason_detail']['predicate'], 'elapsed_only')
        self.assertIsNone(result['fields']['before_start'])
        self.assertIsNone(result['fields']['after_snapshot_clock'])
        self.assertEqual(result['fields']['cross_flags'], 4)

    def test_kind_mask_and_target_consistency(self):
        for index, value in ((2, 19), (26, 63)):
            values = record()
            values[index] = value
            values[27] = C.checksum(values[:27])
            self.assertFalse(C.assess(next(iter(feed(values).values())))['valid'])
        values = record(1)
        values[6] = 0x2c00e8
        values[27] = C.checksum(values[:27], 1)
        self.assertFalse(C.assess(next(iter(feed(values, kind=1).values())))['valid'])

    def test_checksum_binds_kind(self):
        values = record()
        result = C.assess(next(iter(feed(values, kind=1).values())))
        self.assertFalse(result['valid'])
        self.assertIn('record checksum', result['rejected_because'])


if __name__ == '__main__':
    unittest.main()
