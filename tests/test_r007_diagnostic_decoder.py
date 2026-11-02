import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'research/diagnostics'))
import capture_dn2_r007_diagnostic as C


def header(tag, phase, first, second):
    return struct.pack('>7I', 0, 0x4f530000 | tag, phase << 10, first, second, 0, 0)


class R007DecoderTests(unittest.TestCase):
    def test_new_phase15_tags_and_canonical_payloads(self):
        names = {0xdc1f: ('zero_commits', 'discarded_on_skip'),
                 0xdc20: ('usb_guard_accepted', 'usb_guard_rejected'),
                 0xdc21: ('postexport_cross_or_late_events', 'max_accepted_elapsed_cycles')}
        for tag, fields in names.items():
            d = C.decode(header(tag, 15, 0x12345678, 0x90abcdef))
            self.assertTrue(d['checks_passed'])
            self.assertEqual(d['fields'], dict(zip(fields, (0x12345678, 0x90abcdef))))
            self.assertFalse(d['atomic'])
            self.assertFalse(C.decode(header(tag, 14, 1, 2))['checks_passed'])

    def test_bad_lengths_removed_tag_and_r006_chunks(self):
        for raw in (b'', bytes(27), bytes(29), header(0xdc1e, 15, 0, 0), header(0xe000, 0, 0, 0)):
            self.assertFalse(C.decode(raw)['checks_passed'])

    def test_legacy_phase_and_plausibility(self):
        self.assertTrue(C.decode(header(0xdc16, 7, 100, 90))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc11, 2, 100, 10))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc11, 1, 100, 101))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc10, 0, 200, 100))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc12, 2, 1, 1))['checks_passed'])
        self.assertTrue(C.decode(header(0xdc01, 0, 1024, 1))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc01, 0, 2048, 1))['checks_passed'])

    def test_frozen_codec_identity_validation(self):
        self.assertTrue(C.decode(header(0xdc1d, 14, 0, 0))['checks_passed'])
        self.assertTrue(C.decode(header(0xdc1d, 14, 0x2c0478, 0x26b))['checks_passed'])
        self.assertFalse(C.decode(header(0xdc1d, 14, 0x2c0578, 0x261))['checks_passed'])

    def test_counter_delta_separate_from_maximum_and_last(self):
        rows = [dict(at=str(i), decoded=C.decode(raw)) for i, raw in enumerate((
            header(0xdc21, 15, 10, 60000), header(0xdc21, 15, 12, 65000),
            header(0xdc10, 0, 50000, 70000), header(0xdc10, 0, 10000, 70000)))]
        tags = C.summarize(rows)['tags']
        self.assertEqual(tags['4f53dc21']['fields']['postexport_cross_or_late_events']['delta'], 2)
        self.assertNotIn('delta', tags['4f53dc21']['fields']['max_accepted_elapsed_cycles'])
        self.assertNotIn('delta', tags['4f53dc10']['fields']['last_render_cycles'])

    def test_counter_decrease_does_not_become_unsigned_growth(self):
        rows = [dict(at=str(i), decoded=C.decode(header(0xdc20, 15, n, 0)))
                for i, n in enumerate((0xfffffffe, 1, 4))]
        value = C.summarize(rows)['tags']['4f53dc20']['fields']['usb_guard_accepted']
        self.assertIsNone(value['delta'])
        self.assertTrue(value['decreased'])

    def test_single_observation_and_invalid_phase_excluded_from_deltas(self):
        rows = [dict(at='a', decoded=C.decode(header(0xdc1f, 15, 8, 9))),
                dict(at='b', decoded=C.decode(header(0xdc1f, 14, 20, 30)))]
        summary = C.summarize(rows)
        self.assertIsNone(summary['tags']['4f53dc1f']['fields']['zero_commits']['delta'])
        self.assertEqual(summary['rejected_or_unknown']['4f53dc1f'], 1)

    def test_cf_accumulator_wrap_and_partial_capture(self):
        a = dict(profile_time=10., profile=[0xfffffff0, 100, 0, 0, 0, 0], extra=[4])
        b = dict(profile_time=12., profile=[0x100000, 3100, 0, 0, 0, 0], extra=[6])
        values = C.cf_deltas([dict(context=a), dict(context=b), dict(context={})])
        self.assertEqual(values[0]['elapsed_tick_delta'], 0x100010)
        self.assertEqual(values[0]['callback_delta'], 3000)
        self.assertEqual(values[0]['threshold_delta'], 2)
        self.assertTrue(values[0]['plausible'])
        b['profile'][1] = 1
        self.assertFalse(C.cf_deltas([dict(context=a), dict(context=b)])[0]['plausible'])

    def test_new_tag_coverage_reports_missing_and_rejected(self):
        rows = [dict(at='a', decoded=C.decode(header(0xdc1f, 15, 1, 2))),
                dict(at='b', decoded=C.decode(header(0xdc20, 14, 1, 2)))]
        summary = C.summarize(rows)
        self.assertEqual(summary['new_tags_observed'], ['4f53dc1f'])
        self.assertEqual(summary['new_tags_missing'], ['4f53dc20', '4f53dc21'])
        self.assertEqual(summary['new_tags_with_multiple_observations'], [])

    def test_phase15_burst_caps_stalled_window_and_uses_nonuniform_delays(self):
        windows = {}
        d = C.decode(header(0xdc1f, 15, 1, 2))
        delays = [C.phase15_burst_delay(d, windows) for _ in range(14)]
        self.assertEqual(delays[:12], list(C.BURST_DELAYS)*4)
        self.assertEqual(delays[12:], [None, None])
        self.assertEqual(windows['0']['extra_reads_scheduled'], 12)

    def test_phase15_burst_stops_after_three_tags_and_never_runs_other_phases(self):
        windows = {}
        for tag in (0xdc1f, 0xdc20):
            self.assertIsNotNone(C.phase15_burst_delay(C.decode(header(tag, 15, 1, 2)), windows))
        self.assertIsNone(C.phase15_burst_delay(C.decode(header(0xdc21, 15, 1, 2)), windows))
        self.assertIsNone(C.phase15_burst_delay(C.decode(header(0xdc21, 14, 1, 2)), windows))
        self.assertIsNone(C.phase15_burst_delay(C.decode(header(0xdc10, 0, 1, 2)), windows))
        self.assertEqual(windows['0']['extra_reads_scheduled'], 2)

    def test_phase15_global_burst_budget_survives_window_changes(self):
        windows = {}
        for window in range(4):
            d = C.decode(header(0xdc1f, 15, 1, 2))
            d['heartbeat'] += window << 14
            for _ in range(12):
                C.phase15_burst_delay(d, windows)
        self.assertEqual(sum(w['extra_reads_scheduled'] for w in windows.values()), 36)
        self.assertEqual(windows['3']['extra_reads_scheduled'], 0)


if __name__ == '__main__':
    unittest.main()
