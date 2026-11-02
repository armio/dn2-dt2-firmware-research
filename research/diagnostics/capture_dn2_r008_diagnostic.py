#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded R008 rejection journals over HELLO/PEEK; no audio, screen or control operations."""
from pathlib import Path
import argparse
import hashlib
import json
import time

import capture_dn2_r007_diagnostic as C

MAIN_SHA = 'af0f0eb6d0bcfbadad8a2aed69cc90e1c7f8d2dad0cf9ed77bf5784f689c3033'
RUNTIME_SHA = 'ddf418cc1f341222312556ba1dc225a43ab8981ab4f49996a71ef8cb8028aeb2'
DSP_PARENT_SHA = '681a0800b66fb046407b6cf8730cf66de7f1a7640ba7bb78cc9e4e15dab0103b'
DSP_SHA = '7613f501bcf71c8e8a8d99a1976a549baf8f8b2df7dc30a8a88baa2dc08da7ff'
MARKER, MARKER_MASK, FULL = 0x4f53e800, 0xfffffcc0, (1 << 28)-1
KINDS = ('reject', 'post', 'counter_a', 'counter_b')
EVENT_FIELDS = ('snapshot_sequence event_sequence reason reason_count original_i3 original_i13 '
                'tdm_target spi_target before_start before_current before_count before_start_again '
                'after_start after_current after_count after_start_again active_callback event_callback '
                'started finished after_snapshot_clock event_clock accepted rejected crossed cross_flags valid_mask checksum').split()
MAX_EXTRA, MAX_WINDOW, MAX_REQUESTS = 550, 110, 1000
LIMITS = ('One immutable snapshot is grouped by kind and sequence. Full coverage, matching word0, '
          'all observed duplicate values, and checksum are required. single_checked means one complete '
          'union across cycles; repeated_matching means both distinct cycle masks are complete. '
          'Checksum is not a cryptographic integrity proof. Partial/conflicting records remain evidence '
          'but are not decoded as faults. Counter banks belong to different snapshot times; never combine '
          'them into one simultaneous histogram. Event clocks are local DSP cycles, not CF/host time. '
          'A reject/post-check reason does not by itself prove an audible discontinuity.')


def checksum(values, kind=0):
    acc = 0x55475238 ^ kind
    for value in values:
        acc = (((acc << 5) | (acc >> 27)) & C.MASK) ^ value
    return acc


def decode(raw):
    if len(raw) != 28:
        return C.decode(raw)
    w = C.words(raw)
    if w[1] & MARKER_MASK != MARKER:
        return C.decode(raw)
    field, cycle, kind = w[1] & 31, (w[1] >> 5) & 1, (w[1] >> 8) & 3
    reasons = []
    if field >= 28:
        reasons.append('journal field outside 0..27')
    if (w[2] >> 10) & 15 != 15:
        reasons.append('journal outside heartbeat phase15')
    if not w[3]:
        reasons.append('zero snapshot sequence')
    return dict(raw=raw.hex(), words=[f'{v:08x}' for v in w], marker=f'{w[1]:08x}',
                heartbeat=w[2], publisher_phase=(w[2] >> 10) & 15,
                recognized=True, checks_passed=not reasons, rejected_because=reasons,
                journal=True, kind=kind, field=field, cycle=cycle, sequence=w[3], value=w[4])


def add_chunk(banks, decoded, at):
    if not decoded.get('journal') or not decoded.get('checks_passed'):
        return None
    key = f"{decoded['kind']}:{decoded['sequence']}"
    bank = banks.setdefault(key, dict(kind=decoded['kind'], sequence=decoded['sequence'],
                                    values=[None]*28, masks=[0, 0], conflicts=0,
                                    first_at=at, last_at=at, first_heartbeat=decoded['heartbeat'],
                                    last_heartbeat=decoded['heartbeat'], observations=0))
    field, value = decoded['field'], decoded['value']
    if bank['values'][field] is None:
        bank['values'][field] = value
    elif bank['values'][field] != value:
        bank['conflicts'] |= 1 << field
    bank['masks'][decoded['cycle']] |= 1 << field
    bank.update(last_at=at, last_heartbeat=decoded['heartbeat'], observations=bank['observations']+1)
    return bank


def assess(bank, reason_names=None):
    result = {k: v for k, v in bank.items() if k != 'values'}
    result['kind_name'] = KINDS[bank['kind']]
    values, masks = bank['values'], bank['masks']
    reasons = []
    if masks[0] | masks[1] != FULL:
        reasons.append('incomplete field coverage')
    if bank['conflicts']:
        reasons.append('conflicting duplicate field')
    if reasons:
        return dict(result, valid=False, quality='incomplete' if not bank['conflicts'] else 'conflicting',
                    rejected_because=reasons, raw_values=values)
    if values[0] != bank['sequence']:
        reasons.append('word0 differs from echoed sequence')
    if checksum(values[:27], bank['kind']) != values[27]:
        reasons.append('record checksum')
    if bank['kind'] < 2:
        fields = dict(zip(EVENT_FIELDS, values))
        reason, mask = fields['reason'], fields['valid_mask']
        if not fields['event_sequence']:
            if reason or mask:
                reasons.append('empty journal has event validity/reason')
        else:
            expected_mask = None
            if bank['kind'] == 0 and 1 <= reason <= 18:
                expected_mask = 1 if reason == 1 else 3 if reason == 2 else 15
            elif bank['kind'] == 1 and 19 <= reason <= 40:
                expected_mask = 63
            elif bank['kind'] == 1 and reason == 0 and fields['cross_flags'] == 4:
                expected_mask = 39
            if expected_mask is None:
                reasons.append('event reason/flags incompatible with journal kind')
            elif mask != expected_mask:
                reasons.append('event validity mask inconsistent with reason')
        if mask & 2 and (fields['tdm_target'] not in (0x2c08e8, 0x2c10e8)
                         or fields['tdm_target'] != fields['original_i3'] ^ 0x1800):
            reasons.append('invalid TDM target/original pointer pair')
        if mask & 4 and (fields['spi_target'] not in (0x2c49d0, 0x2c59d0)
                         or fields['spi_target'] != fields['original_i13'] ^ 0x1000):
            reasons.append('invalid SPI target/original pointer pair')
        unavailable = []
        for bit, names in ((1, ('original_i3', 'original_i13')), (2, ('tdm_target',)),
                           (4, ('spi_target',)), (8, tuple(EVENT_FIELDS[8:12])),
                           (16, (*EVENT_FIELDS[12:16], 'after_snapshot_clock')),
                           (32, ('finished', 'cross_flags'))):
            if not mask & bit:
                unavailable.extend(names)
        for name in unavailable:
            fields[name] = None
        result.update(fields=fields, event_available=bool(fields['event_sequence']))
        result['unavailable_fields'] = unavailable
        if reason_names and reason:
            result['reason_detail'] = reason_names.get(str(reason))
        elif fields['event_sequence'] and bank['kind'] == 1 and reason == 0:
            result['reason_detail'] = dict(phase='after', bus=None, predicate='elapsed_only')
    else:
        first_reason = 1 if bank['kind'] == 2 else 21
        if values[6] != first_reason:
            reasons.append('counter bank reason base')
        result['fields'] = dict(zip(('snapshot_sequence', 'callback', 'accepted', 'rejected', 'crossed', 'max_elapsed', 'first_reason_id'), values[:7]))
        result['reason_counts'] = {str(first_reason+i): value for i, value in enumerate(values[7:27])}
    result.update(valid=not reasons, quality=('repeated_matching' if masks == [FULL, FULL] else 'single_checked') if not reasons else 'rejected',
                  rejected_because=reasons, raw_values=values)
    return result


def summarize(snapshots, banks, reason_names=None):
    journals = [assess(bank, reason_names) for bank in banks.values()]
    observed = {r['kind_name'] for r in journals if r['valid']}
    legacy = C.summarize([r for r in snapshots if not r.get('decoded', {}).get('journal')])
    return dict(journals=journals, kinds_observed=sorted(observed), kinds_missing=sorted(set(KINDS)-observed),
                legacy=legacy, limits=LIMITS)


def build_guards(root):
    folder = root/'main/expanded'
    doc = json.loads((folder/'build-receipt.json').read_text())
    main, runtime = (folder/'main-os.bin').read_bytes(), (folder/'runtime.bin').read_bytes()
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    if (doc['build'] != 'R008' or sha(main) != MAIN_SHA or sha(runtime) != RUNTIME_SHA
            or doc['main_sha256'] != MAIN_SHA or doc['runtime_sha256'] != RUNTIME_SHA
            or doc['runtime_copy'] != dict(source='0x4033259c', destination='0x47a58000', bytes=420464)):
        raise ValueError('Local MAIN/runtime differs from pinned R008 without CF observers')
    expected = {}
    for at, size in C.GUARDS:
        source, offset = (runtime, at-0x47a58000) if at >= 0x47a58000 else (main, at-0x40000400)
        expected[at] = source[offset:offset+size]
        if len(expected[at]) != size:
            raise ValueError('Truncated local guard bytes')
    dsp = json.loads((root/'dsp/build-receipt.json').read_text())
    raw = (root/'dsp/section_7.bin').read_bytes()
    cfg = dsp['usb_guard_reasons']
    if (cfg['base_sha256'] != DSP_PARENT_SHA or sha(raw) != DSP_SHA
            or dsp['section7_sha256'] != DSP_SHA):
        raise ValueError('Local DSP journal lineage/hash mismatch')
    fixed = dict(schema='R008-UGR8-v1', phase=15, marker_base='0x4f53e800', marker_mask='0xfffffcc0',
                 kind_shift=8, kind_mask=3, cycle_shift=5, field_mask=31, fields=28,
                 hold_calls=16, slots_per_cycle=31, legacy_slots=3, checksum_seed='0x55475238',
                 checksum='seed XOR kind, then ROL32(acc,5) XOR word for words0..26')
    if (any(cfg['publication'].get(k) != v for k, v in fixed.items())
            or cfg['record_fields'] != EVENT_FIELDS or cfg['record_bytes'] != 112
            or set(cfg['reason_map']) != {str(i) for i in range(1, 41)}
            or set(cfg['valid_mask']) != {'1', '2', '4', '8', '16', '32'}):
        raise ValueError('Unsupported R008 journal wire schema')
    return expected, dsp['section7_sha256'], cfg


def capture(out, seconds, root, port='Elektron Digitone II'):
    if type(seconds) is not int or not 12 <= seconds <= 54:
        raise ValueError('Capture duration must be 12..54 seconds')
    expected, dsp_sha, cfg = build_guards(root)
    import readonly_transport as T
    T.require_private_output(out)
    allowed = {(0x47aa5a0c, 4), (0x800053a4, 28), (0x4058dee8, 4),
               (0x402cf894, 24), (0x402d06c4, 20), (0x47a9d9ac, 16), (0x47ab7708, 12)}
    allowed.update((at, len(raw)) for at, raw in expected.items())
    out.mkdir(parents=True, exist_ok=False)
    banks = {}
    result = dict(started=T.now(), read_only=True, screen_polling=False, coreaudio_opened=False,
                  device_writes=False, expected_build='R008', expected_main_sha256=MAIN_SHA,
                  expected_dsp_sha256=dsp_sha, live_dsp_hash_verified=False, seconds_requested=seconds,
                  cf_timer_hz=C.CF_HZ, snapshots=[], phase_windows={}, errors=[], requests=0, extra_requests=0,
                  sampling_policy='250ms base; prearm only phase14 low10>=768 with25ms waits; '
                  'phase15 uses existing approximately6ms PEEK roundtrip. Extra reads capped at110 '
                  'per heartbeat>>14 window and550 total;1000 total requests;60s harddeadline. '
                  'Stop burst after a checked journal, phase exit, budget or capture end. '
                  'Each extra read adds one MIDI PEEK request/reply and28B payload plus framing.', limits=LIMITS)
    started = time.monotonic()
    save = lambda: (out/'capture.json').write_text(json.dumps(result, indent=2)+'\n')
    try:
        with (out/'wire.jsonl').open('w', buffering=1) as wire, T.device(port) as (api, incoming):
            client = T.ReadOnlyClient(incoming, api, lambda e: wire.write(json.dumps(e)+'\n'), allowed)
            client.set_deadline(started+60)

            def peek(at, size):
                if (at, size) not in allowed or result['requests'] >= MAX_REQUESTS:
                    raise ValueError('Outside fixed R008 read allowlist/request budget')
                result['requests'] += 1
                return T.peek(client, at, size)

            def read_header(sampling):
                row = dict(at=T.now(), begin=time.monotonic(), sampling=sampling)
                result['snapshots'].append(row)
                row['decoded'] = decode(peek(0x800053a4, 28))
                row['end'] = time.monotonic()
                bank = add_chunk(banks, row['decoded'], row['at'])
                if bank and assess(bank)['valid']:
                    window = str(row['decoded']['heartbeat'] >> 14)
                    result['phase_windows'].setdefault(window, dict(extra_requests=0))['complete'] = True
                return row

            def hello():
                if result['requests'] >= MAX_REQUESTS:
                    raise ValueError('R008 request budget exhausted')
                result['requests'] += 1
                return T.decode_hello(client.call(1))

            result['build'] = peek(0x47aa5a0c, 4).decode('ascii')
            if result['build'] != 'R008':
                raise ValueError('Expected installed R008')
            result['hook_checks'] = {hex(at): peek(at, len(raw)) == raw for at, raw in expected.items()}
            if not all(result['hook_checks'].values()):
                raise ValueError('Live MAIN hook mismatch')
            result['hello'] = hello()
            first = time.monotonic()
            for index in range(seconds*4+1):
                time.sleep(max(0, first+index*.25-time.monotonic()))
                row = read_header('base')
                if index % 8 == 0 or index == seconds*4:
                    row['context'] = context = {}
                    t0 = time.monotonic()
                    context['profile'] = C.words(peek(0x402cf894, 24))
                    context['profile_time'] = (t0+time.monotonic())/2
                    context['extra'] = C.words(peek(0x402d06c4, 20))
                    context['usb_collection'] = C.words(peek(0x4058dee8, 4))[0]
                    context['sample_restore'] = C.words(peek(0x47a9d9ac, 16))
                    context['recorder_command_control'] = peek(0x47ab7708, 12).hex()
                save()
                while time.monotonic()+.03 < first+seconds and result['extra_requests'] < MAX_EXTRA:
                    d = row['decoded']
                    if not d.get('checks_passed'):
                        break
                    heartbeat = d['heartbeat']
                    phase = (heartbeat >> 10) & 15
                    prearm = phase == 14 and heartbeat & 1023 >= 768
                    if not prearm and phase != 15:
                        break
                    window = result['phase_windows'].setdefault(str(heartbeat >> 14), dict(extra_requests=0))
                    if window.get('complete') or window['extra_requests'] >= MAX_WINDOW:
                        break
                    if prearm:
                        time.sleep(.025)
                    window['extra_requests'] += 1
                    result['extra_requests'] += 1
                    row = read_header('prearm' if prearm else 'phase15-burst')
                    save()
            result['build_after'] = peek(0x47aa5a0c, 4).decode('ascii')
            if result['build_after'] != 'R008':
                raise ValueError('Build changed during capture')
            result['hello_after'] = hello()
    except Exception as exc:
        result['errors'].append(f'{type(exc).__name__}: {exc}')
    result.update(finished=T.now(), elapsed_seconds=time.monotonic()-started,
                  cf_deltas=C.cf_deltas(result['snapshots']))
    save()
    summary = summarize(result['snapshots'], banks, cfg['reason_map'])
    summary['reason_map'] = cfg['reason_map']
    (out/'journal-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(dict(output=str(out), errors=result['errors'], requests=result['requests'],
                         extra_requests=result['extra_requests'], kinds_observed=summary['kinds_observed'],
                         kinds_missing=summary['kinds_missing'])))
    return bool(result['errors'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--seconds', type=int, choices=range(12, 55), default=54)
    parser.add_argument('--build-dir', type=Path, required=True, help='Private matching build tree')
    parser.add_argument('--port', default='Elektron Digitone II')
    args = parser.parse_args()
    raise SystemExit(capture(args.out, args.seconds, args.build_dir, args.port))
