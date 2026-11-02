#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded R007 HELLO/PEEK diagnostics; no audio-device, screen or control operations."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import time

MAIN_SHA = '234307ccb14d4502d745579880a698233c5749bef06dd192b9a913168bbe4c0b'
RUNTIME_SHA = '41ddec95e5ab29f036ff94b7e67a808c775b435a5674d7403ae2ab19517b8635'
DSP_PARENT_SHA = '57be61eb71d41dcb164ecedbb32ea7fd92eae493512d737260466865f5a32e0c'
MASK = 0xffffffff
CF_HZ = 132000000
NEW_TAGS = {'4f53dc1f', '4f53dc20', '4f53dc21'}
BURST_DELAYS = (.007, .0115, .01725)
GUARDS = ((0x400cf7f2, 6), (0x400cf990, 16), (0x47aada56, 6), (0x47aadc92, 10),
          (0x400276b2, 6), (0x400279ba, 6), (0x40003d00, 6),
          (0x402cf540, 64), (0x402d0668, 80))
# Payloads are already canonical CF big-endian32 after the DSP's halfword swap.
# Kind distinguishes cumulative counters, last measurements, maxima and frozen words.
TAGS = {
    0xdc00: (None, ('last_render_cycles', 'last'), ('max_render_cycles', 'maximum')),
    0xdc01: (None, ('completed_renders', 'counter'), ('overbudget_renders', 'counter')),
    0xdc10: ((0,), ('last_render_cycles', 'last'), ('max_render_cycles', 'maximum')),
    0xdc11: ((1,), ('completed_renders', 'counter'), ('overbudget_renders', 'counter')),
    0xdc12: ((2,), ('backlog_skips', 'counter'), ('max_notification_count', 'maximum')),
    0xdc13: ((3,), ('last_callback_to_start_cycles', 'last'), ('max_callback_to_start_cycles', 'maximum')),
    0xdc14: ((4,), ('last_callback_to_staged_pcm_cycles', 'last'), ('max_callback_to_staged_pcm_cycles', 'maximum')),
    0xdc15: ((5,), ('busy_callbacks', 'counter'), ('crossed_completions', 'counter')),
    0xdc16: ((6, 7), ('callback_generation', 'counter'), ('valid_completions', 'counter')),
    0xdc17: ((8,), ('tx_sport_error_callbacks', 'counter'), ('rx_sport_error_callbacks', 'counter')),
    0xdc18: ((9,), ('tx_sport_error_raw_or', 'flags'), ('rx_sport_error_raw_or', 'flags')),
    0xdc19: ((10,), ('codec_copy_windows', 'counter'), ('same_page_candidates', 'counter')),
    0xdc1a: ((11,), ('frozen_before_dma_current', 'frozen'), ('frozen_after_dma_current', 'frozen')),
    0xdc1b: ((12,), ('frozen_before_dma_start', 'frozen'), ('frozen_after_dma_start', 'frozen')),
    0xdc1c: ((13,), ('frozen_before_dma_status', 'frozen'), ('frozen_after_dma_status', 'frozen')),
    0xdc1d: ((14,), ('frozen_cpu_write_base', 'frozen'), ('frozen_identity_flags', 'frozen')),
    0xdc1f: ((15,), ('zero_commits', 'counter'), ('discarded_on_skip', 'counter')),
    0xdc20: ((15,), ('usb_guard_accepted', 'counter'), ('usb_guard_rejected', 'counter')),
    0xdc21: ((15,), ('postexport_cross_or_late_events', 'counter'), ('max_accepted_elapsed_cycles', 'maximum')),
}
LIMITS = ('Headers have no sequence/checksum: phase and plausibility checks do not prove atomicity. '
          'Sparse counter observations are not audible-fault measurements. Counter decreases mean '
          'wrap, reset or inconsistent publication; no automatic unsigned growth is inferred. '
          'Maxima are retained since boot. DSP cycles use nominal 1 GHz; CF ticks use 132 MHz. '
          'DC14 measures private staged PCM completion; codec copy occurs earlier. '
          'A same-page candidate or guard event is not proof of DAC corruption.')


def words(raw):
    return list(struct.unpack('>'+str(len(raw)//4)+'I', raw))


def decode(raw):
    result = dict(raw=raw.hex(), recognized=False, checks_passed=False, atomic=False)
    if len(raw) != 28:
        return dict(result, rejected_because=['header must contain 28 bytes'])
    w = words(raw)
    result.update(words=[f'{v:08x}' for v in w], marker=f'{w[1]:08x}', heartbeat=w[2])
    tag = w[1] & 0xffff
    if w[1] >> 16 != 0x4f53 or tag not in TAGS:
        return dict(result, rejected_because=['unknown R007 tag'])
    phases, left, right = TAGS[tag]
    phase = (w[2] >> 10) & 15
    reasons = []
    if phases is not None and phase not in phases:
        reasons.append('tag does not match heartbeat phase')
    if tag == 0xdc01 and (w[3] >> 10) & 1 != 1:
        reasons.append('legacy exit tag does not match completed-render phase')
    if tag in (0xdc00, 0xdc10, 0xdc13, 0xdc14) and w[4] < w[3]:
        reasons.append('maximum smaller than last measurement')
    if tag in (0xdc01, 0xdc11, 0xdc15, 0xdc19) and w[4] > w[3]:
        reasons.append('subset counter exceeds total')
    if tag == 0xdc12 and w[3] and w[4] < 2:
        reasons.append('skip count without a backlog maximum')
    if tag == 0xdc1d:
        identity, flags = w[4] >> 8, w[4] & 255
        good = identity in (0, 1, 2) and not flags & 128
        if flags & 1:
            good &= (identity in (1, 2) and w[3] in (0x2c0478, 0x2c0578)
                     and bool(flags & 64) and bool(flags & 32) == (identity == 2)
                     and bool(flags & 32) == bool(flags & 24)
                     and (not flags & 8 or bool(flags & 2))
                     and (not flags & 16 or bool(flags & 4)))
        else:
            good &= identity == flags == w[3] == 0
        if not good:
            reasons.append('inconsistent frozen codec identity')
    result.update(recognized=True, checks_passed=not reasons, rejected_because=reasons,
                  publisher_phase=phase, fields={left[0]: w[3], right[0]: w[4]},
                  kinds={left[0]: left[1], right[0]: right[1]})
    return result


def summarize(snapshots):
    tags, unknown = {}, {}
    for row in snapshots:
        d = row.get('decoded', {})
        marker = d.get('marker', 'malformed')
        if not d.get('checks_passed'):
            unknown[marker] = unknown.get(marker, 0)+1
            continue
        group = tags.setdefault(marker, dict(samples=0, first_at=row['at'], last_at=row['at'], fields={}))
        group['samples'] += 1
        group['last_at'] = row['at']
        for name, value in d['fields'].items():
            kind = d['kinds'][name]
            field = group['fields'].setdefault(name, dict(kind=kind, first=value, last=value,
                                                         min_observed=value, max_observed=value, decreased=False))
            field['decreased'] |= value < field['last']
            field.update(last=value, min_observed=min(value, field['min_observed']),
                         max_observed=max(value, field['max_observed']))
    for group in tags.values():
        for field in group['fields'].values():
            if field['kind'] == 'counter':
                field['delta'] = field['last']-field['first'] if group['samples'] > 1 and not field['decreased'] else None
                if field['delta'] is None:
                    field['delta_unavailable'] = 'counter decreased: wrap/reset/publication ambiguity' if field['decreased'] else 'one observation'
    return dict(tags=tags, rejected_or_unknown=unknown,
                new_tags_observed=sorted(NEW_TAGS & tags.keys()),
                new_tags_missing=sorted(NEW_TAGS-tags.keys()),
                new_tags_with_multiple_observations=sorted(t for t in NEW_TAGS & tags.keys() if tags[t]['samples'] > 1),
                limits=LIMITS)


def phase15_burst_delay(decoded, windows):
    """Reserve one bounded extra read only while a new phase15 tag is visible."""
    if not decoded.get('checks_passed') or decoded.get('marker') not in NEW_TAGS:
        return None
    key = str(decoded['heartbeat'] >> 14)
    window = windows.setdefault(key, dict(tags_seen=[], extra_reads_scheduled=0))
    if decoded['marker'] not in window['tags_seen']:
        window['tags_seen'].append(decoded['marker'])
    count = window['extra_reads_scheduled']
    if (len(window['tags_seen']) == 3 or count >= 12
            or sum(w['extra_reads_scheduled'] for w in windows.values()) >= 36):
        return None
    window['extra_reads_scheduled'] += 1
    return BURST_DELAYS[count % 3]


def cf_deltas(snapshots):
    rows = [r['context'] for r in snapshots
            if all(k in r.get('context', {}) for k in ('profile', 'profile_time', 'extra'))]
    result = []
    for a, b in zip(rows, rows[1:]):
        dt = b['profile_time']-a['profile_time']
        if not 0 < dt < 32:
            continue
        ticks = (b['profile'][0]-a['profile'][0]) & MASK
        count = (b['profile'][1]-a['profile'][1]) & MASK
        over = (b['extra'][0]-a['extra'][0]) & MASK
        plausible = count <= dt*3000+10 and over <= count and ticks <= CF_HZ*(dt+.1)
        result.append(dict(seconds=dt, plausible=plausible, callback_delta=count,
                           elapsed_tick_delta=ticks, threshold_delta=over,
                           mean_handler_us=ticks/132/count if count and plausible else None,
                           handler_wall_share_percent=ticks/CF_HZ/dt*100 if plausible else None))
    return result


def build_guards(root):
    folder = root/'main/expanded'
    doc = json.loads((folder/'build-receipt.json').read_text())
    main, runtime = (folder/'main-os.bin').read_bytes(), (folder/'runtime.bin').read_bytes()
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    if (doc['build'] != 'R007' or sha(main) != MAIN_SHA or sha(runtime) != RUNTIME_SHA
            or doc['main_sha256'] != MAIN_SHA or doc['runtime_sha256'] != RUNTIME_SHA
            or doc['runtime_copy'] != dict(source='0x4033259c', destination='0x47a58000', bytes=420464)):
        raise ValueError('Local MAIN/runtime differs from pinned R007 without CF timing observers')
    expected = {}
    for at, size in GUARDS:
        source, offset = (runtime, at-0x47a58000) if at >= 0x47a58000 else (main, at-0x40000400)
        expected[at] = source[offset:offset+size]
        if len(expected[at]) != size:
            raise ValueError('Truncated local guard bytes')
    dsp = json.loads((root/'dsp/build-receipt.json').read_text())
    raw = (root/'dsp/section_7.bin').read_bytes()
    cfg = dsp['usb_guarded_publication']
    if cfg['base_sha256'] != DSP_PARENT_SHA or sha(raw) != dsp['section7_sha256']:
        raise ValueError('Local DSP guard lineage/hash mismatch')
    return expected, dsp['section7_sha256']


def capture(out, seconds, root, port='Elektron Digitone II'):
    if type(seconds) is not int or not 6 <= seconds <= 30:
        raise ValueError('Capture duration must be 6..30 seconds')
    expected, dsp_sha = build_guards(root)
    # Imports are confined to live entry; decoder tests never load MIDI/CoreAudio.
    import readonly_transport as T
    T.require_private_output(out)
    allowed = {(0x47aa5a0c, 4), (0x800053a4, 28), (0x4058dee8, 4),
               (0x402cf894, 24), (0x402d06c4, 20), (0x47a9d9ac, 16), (0x47ab7708, 12)}
    allowed.update((at, len(raw)) for at, raw in expected.items())
    out.mkdir(parents=True, exist_ok=False)
    result = dict(started=T.now(), read_only=True, screen_polling=False, coreaudio_opened=False,
                  device_writes=False, expected_build='R007', expected_main_sha256=MAIN_SHA,
                  expected_dsp_sha256=dsp_sha, live_dsp_hash_verified=False,
                  cf_timer_hz=CF_HZ,
                  cf_profile_fields=['isr_ticks', 'callbacks', 'max_handler_ticks', 'isr_in_idle_ticks', 'idle_ticks', 'switches'],
                  cf_extra_fields=['isr_over_threshold', 'idle_in', 'idle_out', 'idle_offpc', 'idle_lastpc'],
                  cf_scope='Handler elapsed includes IRQ preemption; means are not total task or DSP load.',
                  seconds_requested=seconds, sample_period_seconds=.25, snapshots=[], errors=[], limits=LIMITS,
                  phase15_windows={},
                  sampling_policy='Base header every 250ms. A valid DC1F/DC20/DC21 starts extra cached 28B '
                  'reads after 7/11.5/17.25ms repeating, stopping after all three tags, leaving phase 15, '
                  '12 extra reads per heartbeat>>14 window, 36 extra reads total, or capture end. '
                  'Each extra read adds one MIDI SysEx PEEK request/reply pair: at most 1008B '
                  'additional reply payload plus framing. Probe work can perturb timing.')
    started = time.monotonic()
    save = lambda: (out/'capture.json').write_text(json.dumps(result, indent=2)+'\n')
    try:
        with (out/'wire.jsonl').open('w', buffering=1) as wire, T.device(port) as (api, incoming):
            client = T.ReadOnlyClient(incoming, api, lambda e: wire.write(json.dumps(e)+'\n'), allowed)
            client.set_deadline(started+40)

            def peek(at, size):
                if (at, size) not in allowed:
                    raise ValueError('Outside fixed R007 read allowlist')
                return T.peek(client, at, size)

            def read_header(kind):
                row = dict(at=T.now(), begin=time.monotonic(), sampling=kind)
                result['snapshots'].append(row)
                row['decoded'] = decode(peek(0x800053a4, 28))
                row['end'] = time.monotonic()
                return row

            result['build'] = peek(0x47aa5a0c, 4).decode('ascii')
            if result['build'] != 'R007':
                raise ValueError('Expected installed R007; no diagnostic reads attempted')
            result['hook_checks'] = {hex(at): peek(at, len(raw)) == raw for at, raw in expected.items()}
            if not all(result['hook_checks'].values()):
                raise ValueError('Live MAIN hook mismatch')
            result['hello'] = T.decode_hello(client.call(1))
            first = time.monotonic()
            for index in range(seconds*4+1):
                time.sleep(max(0, first+index*.25-time.monotonic()))
                row = read_header('base')
                if index % 8 == 0 or index == seconds*4:
                    row['context'] = context = {}
                    t0 = time.monotonic()
                    context['profile'] = words(peek(0x402cf894, 24))
                    context['profile_time'] = (t0+time.monotonic())/2
                    context['extra'] = words(peek(0x402d06c4, 20))
                    context['usb_collection'] = words(peek(0x4058dee8, 4))[0]
                    context['sample_restore'] = words(peek(0x47a9d9ac, 16))
                    context['recorder_command_control'] = peek(0x47ab7708, 12).hex()
                row['end'] = time.monotonic()
                save()
                while time.monotonic()+max(BURST_DELAYS) < first+seconds:
                    delay = phase15_burst_delay(row['decoded'], result['phase15_windows'])
                    if delay is None:
                        break
                    time.sleep(delay)
                    row = read_header('phase15-burst')
                    save()
            result['build_after'] = peek(0x47aa5a0c, 4).decode('ascii')
            if result['build_after'] != 'R007':
                raise ValueError('Build changed during capture')
            result['hello_after'] = T.decode_hello(client.call(1))
    except Exception as exc:
        result['errors'].append(f'{type(exc).__name__}: {exc}')
    result.update(finished=T.now(), elapsed_seconds=time.monotonic()-started,
                  cf_deltas=cf_deltas(result['snapshots']),
                  extra_header_requests=sum(r.get('sampling') == 'phase15-burst' for r in result['snapshots']))
    save()
    summary = summarize(result['snapshots'])
    (out/'tag-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(dict(output=str(out), errors=result['errors'], samples=len(result['snapshots']),
                         extra_header_requests=result['extra_header_requests'],
                         new_tags_observed=summary['new_tags_observed'], new_tags_missing=summary['new_tags_missing'])))
    return bool(result['errors'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--seconds', type=int, choices=range(6, 31), default=24)
    parser.add_argument('--build-dir', type=Path, required=True, help='Private matching build tree')
    parser.add_argument('--port', default='Elektron Digitone II')
    args = parser.parse_args()
    raise SystemExit(capture(args.out, args.seconds, args.build_dir, args.port))
