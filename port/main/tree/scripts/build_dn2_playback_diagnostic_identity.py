#!/usr/bin/env python3
"""Give the playback diagnostic a distinct MAIN identity; behavior is unchanged."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

BASE = 0x40000400
sha = lambda data: hashlib.sha256(data).hexdigest()


def build(source, out, fatal_diagnostic=False, code_diagnostic=False, decimator_l2=False, l1_code_fix=False, waveform_coherency_fix=False, stereo_rate_fix=False, stretch_rate_fix=False, samp_slot_display=False, cursor_stop_fix=False, preview_audio_fix=False, encoder_sensitivity=False, sampler_start_fix=False, block_timing_diagnostic=False, timing_publication=False, scheduler_backlog=False, output_deadline=False, codec_usb_capture=False, codec_usb_capture_fix=False, codec_delivery=False, codec_stage_commit=False):
    doc = json.loads((source / 'build-receipt.json').read_text())
    raw = (source / 'main-os.bin').read_bytes()
    assert sha(raw) == doc['main_sha256']
    assert 'sample_load_error_fix' in doc
    copy = doc['runtime_copy']
    start = int(copy['source'], 16) - BASE
    marker = int(doc['dsp_transfer_wait']['methods']['transfer_identity'], 16)
    offset = start + marker - int(copy['destination'], 16)
    assert sum((fatal_diagnostic, code_diagnostic, decimator_l2, l1_code_fix, waveform_coherency_fix, stereo_rate_fix, stretch_rate_fix, samp_slot_display, cursor_stop_fix, preview_audio_fix, encoder_sensitivity, sampler_start_fix, block_timing_diagnostic, timing_publication, scheduler_backlog, output_deadline, codec_usb_capture, codec_usb_capture_fix, codec_delivery, codec_stage_commit)) <= 1
    before, after = ((0x54314453, 0x54314454) if codec_stage_commit else
                     (0x54314452, 0x54314453) if codec_delivery else
                     (0x54314451, 0x54314452) if codec_usb_capture_fix else
                     (0x54314450, 0x54314451) if codec_usb_capture else
                     (0x5431444F, 0x54314450) if output_deadline else
                     (0x5431444E, 0x5431444F) if scheduler_backlog else
                     (0x5431444D, 0x5431444E) if timing_publication else
                     (0x5431444C, 0x5431444D) if block_timing_diagnostic else
                     (0x5431444B, 0x5431444C) if sampler_start_fix else
                     (0x5431444A, 0x5431444B) if encoder_sensitivity else
                     (0x54314449, 0x5431444A) if preview_audio_fix else
                     (0x54314448, 0x54314449) if cursor_stop_fix else
                     (0x54314447, 0x54314448) if samp_slot_display else
                     (0x54314446, 0x54314447) if stretch_rate_fix else
                     (0x54314445, 0x54314446) if stereo_rate_fix else
                     (0x54314444, 0x54314445) if waveform_coherency_fix else
                     (0x54314443, 0x54314444) if l1_code_fix else
                     (0x54314442, 0x54314443) if decimator_l2 else
                     (0x54314441, 0x54314442) if code_diagnostic else
                     (0x54314439, 0x54314441) if fatal_diagnostic else (0x54314438, 0x54314439))
    identity = 'T1DT' if codec_stage_commit else 'T1DS' if codec_delivery else 'T1DR' if codec_usb_capture_fix else 'T1DQ' if codec_usb_capture else 'T1DP' if output_deadline else 'T1DO' if scheduler_backlog else 'T1DN' if timing_publication else 'T1DM' if block_timing_diagnostic else 'T1DL' if sampler_start_fix else 'T1DK' if encoder_sensitivity else 'T1DJ' if preview_audio_fix else 'T1DI' if cursor_stop_fix else 'T1DH' if samp_slot_display else 'T1DG' if stretch_rate_fix else 'T1DF' if stereo_rate_fix else 'T1DE' if waveform_coherency_fix else 'T1DD' if l1_code_fix else 'T1DC' if decimator_l2 else 'T1DB' if code_diagnostic else 'T1DA' if fatal_diagnostic else 'T1D9'
    stem = 'codec-stage-commit' if codec_stage_commit else 'codec-delivery' if codec_delivery else 'codec-usb-capture-fix' if codec_usb_capture_fix else 'codec-usb-capture' if codec_usb_capture else 'output-deadline' if output_deadline else 'scheduler-backlog' if scheduler_backlog else 'timing-publication' if timing_publication else 'block-timing-diagnostic' if block_timing_diagnostic else 'sampler-start-fix' if sampler_start_fix else 'encoder-sensitivity' if encoder_sensitivity else 'preview-audio-fix' if preview_audio_fix else 'cursor-stop-fix' if cursor_stop_fix else 'samp-slot-display' if samp_slot_display else 'stretch-rate-fix' if stretch_rate_fix else 'stereo-rate-fix' if stereo_rate_fix else 'waveform-coherency-fix' if waveform_coherency_fix else 'l1-code-fix' if l1_code_fix else 'decimator-l2' if decimator_l2 else 'code-diagnostic' if code_diagnostic else 'fatal-diagnostic' if fatal_diagnostic else 'playback-diagnostic'
    assert struct.unpack_from('>I', raw, offset)[0] == before
    image = bytearray(raw)
    struct.pack_into('>I', image, offset, after)
    changes = [i for i, (a, b) in enumerate(zip(raw, image)) if a != b]
    assert changes == [offset + 3]
    payload = image[start:start + copy['bytes']]
    doc.update(main_sha256=sha(image), runtime_sha256=sha(payload), flash_ready=False)
    doc['codec_stage_commit_identity' if codec_stage_commit else 'codec_delivery_identity' if codec_delivery else 'codec_usb_capture_fix_identity' if codec_usb_capture_fix else 'codec_usb_capture_identity' if codec_usb_capture else 'output_deadline_identity' if output_deadline else 'scheduler_backlog_identity' if scheduler_backlog else 'timing_publication_identity' if timing_publication else 'block_timing_diagnostic_identity' if block_timing_diagnostic else 'sampler_start_fix_identity' if sampler_start_fix else 'encoder_sensitivity_identity' if encoder_sensitivity else 'preview_audio_fix_identity' if preview_audio_fix else 'cursor_stop_fix_identity' if cursor_stop_fix else 'samp_slot_display_identity' if samp_slot_display else 'stretch_rate_fix_identity' if stretch_rate_fix else 'stereo_rate_fix_identity' if stereo_rate_fix else 'waveform_coherency_fix_identity' if waveform_coherency_fix else 'l1_code_fix_identity' if l1_code_fix else 'decimator_l2_identity' if decimator_l2 else 'code_diagnostic_identity' if code_diagnostic else 'fatal_diagnostic_identity' if fatal_diagnostic else 'playback_diagnostic_identity'] = dict(
        baseline_sha256=sha(raw), baseline_source=str(source.resolve()), address=hex(marker),
        before=hex(before), after=hex(after),
        scope='One identification byte only; input MAIN behavior retained.')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'main-os.bin').write_bytes(image)
    (out / 'runtime.bin').write_bytes(payload)
    (out / 'build-receipt.json').write_text(json.dumps(doc, indent=2) + '\n')
    for name in ('bootstrap.S', 'fn_new_map.txt', 'ram_map.txt'):
        (out / name).write_bytes((source / name).read_bytes())
    check = dict(ok=True, main_sha256=sha(image), baseline_sha256=sha(raw),
                 bytes_changed=1, identity_address=hex(marker), identity=identity,
                 scope='Exact byte comparison; no gameplay or loader code changed.')
    (out / (stem + '-identity-check.json')).write_text(json.dumps(check, indent=2) + '\n')
    print(json.dumps(check, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--fatal-diagnostic', action='store_true')
    parser.add_argument('--code-diagnostic', action='store_true')
    parser.add_argument('--decimator-l2', action='store_true')
    parser.add_argument('--l1-code-fix', action='store_true')
    parser.add_argument('--waveform-coherency-fix', action='store_true')
    parser.add_argument('--stereo-rate-fix', action='store_true')
    parser.add_argument('--stretch-rate-fix', action='store_true')
    parser.add_argument('--samp-slot-display', action='store_true')
    parser.add_argument('--cursor-stop-fix', action='store_true')
    parser.add_argument('--preview-audio-fix', action='store_true')
    parser.add_argument('--encoder-sensitivity', action='store_true')
    parser.add_argument('--sampler-start-fix', action='store_true')
    parser.add_argument('--block-timing-diagnostic', action='store_true')
    parser.add_argument('--timing-publication', action='store_true')
    parser.add_argument('--scheduler-backlog', action='store_true')
    parser.add_argument('--output-deadline', action='store_true')
    parser.add_argument('--codec-usb-capture', action='store_true')
    parser.add_argument('--codec-usb-capture-fix', action='store_true')
    parser.add_argument('--codec-delivery', action='store_true')
    parser.add_argument('--codec-stage-commit', action='store_true')
    args = parser.parse_args()
    build(args.source, args.out, args.fatal_diagnostic, args.code_diagnostic, args.decimator_l2, args.l1_code_fix, args.waveform_coherency_fix, args.stereo_rate_fix, args.stretch_rate_fix, args.samp_slot_display, args.cursor_stop_fix, args.preview_audio_fix, args.encoder_sensitivity, args.sampler_start_fix, args.block_timing_diagnostic, args.timing_publication, args.scheduler_backlog, args.output_deadline, args.codec_usb_capture, args.codec_usb_capture_fix, args.codec_delivery, args.codec_stage_commit)
