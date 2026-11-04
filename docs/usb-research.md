# R011 USB audio

R011 is the previous stable target. It includes the six sample Machines,
Recorder and 42-channel USB capture, with a fix for USB publication stalling
after project changes. The owner reports normal playback after loading a
different project. Repeated instrumented project-change testing and endurance
remain pending.

R012 carries this USB implementation forward unchanged and removes the private
sample-bank build dependency. R013 preserves this DSP implementation and adds
explicit sample-storage setup. Use the [two-file R013 build](../README.md#build)
for the current candidate. Owner testing confirmed stock audio, samples,
Recorder and USB audio on R012, including after changing projects.

## Reproduce historical R011

Follow the [tool setup and private-input instructions](../README.md#build):

```sh
python build.py --target R011 \
  --dn2 /private/inputs/Digitone_II_OS1.11.syx \
  --dt2 /private/inputs/Digitakt_II_OS1.16.syx \
  --sample-bank /private/inputs/sample-bank.bin \
  --out /private/builds/R011.syx
```

The exact private three-slot sample bank is required. It is not DT2 factory
content and is not distributed. Build products must remain outside the source
repository; nothing is flashed automatically.

The recipe rebuilds T1E2, extends it with R003 Recorder, then applies R004 phase
accounting, R005 scratch-memory changes, R007 guarded publication and R008
rejection diagnostics. R009 adds bounded frame recording; R010 retains completed
audio; R011 corrects SPI destination selection. R006 timing instrumentation is
not installed in this chain. See [source layout](../port/usb-research/README.md).

Final output: **2,591,008 bytes**, SHA-256
`91b32a4d2161a87a4725a2296371e01ee6c7e83a95dccb38fe9f4a8dd2e53b0b`.
The builder checks MAIN, DSP and complete SysEx identities against the
[release manifest](../releases/r011.json). Historical R008 remains available
with `--target R008`; it is a diagnostic target, not the current stable release.

## What R011 changes

R010 retained completed audio, but its SPI destination followed an earlier
render/RX phase. After a project change, the oldest retained block could keep
pointing at the active DMA page. Rendering continued while publication was
rejected, so USB replayed old audio.

R011 chooses a destination candidate from the current DMA START snapshot.
Canonical positive-count transfers nominate the opposite page; count zero
nominates the current page as a drained candidate. This does not grant write
permission. Canonical-page checks, START bracketing, CURRENT bounds, count
margins, freshness and post-copy checks still apply.

Only the oldest retained audio can publish. The SPI write covers audio words
only, preserving the native control prefix and trailer. TDM destination
selection, queue order/capacity, overflow behavior, native callbacks and DMA
descriptors remain unchanged. No new interrupt hook, wait loop or DMA register
write is introduced.

Native execution checks reproduce R010's rejection and exercise R011 progress
for both SPI pages and TDM phases. They also check refusal to overwrite an
unconsumed page, FIFO progression after DMA turnover, and rejection without
live writes for invalid ownership snapshots. These checks do not establish
hardware deadlines or exact alignment between the two transport paths.

## Capture evidence

Keep screen polling off during timing tests. Close Recorder, wait for sample
restoration to finish, and keep the same pattern and host audio settings for a
matched capture. Treat each project as a separate condition. Diagnostic reads
still consume time and can affect timing.

The published [read-only diagnostic tools](../research/diagnostics/README.md)
target historical R007/R008 layouts; they are not an R011 capture command.
Do not compare counters from different windows
as though they were simultaneous. An incomplete or conflicting snapshot is
unavailable evidence, not a zero count. Keep raw captures private: they can
contain device state and local paths.

The [November 3 update](research/2026-11-03.md) separates owner observations,
offline checks and remaining validation work.
