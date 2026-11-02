# Experimental USB diagnostics

R008 contains the six sample Machines, Recorder and 42-channel USB interface,
plus the latest buffer-publication diagnostics. **T1E2 remains stable. R008 is
not a validated USB fix.** Its first hardware capture is pending; R007 has a
confirmed failure where USB audio freezes while headphones and UI keep working.

## Build locally

Follow the [tool setup and private-input instructions](../README.md#build), then
add `--target R008` to the build command:

```sh
python build.py --target R008 \
  --dn2 /private/inputs/Digitone_II_OS1.11.syx \
  --dt2 /private/inputs/Digitakt_II_OS1.16.syx \
  --sample-bank /private/inputs/sample-bank.bin \
  --out /private/builds/R008.syx
```

The same exact private three-slot sample bank is required. It is not DT2 factory
content and is not distributed. Build products must remain outside the source
repository; nothing is flashed automatically.

The recipe rebuilds T1E2, extends it with R003 Recorder, then applies R004 phase
accounting, R005 scratch-memory changes, R007 guarded publication and R008
rejection diagnostics. R006 timing instrumentation is not installed in this
chain. Intermediate build numbers identify research stages, not stable releases.
See [source layout](../port/usb-research/README.md).

Final output: 2,587,936 bytes, SHA-256
`2d2a0fad7af74b5ff1e7b355bc4bccf7e932877cf9736ca416613a699a7d3ece`.
The builder checks MAIN, DSP and complete SysEx identities against the
[release manifest](../releases/r008.json).

On November 2, the exported R008 source reproduced these MAIN, DSP and complete
SysEx identities using the pinned public toolchain and previously source-built
T1E2/R003 private intermediates. The unchanged baseline was not rebuilt again
for this check. No hardware was accessed.

## Capture rejection evidence

The [read-only diagnostic tools](../research/diagnostics/README.md) collect
bounded RAM snapshots over MIDI. They do not open an audio device, poll the
screen, send notes, change transport or modify device parameters. Diagnostic
reads still consume time and can affect timing.

Keep Recorder closed, the same pattern running and the host audio engine
streaming for a matched capture. Do not compare counters from different windows
as though they were simultaneous. An incomplete or conflicting snapshot is
unavailable evidence, not a zero count. Keep raw captures private: they can
contain device state and local paths.

R008 records the first failing predicate, target and DMA tuples with explicit
validity masks. It does not relax ownership checks, change control-frame order,
or claim that register snapshots prove DMA completion. The
[research update](research/2026-11-02.md) explains the evidence and remaining
limits.
