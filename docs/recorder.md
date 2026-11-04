# Recording and resampling

R013, R012 and R011 include the Recorder introduced by R003 alongside the sample Machines
and 42-channel USB audio. The workflow includes source selection, recording, normalization,
trim and audition controls, saving to +Drive, and optional track assignment.
VOICE cycles through Voice Setup, Sample Manager and Recorder.

**R013 is the current candidate and preserves the R012 Recorder.**
Owner testing on R012 confirmed Recorder operation,
stock audio, samples and USB audio, including after changing projects.
R003 remains a historical experimental target.
R003 hardware boot, stock audio, MAIN recording, saving and Recorder reopening have passed. Hardware
trimmed-file comparison, power-cycle persistence and long-duration USB stress
testing remain pending. See [R003 evidence and limits](research/2026-10-31.md).

## Build locally

Follow the [tool setup](../port/tools/README.md) and [private input
requirements](../README.md#private-inputs) first. For R013, follow the
[default two-file build](../README.md#build); no sample bank is required.
The command below reproduces historical R003 and requires its original private
test bank, which is not DT2 factory content.

```sh
python build.py --target R003 \
  --dn2 /path/to/Digitone_II_OS1.11.syx \
  --dt2 /path/to/Digitakt_II_OS1.16.syx \
  --sample-bank /private/path/to/sample-bank.bin \
  --out /private/builds/R003.syx
```

The builder reconstructs T1E2, applies the Recorder stages, packs the MAIN tail,
and verifies the final section and SysEx hashes. Outputs must remain outside
the source repository. Existing outputs are never overwritten; the builder
does not access MIDI or flash a device.

Expected output: **2,585,376 bytes**, SHA-256
`eb3030563bb863df771980cbba46f981511935ccf5e89fb2ae668ff90edbd169`.
The [R003 manifest](../releases/r003.json) records identities and validation scope.

Verified on October 31, 2026: a clean export of the public source rebuilt the
complete T1E2 baseline and R003 extension with the pinned toolchain and three
private inputs. Final MAIN, DSP and SysEx matched exactly. No prior Recorder
firmware or private research checkout was required.

## Record, trim and save

1. From a track page, press plain **VOICE** three times to open Recorder.
   **FUNC + VOICE** remains the unison shortcut.
2. Choose **SRC MAIN** to record the main mix. **IN** selects the physical
   inputs; USB and individual tracks are also available. MAIN is the source
   verified on hardware in this round.
3. Set recording length and threshold as needed. Arm using **H/ARM**, then
   press **YES** to start. Play the material to record; press **YES** to stop.
4. On the trim page, use **E** for start and **H** for end. **F** controls zoom
   and **G** pans the view. **FUNC + YES** auditions the selected range.
5. Press **YES**, enter a new filename and confirm to save. Recorded files
   appear in the +Drive `recorded` directory. At the assignment prompt,
   assign the sample or press **NO** to decline.
6. Close Recorder and reopen it through the VOICE pages. The retained take's
   waveform and trim range should be available. Saving audio and assigning it
   to a track are separate actions; save the project to retain assignments.

Use a new filename for a trimmed copy when preserving the original. The trim
and save path passed native instruction checks; the current hardware test has
not yet completed the trimmed-file comparison. A successful source build does
not certify every Recorder source or real-time workload.

## What changed from T1E2

The DT2 Recorder UI and DSP routines are extracted from the supplied official
firmware. Adapters bind them to DN2 controls, fonts, tempo and source routing.
Recorder replies own the shared meter fields only while Recorder is enabled;
control snapshots and scalar acknowledgments avoid stale controls and adjacent
USB sample writes. Reopening uses retained-take metadata instead of interpreting
closed-mode diagnostic replies as the take length.

R003 also repairs a confirmed MAIN-loader input overlap by restoring a
separately compressed tail before original startup. Protected loader sections,
panel firmware and flash writer remain unchanged. R003 excludes later USB
queues, scheduling and timing changes; R011 and R012 include the
[USB publication changes](usb-research.md).
