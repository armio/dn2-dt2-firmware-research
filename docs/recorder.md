# Recording and resampling

R027 includes source selection, recording, normalization, trimming, auditioning,
saving to +Drive and optional track assignment. VOICE cycles through Voice Setup,
Sample Manager and Recorder. Sample Machines and 42-channel USB audio (untested
on R027) remain available alongside it.

**R027 is the current candidate; R012 remains stable.** It includes the R016
assignment fix: a failed assignment preserves the original Sound and SAMP value.
A successful assignment on a stock synth track converts it to ONESHOT when
requested. R022 also snapshots Recorder preferences during incremental working
updates without rebuilding unchanged sample identities. This new path has native
replay coverage, not hardware confirmation. See the [R027 manifest](../releases/r027.json).

Owner testing on R012 confirmed Recorder operation, stock audio, samples and USB
audio, including after changing projects. MAIN recording, saving and reopening
also passed earlier hardware checks. The combined offline workflow now covers
normalization, mono/stereo trimming, save/reopen, file download and project
identity restoration. Physical input acquisition, every source, exact hardware
trimmed-file comparison and long-duration USB stress remain incomplete. See
[current test scope](research/2026-11-06.md).

## Build locally

Follow the [tool setup](../port/tools/README.md) and [private input
requirements](../README.md#private-inputs), or use the [browser patcher](browser.md).
The default R027 build ([browser](browser.md)) or the [native R022 build](../README.md#build) needs only the two official OS files;
no sample bank is required. The builder verifies section and SysEx hashes and
does not access MIDI or flash a device.

## Record, trim and save

1. From a track page, press plain **VOICE** three times to open Recorder.
   **FUNC + VOICE** remains the unison shortcut.
2. Choose **SRC MAIN** to record the main mix. **IN** selects the physical
   inputs; USB and individual tracks are also available. MAIN has prior hardware
   confirmation; the R020 cold-boot check did not retest every Recorder source.
3. Set recording length and threshold as needed. Arm using **H/ARM**, then
   press **YES** to start. Play the material to record; press **YES** to stop.
4. On the trim page, use **E** for start and **H** for end. **F** controls zoom
   and **G** pans the view. **FUNC + YES** auditions the selected range.
5. Press **YES**, enter a new filename and confirm to save. Recorded files
   appear in the +Drive `recorded` directory. At the assignment prompt,
   assign the sample or press **NO** to decline.
6. Close Recorder and reopen it through the VOICE pages. The retained take's
   waveform and trim range should be available. Saving audio and assigning it
   to a track are separate actions; save the project to retain assignments in
   its explicit saved checkpoint. See [working-state persistence](samples.md#working-state-saved-projects-and-sample-files).

Use a new filename for a trimmed copy when preserving the original. Wait for the
save to finish before closing Recorder or switching off. The trim/save path
passed native instruction checks; an exact hardware trimmed-file comparison
remains incomplete. A successful source build does not certify every Recorder
source or real-time workload.

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
queues, scheduling and timing changes; R011 through R022 include the
[USB publication changes](usb-research.md).

Historical R003 reproduction and its private-bank requirement remain documented
in the [R003 manifest](../releases/r003.json) and [October 31 update](research/2026-10-31.md).
