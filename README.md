# DN2 DT2 firmware research

Source recipes for reproducing **R011**, designated stable on November 3, 2026.
It adds the six Digitakt II sample Machines, sample browsing, recording and
resampling, and multichannel USB audio to Digitone II. No firmware images or
sample audio are distributed. Build locally from your own firmware inputs.

**R011 fixes the USB publication stall after project changes.** The owner reports
normal playback after loading another project. T1E2 remains available as the
previous stable release. See the [R011 USB guide](docs/usb-research.md) and
[release manifest](releases/r011.json) for changes and validation limits.

**Known issue under investigation:** a sample assigned to track 2 was reported
missing after project loads. The cause and scope are not yet confirmed. Keep
project backups; the stable designation does not mean every workflow is verified.

**Build limitation:** every current target also requires a private project test-sample bank.
This is **not Digitakt II factory content** and cannot be obtained by exporting
samples from a Digitakt II. See [private inputs](#private-inputs) before building.

This project builds on the DN2 research and `dnfw` tooling from
[angellinares/dn2_firmware_explore](https://github.com/angellinares/dn2_firmware_explore),
with firmware container tooling from
[mischa85/elektron-firmware-tool](https://github.com/mischa85/elektron-firmware-tool).
Credit to the upstream authors and contributors for that foundation. See
[source attribution](THIRD_PARTY.md) for component credits and licences.

R011 includes ONESHOT, WERP, STRETCH, REPITCH, GRID and SLICE; stereo samples;
sample browsing; DT2 parameter graphics; SLICES trig mode; and class-compliant
USB audio with 42 capture channels at 48 kHz/24 bit. Its USB return is stereo.
The 21 capture pairs are MAIN, tracks 1–16, DELAY, REVERB, CHORUS and INPUT,
in that order. Individual tracks exclude shared effect returns.

Already running this firmware? See [loading your own samples](docs/samples.md)
for Transfer, +Drive, project loading and track assignment instructions.

Recording includes source selection, trimming, auditioning and saving to +Drive.
Plain **VOICE** cycles through Voice Setup, Sample Manager and Recorder;
**FUNC + VOICE** retains unison. See the [Recorder workflow](docs/recorder.md).

This is a version-specific port, not Elektron's source code. T1E2 is the earlier
stable build without Recorder. R003 and R008 remain available as historical
experimental targets. R011 includes Recorder and the later USB publication work.
Long-duration endurance and exact end-to-end USB latency remain unmeasured.

## Private inputs

The exact build requires official Digitone II OS 1.11, official Digitakt II
OS 1.16, and the original private 47,104-byte three-slot test-sample bank. Sizes and SHA-256
hashes are pinned in [releases/t1e2.json](releases/t1e2.json). Obtain firmware
from Elektron and retain your own copies locally.

The Digitakt II input is its **OS firmware `.syx` file**, from which the build
extracts Machine code and UI assets. The Digitakt II factory sample library is
not a build input.

**`sample-bank.bin` is not included or offered for download.** It is a private
test asset created for this project, separate from both official OS files.
Owning a Digitakt II or exporting its factory samples will not supply this file.
Without the exact bank, the current recipes cannot build any target. Arbitrary WAVs,
an empty file, or samples uploaded through Transfer cannot replace it: the
builder checks the bank's size and hash before building.

A build without this dependency needs its own release and validation; none of
T1E2, R003, R008 or R011 currently provides that. The instructions for [loading playable
samples](docs/samples.md) apply after installation and are a separate workflow.

Check the inputs without changing them:

```sh
python3 tools/check_inputs.py \
  --dn2 /path/to/Digitone_II_OS1.11.syx \
  --dt2 /path/to/Digitakt_II_OS1.16.syx \
  --sample-bank /private/path/to/sample-bank.bin
```

## Build

Use Python 3.12+, Git, Rust/Cargo, GNU Make, a host C compiler, Clang's
preprocessor and zlib headers. See [tool setup](port/tools/README.md) for the
pinned open-source dependencies. All build products stay local; the builder
does not access a MIDI device or flash hardware.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python port/tools/bootstrap.py --prefix .toolchain --jobs 4
python build.py \
  --dn2 /path/to/Digitone_II_OS1.11.syx \
  --dt2 /path/to/Digitakt_II_OS1.16.syx \
  --sample-bank /private/path/to/sample-bank.bin \
  --out /private/builds/R011.syx
```

The output must be outside this repository. An existing output is never
overwritten. Intermediate firmware and diagnostic logs stay in the private
temporary directory printed by the builder; retain or remove that directory
locally after the build. Nothing is flashed automatically.

R011 is the default target. Expected output: **2,591,008 bytes**, SHA-256
`91b32a4d2161a87a4725a2296371e01ee6c7e83a95dccb38fe9f4a8dd2e53b0b`.
The builder checks MAIN, DSP and complete SysEx identities against
[releases/r011.json](releases/r011.json).

Use `--target T1E2` to reproduce the previous stable release, or `--target R003`
and `--target R008` for the historical experimental builds. Give each target a
separate output filename. All targets require the same private inputs; R011
builds through T1E2, Recorder and the USB publication stages.

## Source and contributions

[November 3 research update](docs/research/2026-11-03.md) covers R011
publication, project-change behavior and the reported sample persistence issue.
The [November 2 research update](docs/research/2026-11-02.md) covers the USB freeze,
buffer checks and new diagnostics. The
[October 31 research update](docs/research/2026-10-31.md) documents Recorder
verification, loader-overlap findings and remaining audit limits. Reusable
offline checks and synthetic tests are described in the
[audit guide](docs/research-audits.md).

The port contains original adapters, extraction/relocation recipes and factual
address metadata. Donor routines, fonts and graphics are extracted locally.
Read [publication boundaries](docs/publication.md) before contributing. Do not
attach firmware, samples, generated disassemblies or raw device captures to
commits, issues, pull requests or releases.

Research builds modify device firmware. Keep project backups and a known-good
recovery image privately. This project is independent of Elektron.

Source licence: AGPL-3.0-or-later, with component notices retained in
[THIRD_PARTY.md](THIRD_PARTY.md).
