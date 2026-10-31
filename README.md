# DN2 DT2 firmware research

Source recipes for reproducing **T1E2**, the Digitone II research firmware
designated stable on October 15, 2026. No firmware images or sample audio are
distributed. The build extracts required Elektron code and assets from firmware
you supply locally, assembles the adapters, and checks the complete output hash.

T1E2 includes ONESHOT, WERP, STRETCH, REPITCH, GRID and SLICE; stereo samples;
sample browsing; DT2 parameter graphics; SLICES trig mode; and class-compliant
USB audio with 42 capture channels at 48 kHz/24 bit. Its USB return is stereo.
The 21 capture pairs are MAIN, tracks 1–16, DELAY, REVERB, CHORUS and INPUT,
in that order. Individual tracks exclude shared effect returns.

This is a version-specific port, not Elektron's source code. Later experimental
Recorder changes and USB stress-test branches are outside this release. The
stable designation records successful owner testing with USB streaming; it is
not a claim that every workflow or long-running workload has been verified.

## Private inputs

The exact build requires official Digitone II OS 1.11, official Digitakt II
OS 1.16, and the original 47,104-byte three-slot sample bank. Sizes and SHA-256
hashes are pinned in [releases/t1e2.json](releases/t1e2.json). Obtain firmware
from Elektron and retain your own copies locally.

**The sample bank is not included or offered for download.** It contains private
sample audio. Someone without that exact bank cannot reproduce T1E2 from this
repository alone. Replacing it would produce a different firmware, outside the
stable release's checksum and validation history.

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
  --out /private/builds/T1E2.syx
```

The output must be outside this repository. An existing output is never
overwritten. Intermediate firmware and diagnostic logs stay in the private
temporary directory printed by the builder; retain or remove that directory
locally after the build. Nothing is flashed automatically.

Expected output: 2,537,120 bytes, SHA-256
`c79c42d2e044bb1142b575f7b62e2a0d7aeb68179fdea333217c17bb03f2ec8b`.

Verified on October 31, 2026: a clean export of the staged source reproduced
that exact output on macOS with Python 3.12, a fresh Capstone-only environment,
and tools built from the pinned public sources. All MAIN and DSP stage hashes
matched. No historical firmware builds or private research checkout were used
as build dependencies.

## Source and contributions

The port contains original adapters, extraction/relocation recipes and factual
address metadata. Donor routines, fonts and graphics are extracted locally.
Read [publication boundaries](docs/publication.md) before contributing. Do not
attach firmware, samples, generated disassemblies or raw device captures to
commits, issues, pull requests or releases.

Research builds modify device firmware. Keep project backups and a known-good
recovery image privately. This project is independent of Elektron.

Source licence: AGPL-3.0-or-later, with component notices retained in
[THIRD_PARTY.md](THIRD_PARTY.md).
