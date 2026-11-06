# Experimental offline audits

The tools in [`research/audits`](../research/audits) inspect local inputs without
accessing MIDI, USB or the device. They do not change the selected firmware build or
certify a candidate as safe to flash. No vendor firmware, disassembly, samples
or hardware captures accompany them.

The [November 6 research update](research/2026-11-06.md) summarizes the wider
R015–R020 native-instruction and hardware work, including the cold-start
readiness regression. Those research fixtures have additional private OS and
emulator-state dependencies; this standalone audit directory does not claim
to reproduce the entire development test suite. The
[R021/R022 follow-up](research/2026-11-06-autosave.md) adds native UI-transition
and incremental sample-backup regressions with their fixture boundaries.

## Recovery and container checks

`audit_dn2_recovery.py` uses the repository's existing `dnfw` parser and codec.
It checks strict section boundaries, protected bootstrap/panel/writer ranges,
intended MAIN/DSP identity, DSP loader capacity and whether decompression writes
can reach compressed bytes that have not yet been read. Only the pinned
Digitone II OS 1.11 profile is supported; an unknown stock input fails closed.

From the repository root, with your own local inputs:

```sh
python3 -B research/audits/audit_dn2_recovery.py \
  --stock /private/path/Digitone_II_OS1.11.syx \
  --candidate /private/path/candidate.syx \
  --intended-main /private/path/main-os.bin \
  --intended-dsp /private/path/section_7.bin \
  --out /private/path/recovery-report.json
```

The intended files must be the candidate's actual packaged sections. For a
candidate with a separately staged MAIN tail, pass staged MAIN, not its expanded
runtime projection. Exit 0 means these static checks passed; exit 1 means a
failure or missing/unsupported input. This model does not execute the hardware
boot, flash writer, caches or DMA. Protection checks compare against the local
stock file; the source contains only address metadata and short instruction
compatibility guards, not firmware payloads.

The alternate section-4/board-test path and normal startup have different
compressed-input staging addresses. Passing normal startup does not establish
that the alternate path is safe. Keep any reported overlap visible; do not
waive it because an image has booted normally.

## SHARC store dependencies

`audit_dn2_dsp_stores.py` traces indirect-store address dependencies through
straight-line assembly, calls, delay slots and stack reloads:

```sh
python3 -B research/audits/audit_dn2_dsp_stores.py \
  /private/path/bridge.asm --entry-registers I6,I7,M7 \
  --out /private/path/stores-report.json
```

Only declare incoming registers supplied by the actual calling convention.
The default call contract is selcc's R0–R7 clobbered, R8–R15 preserved and R0
returned; other ABIs need explicit flags. A resolved dependency is not a
memory-bounds, ownership, SIMD-partner or timing proof. Branches, merge points
and unknown semantics remain unresolved. Exit 0 means resolved for the supplied
scope, 1 means a caller-clobber hazard, and 2 means incomplete coverage.

This tracer inspects text; it does not bind that text to a firmware binary.
Reports contain input paths and assembly excerpts. Keep reports private unless
separately reviewed.

## SHARC instruction rules

`dn2_sharc_rules.py` exposes `check_rows(rows)` for already decoded and explicitly
classified instructions. Each row supplies `pc` in short words, byte `size`,
mnemonic `text`, decoder `type`, merged `fields`, physical `region`, `origin`
and integer `raw` encoding. See its docstring and synthetic tests for examples.

It checks hardware-loop widths/endpoints and DAG-register restrictions, while
retaining context-dependent loop calls and branch interpretations as review
findings. RFRAME restores a return frame; a renderer's `return-frame` annotation
is not classified as a second branch. Findings are not suppressed merely
because a baseline has the same count.

This module does not decode a firmware image. Its caller must establish
executable boundaries, final-load overlays and binary identity. Missing
context produces review findings, not a whole-image pass. The private research
workspace also has encoding, parameter-contract, binary-adapter and aggregate
checks; this standalone subset does not claim their coverage.

## Tests and attribution

The public tests use synthetic source, instruction rows and compressed data:

```sh
python3 -B -m unittest discover -s research/audits/tests -v
```

No firmware inputs or third-party Python packages are needed for these tests.
The recovery audit reuses the vendored `dnfw` implementation under
`port/tools/dnfw`; its notices still apply.

The source-store tracer adapts [Digiwerk's store tracer](https://github.com/naturarum/dn2-cfw/tree/eb1cfa7d4fc3cd0a77a430e9e9226c5d9cc10979/tools/dspsplice)
under GPL-2.0-or-later. Its notice is retained in the script; the license is in
[`research/audits/LICENSE-GPL-2.0.txt`](../research/audits/LICENSE-GPL-2.0.txt).
Recovery-check categories also draw on that project's brick-check research.
SHARC rule research credits the MIT-licensed
[Digitone II modding skill](https://github.com/complex-ping/digitone-2-modding-skill/tree/84c8cd359470c648d55bac6075bd6778ba9e69f0),
with its complete notice retained in `dn2_sharc_rules.py`. No upstream allocator,
1.12 memory layout or baseline-suppression policy was imported.
