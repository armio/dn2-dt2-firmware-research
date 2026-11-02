# Experimental USB publication research

R008 adds bounded diagnostics for rejected USB audio publications. It preserves
R007 ownership checks and control-frame ordering. **The USB freeze is unresolved:
R008 is a diagnostic build, not a stable replacement for T1E2.**

The source chain is R003 → R004 phase accounting → R005 private scratch relocation
→ R007 guarded publication → R008 rejection diagnostics. R006 publication helper
definitions are reused by the assembler generator; its observer patches are not
applied. MAIN is the exact R002 Recorder reopen result repacked with the R008
marker through the existing recovery-tail builder.

`build.py` extends private, reproduced T1E2 and R003 work directories in a fresh
directory. It does not alter either parent, contact hardware, flash firmware or
upload results. The top-level R008 target invokes this stage automatically. Final
MAIN and DSP hashes must match the release manifest. No additional private inputs
are required beyond the three inputs already required for T1E2/R003.

`SOURCE_PROVENANCE.json` records original and exported source digests. The files
under `tree/scripts` are generators and offline fixtures, not firmware payloads.
The assembler and decoder remain pinned external tools. The stock encoding audit
credits Digiwerk and the original DN2 research; its implementation imports no
code from the Digiwerk repository.

The exported phase-accounting, scratch-relocation, guarded-publication and
guard-reason execution fixtures use the existing Digikit emulator with local
compatibility helpers.
They check exact parent reversal, instruction/register scope and guarded export
behavior. They do not establish on-device IRQ latency or prove arbitrary
concurrent-writer exclusion. They are optional research checks, separate from the
deterministic source build.

Run one fixture against a completed private R008 work directory:

```sh
python3 port/usb-research/check.py reasons \
  --work /path/to/private-build/usb-research \
  --toolchain /path/to/toolchain/paths.json
```

Choose `phase`, `scratch`, `guard` or `reasons`. Historical check modules supply
helpers; their older standalone fixture inputs are not part of this interface.
The source-only recovery-tail checker is also retained for researchers with the
patched ColdFire Unicorn runtime and private packaged image. It is not run by the
normal build and does not install emulator dependencies automatically.

R008 reports the first failed predicate and bounded immutable snapshots via the
existing diagnostic header. A rejected publication retains prior audio; rejection
can therefore cause repeated USB blocks even while packet transmission continues.
Do not interpret a successful build or matching hash as a resolved audio fault.
