# USB publication source

R011 retains completed USB audio in a bounded FIFO and chooses its SPI publication
page from live DMA ownership. This avoids reusing a render-time page selection
after a project change. Ownership checks, FIFO order and control-frame ordering
remain intact. The user reported normal playback after loading another project
and designated R011 stable; this is not an endurance-test claim. See the release
notes for known issues, including the subsequent sample-persistence report.

The source chain is R003 → R004 phase accounting → R005 private scratch relocation
→ R007 guarded publication → R008 rejection diagnostics → R009 frame recorder
→ R010 retained audio → R011 SPI publication. R006 helper definitions are reused
by the assembler generator; its observer patches are not applied. R009's bounded
frame recorder defaults to off. R010/R011 MAIN changes only its build identifier.

`build.py` extends private, reproduced T1E2 and R003 work directories in a fresh
directory. It does not alter either parent, contact hardware, flash firmware or
upload results. The top-level R011 and R008 targets invoke this stage automatically.
Final MAIN and DSP hashes must match the selected release manifest. The same
three private inputs are required for all targets.

`SOURCE_PROVENANCE.json` records original and exported source digests. The files
under `tree/scripts` are generators and offline fixtures, not firmware payloads.
The assembler and decoder remain pinned external tools. The stock encoding audit
credits Digiwerk and the original DN2 research; its implementation imports no
code from the Digiwerk repository.

The normal build reuses a published R009 offline fixture receipt under `metadata`.
The staging builder checks that this receipt names the exact rebuilt MAIN hash.
This is an audit of a previously executed image, not a fresh emulator execution.
It avoids making a patched ColdFire Unicorn runtime a mandatory build dependency.
The native checker source is included for researchers who want to repeat it.

Optional DSP execution fixtures use the existing Digikit emulator with local
compatibility helpers. They check exact parent reversal, register scope, retained
FIFO behavior and guarded publication across DMA phases. They do not establish
on-device IRQ latency or prove arbitrary concurrent-writer exclusion.

Run one fixture against a completed private R011 work directory:

```sh
python3 port/usb-research/check.py publication \
  --work /path/to/private-build/usb-research \
  --toolchain /path/to/toolchain/paths.json
```

Choose `phase`, `scratch`, `guard`, `reasons`, `retained` or `publication`.
`retained` and `publication` need an R011 build; the earlier checks also support
R008. Emulator dependencies are not installed automatically.

R008 remains an experimental diagnostic target with unresolved USB freezes.
The finite R011 queue can still overflow if no safe DMA publication window becomes
available. A successful build alone does not prove hardware continuity.
