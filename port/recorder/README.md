# Experimental R003 Recorder source

This extension adds the DT2 Recorder workflow to the reproduced T1E2 baseline:
source selection, recording, normalization, trimming, audition, naming and
saving. It includes the retained-take Recorder reopen fix and the separate MAIN
tail packing that avoids a reproduced overlap in the conditional loader.
T1E2 remains the designated stable release. R003 is experimental.

The extension preserves T1E2's USB capture, SPI frame size and control ordering;
it does not include the later USB timing and queue experiments. Its DSP changes
are limited to Recorder capture, control snapshots and reply ownership, plus
the scalar ACK publication fix. Donor code and graphics are extracted from the
same locally supplied official OS files used by the stable recipe.

## Inputs and output

Use the top-level experimental build instructions. This lower-level entry point
requires the complete private work directory produced by the stable `build.py`:

```sh
python port/recorder/build.py \
  --stable-work /private/path/t1e2-work \
  --work /private/path/r003-work \
  --toolchain /private/path/toolchain/paths.json
```

`--work` must be fresh and outside this repository. The builder validates the
baseline MAIN, DSP and donor section hashes, then reconstructs MAIN and DSP
from source. It checks both final section hashes against R003. It does not
package, flash or access a device.

Generated firmware sections, relocated donor code, listings, temporary objects
and build receipts remain in that private work directory. They must not be
committed. The original private sample bank is still required to build the
T1E2 baseline; this extension does not remove that dependency.

## Source boundaries

`tree/` contains original adapters, relocation recipes and build orchestration.
`SOURCE_PROVENANCE.json` identifies their local research sources and hashes.
The shared MAIN and DSP helpers come from `port/main` and `port/dsp`; the
recovery decoder comes from `research/audits`. Ownership metadata contains
addresses and extents only. No donor routine dumps, compiled firmware, samples,
recordings or hardware logs are included.

Hardware R003 boot, MAIN recording, saving and Recorder reopening have been
checked. A complete saved take was read back as stereo 48 kHz audio. The current
trimmed-file comparison, power-cycle persistence and long-duration USB tests
remain pending. Offline native checks cover additional trim/save paths but do
not replace these hardware checks.
