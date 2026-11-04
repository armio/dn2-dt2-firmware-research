# R014 sampler control fixes

This source-only continuation starts from exact expanded R013, then applies
FUNC TUNE octave snapping, native SYN clear/undo, and held SLICE marker updates.
The final builder changes the release identity and restages the existing boot
tail. Its allowed-diff check reverses every change to recover exact R013.
DSP and USB transport remain unchanged.

The top-level `build.py --target R014` runs these stages after reproducing R013
from the two pinned official OS files. Official donor/native code stays in the
private build workspace. No firmware, recorded samples, snapshots or hardware
captures are included here.

The recovery-tail helper differs from the prior public helper only by its
R014-specific profile and projection check. Historical build branches are
unchanged. See [release evidence and limits](../../releases/r014.json).
