# R014–R022 sampler fixes

This source-only continuation starts from exact expanded R013, then applies
FUNC TUNE octave snapping, native SYN clear/undo, and held SLICE marker updates.
The final builder changes the release identity and restages the existing boot
tail. Its allowed-diff check reverses every change to recover exact R013.
DSP and USB transport remain unchanged.

The top-level `build.py --target R014` runs these stages after reproducing R013
from the two pinned official OS files. Official donor/native code stays in the
private build workspace. No firmware, recorded samples, snapshots or hardware
captures are included here.

R014 introduced its recovery-tail profile and projection check. Later targets
extend that dispatch while leaving historical build branches unchanged.
See [R014 evidence and limits](../../releases/r014.json).

Later continuations add the accumulated R015–R020 fixes, R021's deferred SYN
view reconciliation and R022's incremental working-state sample snapshot.
`build.py --target R022` runs that chain from the two official OS inputs.
`--target R020` stops before R021. Each revision verifies its pinned parent and
declared edits. R022 remains a hardware-unconfirmed candidate; R012 is stable.
See the [R022 findings](../../docs/research/2026-11-06-autosave.md) and
[release manifest](../../releases/r022.json).
