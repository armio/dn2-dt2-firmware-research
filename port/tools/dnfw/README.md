# dnfw build support

This is the minimal Python/source dependency closure from the V7 research
snapshot used to build T1E2, based on
[dn2_firmware_explore](https://github.com/angellinares/dn2_firmware_explore).
`SOURCE_MANIFEST.json` records each original file's SHA-256 and whether it matches
upstream commit `249876bbd4cd85e06c345a5639596aa2e58e1aac`. The ONESHOT modules and
assembly-only loader are research additions absent from that upstream revision;
the comparison revision is not claimed to reproduce the whole snapshot.

The upstream project and this snapshot declare AGPL-3.0-or-later. Preserve
`LICENSE` and per-file notices. The USB probe credits irpina/digihealth under
GPL-2.0-or-later, used under GPL-3.0 within this AGPL project. The firmware HMAC
derivation code credits the MIT-licensed `mischa85/elektron-firmware-tool`; its
MIT notice is also provided in the adjacent tool directory.

Only Python, hand-written assembly and C headers are included. Firmware code,
compiled `*_code.json` payloads, adapter JSON, disassemblies and sample assets
are excluded. Donor code and data are read from user-supplied official firmware
when the builder runs. Addresses, relocation rules, opcode guards and hashes
are compatibility metadata, not a bundled donor implementation.

The loader's host-side temporary-directory handling and binutils default are
portable. These changes do not alter assembled target instructions. Its source
manifest identifies the original snapshot before those host-side changes.
