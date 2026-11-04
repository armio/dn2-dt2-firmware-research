# Source-only publication

R014 builds from two privately supplied official OS files identified in its
`releases/` manifest. It generates silent compatibility data from source and
requires no private sample bank. Historical exact R011, R008, R003 and T1E2
recipes retain their original private-bank requirement. No input firmware,
generated firmware or sample audio is distributed. See [sample loading](samples.md)
for importing playable samples after installation.

Publish validation summaries with their limits, not private hardware captures
or raw build receipts. Reviewed offline fixture summaries may be included when
bound to exact output hashes and stripped of private paths and binary payloads.
R014 is the current candidate. It adds three sampler control fixes and retains
R013 sample-storage setup; DSP code remains unchanged. R012 was designated stable after owner-confirmed stock audio, sample playback,
Recorder and USB audio, including after changing projects. R011 remains the
previous stable release. These designations do not claim completed long-duration
endurance testing. Historical R003/R008 manifests retain their original
validation scope; their experimental status is not changed retroactively.

Publish original build/adaptor source, extraction and relocation recipes,
factual address metadata, dependency pins, synthetic tests and research notes.
Extract Elektron code, fonts, graphics and tables from the user's official
firmware during the local build.

Do not commit firmware images, decompressed or relocated vendor routines,
generated disassemblies, sample banks, audio recordings, private projects or
raw device captures. Generated JSON can contain compiled code and donor data;
text format alone does not make a file publishable. Review actual contents.

Keep private inputs and generated outputs outside Git. Public CI must not
upload them in artifacts, releases, caches or logs. Start with fresh Git
history; excluding a file in `.gitignore` does not remove an earlier commit.

Preserve licences and attribution for every included third-party source. This
project must not adopt the original C tool's independent-implementation claim
for the entire port: vendor routines are deliberately transplanted locally
from the user's firmware inputs.

## Browser patcher

The site contains original patcher code, a release recipe and compiled original
adapter fragments tied to their source hashes. Donor bytes are excluded from
those fragments; their reserved holes are filled from the user's OS files.
The recipe copies vendor code and graphics from those local inputs and applies
explicit relocation operations. An unexplained output byte blocks export;
there is no generic binary-diff payload fallback.

GitHub Pages compiles the vendored MIT container tool to WebAssembly and stages
an explicit list of browser assets. CI receives no firmware or samples and
publishes no generated instrument firmware. The browser checks both inputs,
reconstructed sections and the final SysEx against the release hashes before
enabling its download. Nothing is flashed automatically.
