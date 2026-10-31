# Source-only publication

This repository reproduces stable T1E2 and experimental R003 from three privately
supplied inputs identified in their `releases/` manifests. It does not distribute those inputs
or any generated firmware. The original sample bank is required for exact
reproduction; arbitrary replacement audio will not match the release hash.
That bank is a private project test asset, not Digitakt II factory content or
an export obtainable from a Digitakt II. See [sample loading](samples.md) for
the separate workflow of importing playable samples after installation.

Experimental recipes and research checks do not promote a build to stable.
Publish validation summaries with their limits, not private hardware captures
or generated receipts. R003 hardware trim comparison and endurance remain
pending; T1E2 retains its stable designation.

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
