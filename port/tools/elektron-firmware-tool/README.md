# ELE3/SysEx container tool

MIT-licensed original source from
[mischa85/elektron-firmware-tool](https://github.com/mischa85/elektron-firmware-tool)
at commit `a5bce9a6af644386d900924082993a805e812874`, copyright Marcel Bierling.
The included `LICENSE` and upstream `PROVENANCE.md` describe that source.

One local compatibility fix in `container.c` aligns newly compressed ELE3
section lengths to four bytes while preserving untouched sections. The exact
change is also recorded in `ele3-section-padding.patch`; it is already applied.
This change is necessary for the T1E2 repack. No other upstream C source changed.

The parent bootstrap compiles this source into the ignored build directory.
It contains no vendor firmware, samples or stored signing keys; it reads the
user-supplied image and derives its integrity information locally.
