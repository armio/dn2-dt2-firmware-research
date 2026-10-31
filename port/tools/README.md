# Build tools

Run from the repository root on macOS or Linux with Python 3.12+, Git, curl, Rust/Cargo,
GNU Make, a host C compiler, Clang's preprocessor and zlib development headers:

```sh
python3 port/tools/bootstrap.py --prefix .toolchain --jobs 4
```

For a rustup installation, first load `~/.cargo/env` if `cargo` is not on `PATH`.
Downloads use curl's platform certificate trust and verified SHA-256; TLS
verification is never disabled.
The bootstrap skips rebuilding GNU info manuals, so Texinfo is not required.

The script fetches only pinned open-source tool sources. It builds GNU binutils
2.43.1 for `m68k-linux-gnu`, Selache's `selas`, and the included MIT container tool.
It checks out Digikit for its pure-Python SHARC decoding helpers. The build does
not need Digikit's Unicorn emulator or its optional UI dependencies. No Elektron
firmware, private sample bank, generated firmware or compiled payload is included
or downloaded.

`dependencies.json` records revisions, licenses and the GNU archive digest.
`.toolchain/paths.json` records absolute local paths for the firmware builder.
The build-tree binutils programs are also available under
`.toolchain/binutils-build/{gas,ld,binutils}`. Installed programs use the prefix
`.toolchain/bin/m68k-linux-gnu-`; add `.toolchain/bin` to `PATH` when running the
individual historical source generators. Set `ONESHOT_BINUTILS` to the absolute
installed prefix when invoking the assembly-only loader directly.

The pinned Digikit commit exactly matches every Python file in the frozen V7
snapshot. Selache's source and Cargo manifests match the assembler used for that
snapshot. The SHARC negative-shift immediate correction belongs to the firmware
builder's assembly helper, not a local Selache patch.

`dnfw/` contains the dependency closure needed by the port, with the upstream
AGPL license and retained component notices. `elektron-firmware-tool/` has its
own MIT license. Generated files and dependency checkouts belong in ignored
build directories and must not be added to this source repository.

The early MAIN prerequisite can also be rebuilt independently:

```sh
python3 port/tools/build_v7_main.py \
  --dn2-main build/stock-dn2/section_3_MAIN_OS.bin \
  --dt2-main build/stock-dt2/section_3_MAIN_OS.bin \
  --binutils-prefix "$PWD/.toolchain/bin/m68k-linux-gnu-" \
  --output build/v7/section_3_MAIN_OS.bin \
  --shims-output build/v7/oneshot_code.json
```

Both input section hashes and the resulting V7 MAIN hash are enforced. The
original probe generator is narrowed to its compose function in
`gen_usbprobe.py`. `native_assembly.py` assembles the probe with Clang preprocessing
and the pinned GNU assembler/linker, removing the cross-GCC dependency without
changing the resulting bytes. Generated shim JSON stays in the private build
directory; it is never part of the public source snapshot.
