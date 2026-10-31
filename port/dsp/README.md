# Exact T1E2 DSP rebuild

`build.py` reconstructs the DSP from the user's official Digitone II OS1.11 and Digitakt II OS1.16 images. No previous experimental firmware, extracted routines, compiled code JSON, hardware connection, or private sample bank is needed. Final SHA-256: `409811b1776c9a2cf1c73e5fce2f5dbcf7378c9fd6f835f45ba1a0e97c1a3cc3`.

```sh
python3 -B port/dsp/build.py --dn2 /private/Digitone_II_OS1.11.syx --dt2 /private/Digitakt_II_OS1.16.syx --work /private/fresh-dsp-build --digikit /toolchains/digikit --selas /toolchains/selas
```

Default Python support is `port/tools/dnfw/src`; `--dnfw-src` overrides it. `--work` must not exist and must be outside the release tree. Outputs: `section_7.bin`, `rebuild.json`, build log, and historical intermediate paths inside that work directory. Keep the complete work directory private: builds extract vendor code and produce firmware.

Requires Python 3.12, selache commit `2b26d3b75c53063575bc5c820fa0d38879335187`, and Digikit commit `6f812e994ccc5ea939e86f0e5098d9dfab3b7eaf`. Toolchain setup and licenses live in `port/tools`. Build sources derive from the project's AGPL-3.0-or-later dnfw research; source provenance is recorded in `SOURCE_PROVENANCE.json`.

The original V7 adapter is assembled directly, donor spans are extracted/relocated from validated official inputs, and the original chirp is generated with its historical signed16 WAV quantization. This recreates V7 without distributing or requiring V5/V6 firmware. Original bank-loader, keyboard, bounds, sampler, stereo, memory, timing and USB generators then run in their historical order. Every firmware stage is hash-checked. L1 instruction boundaries are regenerated from their source producers, rather than supplied as compiled metadata.

Rebuilt twice on macOS/Python 3.12. The second clean run used the release-staged dnfw library. All 46 post-base stages and final output matched retained T1E2 hashes. This establishes byte reproducibility, not additional hardware validation.

## Earlier MAIN bootstrap

`main_baseline.py` continues a fresh `port/bootstrap/fs.py` workspace through merged storage, GUI, keyboard identity, native bounds and M3B callback repair. Sources are read from `port/main/tree`; only generated private work files are changed.

```sh
python3 -B port/dsp/main_baseline.py --workspace /private/fs-build --v7-main /private/v7-main.bin --v7-dsp /private/dsp-build/firmware/ghidra/oneshot-proof/v7-source/out/os1handoff-v7/section_7.bin --v7-shims /private/oneshot_code.json --binutils-build /toolchains/binutils-build
```

`port/tools/build_v7_main.py` produces the MAIN/shims prerequisites. DSP builder above produces V7 DSP. The FS workspace already contains both official MAIN sections and the user's private bank. Default Python support is the staged dnfw source. Use a fresh workspace without existing merge-v1/v2/v3 directories.

Output: `WORKSPACE/output/dn2-research/oneshot-drive-v3-m3b-rev3-stackfix-20261009/main-os.bin`, SHA-256 `205673af2a58674bb239195d4d40a5084d22d626aab59ca11547a31a0d7b0c64`, plus FS relocation maps there and under `firmware/ghidra/storage-proof/oneshot-storage-merge-v3/src`. This is the input to the later six-machine MAIN stages, not final T1E2 MAIN.

Verified from a fresh FS source rebuild and freshly generated V7 inputs. Native waveform cache regenerates from the original chirp; donor UI and sample-name routines extract from official DT2 input at build time. Native-twin metadata contains addresses and relocation constraints, not copied routines. Historical parent firmware packages and old hardware-test receipts are not required. Reports generated during reproduction distinguish build metadata from hardware evidence.
