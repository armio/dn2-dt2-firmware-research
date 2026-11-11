# Browser patcher

Build R027 in a current desktop browser without installing the native toolchain.
You need the original Digitone II OS 1.11 and Digitakt II OS 1.16 `.syx` files.
No sample bank or factory sample library is required.

1. Open the [patcher](https://armio.github.io/dn2-dt2-firmware-research/).
2. Select both OS files and click **Build firmware**.
3. When verification finishes, download the `.syx` file.

Files stay on your device. The page checks exact OS versions, builds locally
and verifies the result against the [R027 release hash](../releases/r027.json).
It does not upload files, store them between visits or flash your instrument.
A few values derived from Elektron data (R027: the SEM graph's log-cutoff table
and TYPE icons) are computed in the browser from your own OS file; the recipe
contains only the formula names.
Cancel closes the build worker; selected files can be reused for another attempt.

R027 is a candidate that adds the [SEM filter](sem-filter.md) to R022's sample
autosave and SYN sample-menu fixes. It is owner-tested, not instrumented, and
**USB audio is untested on R027**; stay on R012 if you rely on it. See the
[release manifest](../releases/r027.json) for changes and limits. R012 remains
stable; R022 and earlier targets remain available through the
[native builder](../README.md#build).
Back up projects and samples and keep an official recovery OS before installing
with Elektron Transfer. For first-time sample storage, follow the
[setup and sample-loading guide](samples.md#sample-storage-setup). Formatting is
explicit and destructive; working sample storage does not need reformatting.
Save projects to retain checkpoints for explicit reloads, and save after editing
slice grids. Since R022 the build also updates sample identities in the working-state backup
used at boot. Let saves, loading and transfers finish before switching off; this
is not atomic crash recovery and does not fix the reported iPhone USB freeze. Native project exports do not include
[SLICE-grid companion files](samples.md#slice-grid-persistence).

## Run the patcher locally

With Emscripten 4.0.22 available:

```sh
sh web/build-codec.sh
python3 tools/build_site.py --out build/site
python3 -m http.server 8000 --directory build/site --bind 127.0.0.1
```

Open `http://127.0.0.1:8000`. Building from a `file://` page is unsupported;
file verification requires HTTPS or localhost.

The browser reconstructs the same pinned result as the
[native source build](../README.md#build). The [publication guide](publication.md)
explains how vendor bytes remain in the user's input files. Generated WebAssembly
contains only the original open-source container tool, with its licence retained.
