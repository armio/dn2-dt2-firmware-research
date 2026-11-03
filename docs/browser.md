# Browser patcher

Build R012 in a current desktop browser without installing the native toolchain.
You need the original Digitone II OS 1.11 and Digitakt II OS 1.16 `.syx` files.
No sample bank or factory sample library is required.

1. Open the [patcher](https://armio.github.io/dn2-dt2-firmware-research/).
2. Select both OS files and click **Build firmware**.
3. When verification finishes, download the `.syx` file.

Files stay on your device. The page checks exact OS versions, builds locally
and verifies the result against the [R012 release hash](../releases/r012.json).
It does not upload files, store them between visits or flash your instrument.
Cancel closes the build worker; selected files can be reused for another attempt.

R012 is a candidate based on stable R011. Hardware testing is pending.
Back up projects and keep an official recovery OS before installing with
Elektron Transfer. Add playable samples using the [sample-loading guide](samples.md).

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
