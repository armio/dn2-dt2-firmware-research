// Exercise the browser backend with private inputs; never write firmware.
// node tools/test_browser_build.mjs <official-dn2.syx> <official-dt2.syx>
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { unpackOfficial, packFirmware, compressMainTail } from '../web/firmware-codec.js';
import { applyRecipe, verify } from '../web/recipe.js';

if (process.argv.length !== 4) throw new Error('Supply official DN2 and DT2 OS file paths');
const started = performance.now();
const release = JSON.parse(await readFile(new URL('../releases/r027.json', import.meta.url)));
const recipe = JSON.parse(await readFile(new URL('../web/recipe.json', import.meta.url)));
if (recipe.release !== release.build) throw new Error('Recipe release differs from manifest');
const files = {}, decoded = {};
for (const [index, name] of ['dn2', 'dt2'].entries()) {
  files[name] = new Uint8Array(await readFile(process.argv[index + 2]));
  await verify(files[name], release.inputs[name], name);
  decoded[name] = await unpackOfficial(files[name]);
}
const images = await applyRecipe(recipe, decoded);
const cutoff = recipe.postprocess.main_tail.cutoff;
const tail = compressMainTail(images.main_expanded.subarray(cutoff));
const main = new Uint8Array(cutoff + tail.length);
main.set(images.main_expanded.subarray(0, cutoff));
main.set(tail, cutoff);
await verify(main, { bytes: main.length, sha256: release.outputs.main_sha256 }, 'MAIN');
const firmware = await packFirmware({ dn2Original: files.dn2, main, dsp: images.dsp });
await verify(firmware, {
  bytes: release.outputs.sysex_bytes, sha256: release.outputs.sysex_sha256,
}, 'Complete firmware');
console.log(JSON.stringify({
  build: release.build, bytes: firmware.length, sha256: release.outputs.sysex_sha256,
  seconds: Math.round((performance.now() - started) / 100) / 10,
}));
