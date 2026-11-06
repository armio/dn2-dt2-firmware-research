import { unpackOfficial, packFirmware, compressMainTail } from './firmware-codec.js';
import { applyRecipe, verify, sha256 } from './recipe.js';

let building = false;
const update = (message, progress) => postMessage({ type: 'progress', message, progress });

async function readJSON(name) {
  const response = await fetch(new URL(name, import.meta.url), { cache: 'no-cache' });
  if (!response.ok) throw new Error(`Build asset unavailable: ${name}`);
  return response.json();
}

async function build(inputs) {
  const release = await readJSON('release.json');
  if (release.build !== 'R020') throw new Error('Unsupported browser release');
  const files = {}, decoded = {};
  for (const [index, name] of ['dn2', 'dt2'].entries()) {
    if (!(inputs?.[name] instanceof ArrayBuffer)) throw new Error(`Select the ${name.toUpperCase()} OS file`);
    files[name] = new Uint8Array(inputs[name]);
    update(`Checking ${name.toUpperCase()} OS file`, 5 + index * 10);
    await verify(files[name], release.inputs[name], name.toUpperCase());
    decoded[name] = await unpackOfficial(files[name]);
  }
  update('Reading reviewed build recipe', 25);
  const recipe = await readJSON('recipe.json');
  if (recipe.release !== release.build) throw new Error('Recipe release differs from manifest');
  for (const name of ['dn2', 'dt2']) {
    if (recipe.inputs[name]?.sha256 !== release.inputs[name].sha256 ||
        recipe.inputs[name]?.bytes !== release.inputs[name].bytes) throw new Error('Recipe input identity differs from release');
  }
  const images = await applyRecipe(recipe, decoded, message => update(message, 55));
  let main = images.main;
  if (recipe.postprocess.main_tail) {
    const profile = recipe.postprocess.main_tail;
    const expanded = images.main_expanded;
    if (!expanded || !Number.isSafeInteger(profile.cutoff) || profile.cutoff <= 0 ||
        profile.cutoff >= expanded.length) throw new Error('Invalid MAIN tail profile');
    await verify(expanded, { bytes: expanded.length, sha256: release.outputs.expanded_main_sha256 }, 'Expanded MAIN');
    update('Compressing MAIN runtime', 65);
    const tail = await compressMainTail(expanded.subarray(profile.cutoff));
    main = new Uint8Array(profile.cutoff + tail.length);
    main.set(expanded.subarray(0, profile.cutoff));
    main.set(tail, profile.cutoff);
  }
  if (!main || !images.dsp) throw new Error('Build recipe did not produce MAIN and DSP');
  await verify(main, { bytes: main.length, sha256: release.outputs.main_sha256 }, 'Final MAIN');
  await verify(images.dsp, { bytes: images.dsp.length, sha256: release.outputs.dsp_sha256 }, 'Final DSP');
  update('Packaging firmware locally', 80);
  const firmware = await packFirmware({ dn2Original: files.dn2, main, dsp: images.dsp });
  update('Checking complete firmware identity', 95);
  await verify(firmware, { bytes: release.outputs.sysex_bytes, sha256: release.outputs.sysex_sha256 }, 'Firmware');
  const hash = await sha256(firmware);
  const result = firmware.buffer.slice(firmware.byteOffset, firmware.byteOffset + firmware.byteLength);
  postMessage({ type: 'complete', buffer: result, sha256: hash, bytes: firmware.length }, [result]);
}

self.onmessage = async ({ data }) => {
  if (data?.type !== 'build') return;
  if (building) {
    postMessage({ type: 'error', message: 'A build is already running' });
    return;
  }
  building = true;
  try {
    await build(data.inputs);
  } catch (error) {
    postMessage({ type: 'error', message: error instanceof Error ? error.message : 'Build failed' });
  } finally {
    building = false;
  }
};
