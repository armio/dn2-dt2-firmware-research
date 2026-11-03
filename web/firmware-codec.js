// Browser wrapper around the unchanged MIT elektron-firmware-tool C codec.
// Firmware remains in the worker's memory; this module performs no uploads.
import createCodec from './codec-native.mjs';

const MAX_INPUT = 32 * 1024 * 1024;
let modulePromise;
let operation = Promise.resolve();
let nextJob = 0;

function bytes(value, name) {
  if (!(value instanceof Uint8Array) || !value.length || value.length > MAX_INPUT) {
    throw new Error(`${name} must be a nonempty Uint8Array under 32 MiB`);
  }
  return value;
}

function runExclusive(callback) {
  const result = operation.then(async () => {
    if (!modulePromise) modulePromise = createCodec({noInitialRun: true, print() {}, printErr() {}});
    return callback(await modulePromise);
  });
  operation = result.catch(() => {});
  return result;
}

function removeTree(fs, path) {
  for (const name of fs.readdir(path)) {
    if (name === '.' || name === '..') continue;
    const child = `${path}/${name}`;
    if (fs.isDir(fs.stat(child).mode)) removeTree(fs, child);
    else fs.unlink(child);
  }
  fs.rmdir(path);
}

function run(module, args) {
  const result = module.callMain(args);
  if (result !== 0) throw new Error(`Firmware container tool failed (${result})`);
}

export async function unpackOfficial(input) {
  bytes(input, 'Official OS');
  return runExclusive(module => {
    const fs = module.FS, dir = `/job-${nextJob++}`;
    fs.mkdir(dir);
    try {
      fs.writeFile(`${dir}/input.syx`, input);
      run(module, ['-i', `${dir}/input.syx`, '-o', `${dir}/sections`]);
      const sections = {};
      for (const name of fs.readdir(`${dir}/sections`)) {
        const match = /^section_(\d+)_.*\.(bin|raw)$/.exec(name);
        if (match) sections[Number(match[1])] = fs.readFile(`${dir}/sections/${name}`).slice();
      }
      if (!sections[3] || !sections[7]) throw new Error('Official OS lacks MAIN or DSP section');
      return {sections};
    } finally {
      removeTree(fs, dir);
    }
  });
}

export async function packFirmware({dn2Original, main, dsp}) {
  bytes(dn2Original, 'DN2 OS'); bytes(main, 'MAIN'); bytes(dsp, 'DSP');
  return runExclusive(module => {
    const fs = module.FS, dir = `/job-${nextJob++}`;
    fs.mkdir(dir);
    try {
      fs.writeFile(`${dir}/input.syx`, dn2Original);
      fs.writeFile(`${dir}/main.bin`, main);
      fs.writeFile(`${dir}/dsp.bin`, dsp);
      run(module, ['-i', `${dir}/input.syx`, '-c', '3', `${dir}/main.bin`,
        '-c', '7', `${dir}/dsp.bin`, '-o', `${dir}/output.syx`]);
      return fs.readFile(`${dir}/output.syx`).slice();
    } finally {
      removeTree(fs, dir);
    }
  });
}

// Exact JS translation of port/tools/dnfw/src/dnfw/codec/aplibpack.py.
// This greedy/lazy inner-tail strategy differs from the C outer packer.
const FAR = 3328, BIAS = 767, MAX_MATCH = 2048, WINDOW = (1 << 20) - 4096;
const gammaCost = value => 2 * (31 - Math.clz32(value));

function matchCost(offset, length, last) {
  const base = length - 1 - Number(offset > FAR);
  return 1 + (offset === last ? 2 : gammaCost((offset + BIAS) >> 8) + 8)
    + (base <= 3 ? 2 : 2 + gammaCost(base - 2));
}

export function compressMainTail(input) {
  bytes(input, 'MAIN tail');
  const head = new Int32Array(65536).fill(-1);
  const previous = new Int32Array(input.length).fill(-1);
  const output = new Uint8Array(input.length * 2 + 64);
  let used = 8, tagPosition = -1, tagBits = 0;
  function bit(value) {
    if (tagBits === 0) { tagPosition = used++; tagBits = 8; }
    if (value) output[tagPosition] |= 1 << (tagBits - 1);
    tagBits--;
  }
  function gamma(value) {
    for (let k = 30 - Math.clz32(value); k >= 0; k--) {
      bit((value >>> k) & 1); bit(k === 0);
    }
  }
  function best(position, cap, last) {
    let bestOffset = 0, bestLength = 0, bestCost = 0;
    function consider(offset) {
      let length = 0;
      while (length < cap && input[position - offset + length] === input[position + length]) length++;
      if (length < (offset > FAR ? 3 : 2)) return;
      const cost = matchCost(offset, length, last);
      if (length > bestLength || (length === bestLength && cost < bestCost)) {
        bestOffset = offset; bestLength = length; bestCost = cost;
      }
    }
    if (last > 0 && last <= Math.min(position, WINDOW)) consider(last);
    if (position + 2 <= input.length) {
      let candidate = head[(input[position] << 8) | input[position + 1]], depth = 32;
      while (candidate >= 0 && depth) {
        if (position - candidate > WINDOW) break;
        consider(position - candidate);
        if (bestLength >= cap) break;
        candidate = previous[candidate]; depth--;
      }
    }
    return [bestOffset, bestLength, bestCost];
  }
  let position = 0, last = 1;
  while (position < input.length) {
    let [offset, length, cost] = best(position, Math.min(input.length - position, MAX_MATCH), last);
    if (length && position + 1 < input.length) {
      const [, alternativeLength, alternativeCost] = best(position + 1,
        Math.min(input.length - position - 1, MAX_MATCH), last);
      if (alternativeLength && (9 + alternativeCost) * length < cost * (1 + alternativeLength)) length = 0;
    }
    let step;
    if (length) {
      bit(0);
      if (offset === last) gamma(2);
      else { const raw = offset + BIAS; gamma(raw >> 8); output[used++] = raw & 255; last = offset; }
      const base = length - 1 - Number(offset > FAR);
      if (base <= 3) { bit(base >> 1); bit(base & 1); }
      else { bit(0); bit(0); gamma(base - 2); }
      step = length;
    } else {
      bit(1); output[used++] = input[position]; step = 1;
    }
    const limit = Math.min(position + step, input.length - 1);
    for (let k = position; k < limit; k++) {
      const key = (input[k] << 8) | input[k + 1];
      previous[k] = head[key]; head[key] = k;
    }
    position += step;
  }
  bit(0); gamma(0x1000002); output[used++] = 255;
  let sum = 0;
  for (let k = 8; k < used; k++) sum = (sum + output[k]) >>> 0;
  const view = new DataView(output.buffer);
  view.setUint32(0, used - 8); view.setUint32(4, sum);
  return output.slice(0, (used + 3) & ~3);
}
