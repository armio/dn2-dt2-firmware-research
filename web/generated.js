// Original deterministic fixtures; no recorded samples or vendor tables.
function roundEven(value) {
  const floor = Math.floor(value), fraction = value - floor;
  return fraction < 0.5 ? floor : fraction > 0.5 ? floor + 1 : floor + (floor & 1);
}

function chirp() {
  const pcm = new Int16Array(7200), k = Math.log(8) / pcm.length;
  let phase = 0;
  for (let i = 0; i < pcm.length; i++) {
    phase += 2 * Math.PI * (220 * Math.exp(k * i)) / 48000;
    const envelope = 0.9 * 10 ** (-i / pcm.length);
    const sample = Math.max(-32768, Math.min(32767, roundEven(envelope * Math.sin(phase) * 32768)));
    pcm[i] = roundEven(sample / 32768 * 32767);
  }
  return pcm;
}

// Values derived from the user's own OS input; the recipe carries only the formula's name.
export function computeFromFirmware(name, input) {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  if (name === 'sem-graph-log-cutoff' && input.length === 4096) {
    const g = Array.from({ length: 1024 }, (_, i) => view.getFloat32(i * 4, true));
    const at = raw => {
      const position = Math.min(1023, raw / 32), i = Math.trunc(position);
      return i >= 1023 ? g[i] : g[i] + (position - i) * (g[i + 1] - g[i]);
    };
    const values = [
      ...Array.from({ length: 129 }, (_, k) => Math.min(6.3137515, at(k * 256))),
      ...Array.from({ length: 49 }, (_, column) => at(column * 32768 / 48)),
    ];
    const result = new Uint8Array(values.length * 2), out = new DataView(result.buffer);
    values.forEach((value, i) => out.setInt16(i * 2, roundEven(256 * Math.log2(value)), false));
    return result;
  }
  if (name === 'sem-type-planes' && input.length === 76) {
    const words = Array.from({ length: 19 }, (_, i) => view.getUint32(i * 4, false));
    const sem = [...words], bp = new Array(19).fill(0), bit = row => (0x80000000 >>> row) >>> 0;
    for (let column = 7; column < 12; column++) {
      let keep = 0, flipped = 0;
      for (let row = 4; row < 9; row++) {
        if (words[column] & bit(row)) { keep |= bit(row); flipped |= bit(12 - row); }
      }
      sem[column] = ((words[column] & ~keep) | flipped) >>> 0;
      bp[column] = keep >>> 0;
    }
    const result = new Uint8Array(152), out = new DataView(result.buffer);
    [...sem, ...bp].forEach((value, i) => out.setUint32(i * 4, value, false));
    return result;
  }
  throw new Error(`Unsupported computed source: ${name}`);
}

export function generateOriginal(name) {
  if (name === 'chirp-bank') {
    const result = new Uint8Array(22612), view = new DataView(result.buffer);
    [0x3142534f, 1, 0x311814, 7200, 48000].forEach((value, i) => view.setUint32(i * 4, value, true));
    chirp().forEach((value, i) => view.setInt16(4116 + i * 2, value, true));
    return result;
  }
  if (name === 'chirp-cache') {
    const result = new Uint8Array(404), pcm = chirp();
    for (let x = 0; x < 96; x++) {
      let maximum = 0, minimum = 0;
      for (let i = Math.floor(x * 7200 / 96); i < Math.floor((x + 1) * 7200 / 96); i++) {
        maximum = Math.max(maximum, pcm[i] >> 8);
        minimum = Math.min(minimum, pcm[i] >> 8);
      }
      result[0x10 + x] = maximum & 255;
      result[0x70 + x] = minimum & 255;
    }
    return result;
  }
  if (name === 'pitch-table') {
    const result = new Uint8Array(2048), view = new DataView(result.buffer);
    for (let reverse = 0; reverse < 2; reverse++) {
      for (let tune = 0; tune < 128; tune++) {
        const value = BigInt(roundEven(0.5 * 2 ** ((tune - 64) / 12) * 2 ** 31));
        view.setBigInt64((reverse * 128 + tune) * 8, reverse ? -value : value, true);
      }
    }
    return result;
  }
  if (name === 'silent-compatibility-bank') {
    const result = new Uint8Array(47104), view = new DataView(result.buffer);
    [0x3142534f, 3, 0x31182c, 2708, 48000, 0x314d54, 2723, 48000,
      0x31829c, 3145, 48000].forEach((value, i) => view.setUint32(i * 4, value, true));
    return result;
  }
  throw new Error(`Unsupported original data generator: ${name}`);
}
