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
