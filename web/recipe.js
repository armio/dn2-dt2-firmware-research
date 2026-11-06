// Reconstruct only checked source ranges and explicitly reviewed writes.
import { generateOriginal } from './generated.js';
export async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

export async function verify(bytes, identity, label) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== identity.bytes ||
      await sha256(bytes) !== identity.sha256) throw new Error(`${label}: identity mismatch`);
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${label}`);
  return value;
}

function reconstruct(spec, sources) {
  const output = new Uint8Array(integer(spec.bytes, 'image size'));
  let position = 0;
  for (const op of spec.operations) {
    const size = integer(op.bytes, 'operation size');
    if (!size || position + size > output.length) throw new Error('Recipe exceeds output bounds');
    if (op.kind === 'copy') {
      const source = sources.get(op.source), offset = integer(op.offset, 'copy offset');
      if (!source || offset + size > source.length) throw new Error('Recipe copy exceeds source bounds');
      output.set(source.subarray(offset, offset + size), position);
    } else if (op.kind === 'fill') {
      if (op.value !== 0) throw new Error('Unsupported fill');
    } else if (op.kind === 'scalar') {
      const value = integer(op.value, 'scalar');
      if (![1, 2, 4].includes(size) || !['big', 'little'].includes(op.endian) ||
          !op.provenance?.source || value >= 2 ** (size * 8)) throw new Error('Invalid scalar write');
      for (let i = 0; i < size; i++) {
        const shift = (op.endian === 'little' ? i : size - 1 - i) * 8;
        output[position + i] = Math.floor(value / 2 ** shift) & 255;
      }
    } else throw new Error(`Unsupported recipe operation: ${op.kind}`);
    position += size;
  }
  if (position !== output.length) throw new Error('Recipe leaves unexplained output bytes');
  return output;
}

export async function applyRecipe(recipe, decoded, progress = () => {}) {
  if (recipe.schema !== 1 || !['R012', 'R013', 'R014', 'R020'].includes(recipe.release)) throw new Error('Unsupported build recipe');
  const sources = new Map();
  for (const [name, spec] of Object.entries(recipe.sources)) {
    let bytes;
    if (spec.kind === 'firmware') {
      bytes = decoded[spec.input]?.sections[spec.section];
    } else if (spec.kind === 'adapter' && spec.provenance?.length && spec.toolchain_sha256) {
      bytes = Uint8Array.from(atob(spec.base64), character => character.charCodeAt(0));
      for (const hole of spec.donor_holes || []) {
        const offset = integer(hole.offset, 'donor offset'), size = integer(hole.bytes, 'donor size');
        if (!size || offset + size > bytes.length || bytes.subarray(offset, offset + size).some(Boolean)) {
          throw new Error('Adapter contains an invalid donor hole');
        }
      }
    } else if (spec.kind === 'generated' && spec.provenance?.length) {
      bytes = generateOriginal(spec.generator);
    } else if (spec.kind === 'derived' && spec.provenance?.length) {
      bytes = reconstruct(spec, sources);
    } else throw new Error(`Unsupported recipe source: ${name}`);
    await verify(bytes, spec, name);
    sources.set(name, bytes);
  }
  const images = {};
  for (const [name, spec] of Object.entries(recipe.images)) {
    const output = reconstruct(spec, sources);
    await verify(output, spec, name);
    images[name] = output;
    progress(`Reconstructed ${name}`);
  }
  return images;
}
