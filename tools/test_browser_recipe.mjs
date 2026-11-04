import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { applyRecipe, sha256 } from '../web/recipe.js';
import { generateOriginal } from '../web/generated.js';

globalThis.crypto ??= webcrypto;
const input = Uint8Array.of(10, 20, 30, 40);
const output = Uint8Array.of(20, 30, 0, 0x12, 0x34);
const identity = async data => ({ bytes: data.length, sha256: await sha256(data) });
const fixture = {
  schema: 1, release: 'R012', sources: {
    original: { kind: 'firmware', input: 'dn2', section: 3, ...await identity(input) },
  }, images: { main: { ...await identity(output), operations: [
    { kind: 'copy', source: 'original', offset: 1, bytes: 2 },
    { kind: 'fill', value: 0, bytes: 1 },
    { kind: 'scalar', bytes: 2, value: 0x1234, endian: 'big', provenance: { source: 'synthetic' } },
  ] } },
};
const decoded = { dn2: { sections: { 3: input } } };
assert.deepEqual((await applyRecipe(fixture, decoded)).main, output);
assert.deepEqual((await applyRecipe({ ...fixture, release: 'R013' }, decoded)).main, output);
await assert.rejects(applyRecipe({ ...fixture, release: 'R999' }, decoded), /Unsupported build recipe/);
const wrongInput = { dn2: { sections: { 3: Uint8Array.of(0, 0, 0, 0) } } };
await assert.rejects(applyRecipe(fixture, wrongInput), /identity mismatch/);
const badCopy = structuredClone(fixture);
badCopy.images.main.operations[0].offset = 4;
await assert.rejects(applyRecipe(badCopy, decoded), /source bounds/);
const missing = structuredClone(fixture);
missing.images.main.operations.pop();
await assert.rejects(applyRecipe(missing, decoded), /unexplained/);
const overflow = structuredClone(fixture);
overflow.images.main.operations[2].value = 65536;
await assert.rejects(applyRecipe(overflow, decoded), /Invalid scalar/);
const opaque = structuredClone(fixture);
opaque.images.main.operations[0] = { kind: 'literal', bytes: 2, value: '141e' };
await assert.rejects(applyRecipe(opaque, decoded), /Unsupported recipe operation/);
for (const [name, expected] of [
  ['chirp-bank', 'ac62e084f8556279e827d63736789f6fec1f0895dc8ebae75722a172f9ea79d8'],
  ['pitch-table', '2c78d0c1681a9f0cc45e29274d7fd96db3cb4e80d71a9387d2829a96afcedf5c'],
  ['chirp-cache', 'be72b422fc399b0732083d734902013a4fd2c52c78e64254fa353e21ac64c074'],
]) assert.equal(await sha256(generateOriginal(name)), expected);
console.log('Browser recipe input, bounds, provenance-bound operation and generator checks passed');
