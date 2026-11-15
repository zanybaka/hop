import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pack, unpack } from '../src/container.mjs';

test('round trips text, binary files, and an empty publication', async () => {
  const text = 'Привет 🌍\n<hello>';
  const payload = Uint8Array.of(0, 255, 128, 10);
  const { text: received, files } = await unpack(pack({
    text, files: [{ name: 'файл.bin', blob: new Blob([payload]) }, { name: 'empty', blob: new Blob() }],
  }));
  assert.equal(received, text);
  assert.equal(files[0].name, 'файл.bin');
  assert.deepEqual(new Uint8Array(await files[0].blob.arrayBuffer()), payload);
  assert.equal(files[1].blob.size, 0);
  assert.deepEqual(await unpack(pack()), { text: '', files: [] });
});

test('rejects wrong version, invalid manifest, and length mismatches', async () => {
  const blob = pack();
  await assert.rejects(unpack(new Blob(['HOP2', blob.slice(4)])), /version/);
  await assert.rejects(unpack(new Blob([blob.slice(0, 8), Uint8Array.of(0xff), blob.slice(9)])), TypeError);
  await assert.rejects(unpack(new Blob([blob.slice(0, 8), '!', blob.slice(9)])), SyntaxError);
  await assert.rejects(unpack(blob.slice(0, -1)), /manifest length/);
  await assert.rejects(unpack(new Blob([blob, 'extra'])), /container length/);
  await assert.rejects(unpack(null), /container/);
});

test('enforces the combined limit across attachments', async () => {
  const part = new Blob([new Uint8Array(10_000_000)]);
  const half = new Blob(Array(5).fill(part));
  const files = [{ name: 'a', blob: half }, { name: 'b', blob: half }];
  const decoded = await unpack(pack({ files }));
  assert.deepEqual(decoded.files.map(file => file.blob.size), [50_000_000, 50_000_000]);
  assert.throws(() => pack({ files: [...files, { name: 'c', blob: new Blob(['x']) }] }), /File limit/);
});
