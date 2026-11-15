import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decryptTransfer, encryptTransfer, newTransfer, parseTransferLink, transferLink } from '../src/envelope.mjs';

test('fresh recipient reconstructs access from a full link and decrypts', async () => {
  const sender = newTransfer();
  const link = transferLink('https://example.test/hop/', sender);
  const url = new URL(link);
  assert.equal(url.pathname + url.search, '/hop/');
  const receiver = parseTransferLink(link);
  const file = new Blob([Uint8Array.of(0, 255)]);
  const encrypted = await encryptTransfer(sender, { text: 'Привет', files: [{ name: 'a.bin', blob: file }] });
  const decoded = await decryptTransfer(receiver, encrypted);
  assert.equal(decoded.text, 'Привет');
  assert.deepEqual(new Uint8Array(await decoded.files[0].blob.arrayBuffer()), Uint8Array.of(0, 255));
  assert.deepEqual(await decryptTransfer(receiver, await encryptTransfer(sender)), { text: '', files: [] });
});

test('wrong access, altered ciphertext, and unknown versions fail before container parsing', async () => {
  const access = newTransfer();
  const encrypted = await encryptTransfer(access, { text: 'sample' });
  const other = newTransfer();
  await assert.rejects(decryptTransfer({ ...access, secret: other.secret }, encrypted), { name: 'OperationError' });
  await assert.rejects(decryptTransfer({ ...access, id: other.id }, encrypted), { name: 'OperationError' });
  const corrupt = new Uint8Array(await encrypted.arrayBuffer());
  corrupt[corrupt.length - 1] ^= 1;
  await assert.rejects(decryptTransfer(access, new Blob([corrupt])), { name: 'OperationError' });
  await assert.rejects(decryptTransfer(access, new Blob(['HOPX', encrypted.slice(4)])), /version/);
  assert.throws(() => parseTransferLink('https://example.test/hop/'), /link/);
  assert.throws(() => parseTransferLink(transferLink('https://example.test/hop/', access).replace('#v1/', '#v2/')), /link/);
});
