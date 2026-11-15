import assert from 'node:assert/strict';
import { test } from 'node:test';
import { newTransfer } from '../src/envelope.mjs';
import { compareRevision, openRevision, sealRevision } from '../src/direct-revision.mjs';

test('same-clock revisions have a common order and the frame authenticates role and clock', async () => {
  const access = newTransfer();
  const owner = { clock: 2, role: 'owner' };
  const recipient = { clock: 2, role: 'recipient' };
  assert(compareRevision(owner, recipient) > 0);
  assert(compareRevision(owner, { ...recipient, clock: 3 }) < 0);
  const frame = await sealRevision(access, owner, { text: 'new' });
  assert.deepEqual(await openRevision(access, frame, 'owner'),
    { revision: owner, content: { text: 'new', files: [] } });
  await assert.rejects(openRevision(access, frame, 'recipient'), /sender/);
  const bytes = new Uint8Array(await frame.arrayBuffer());
  bytes[7] ^= 1;
  await assert.rejects(openRevision(access, new Blob([bytes]), 'owner'), { name: 'OperationError' });
});
