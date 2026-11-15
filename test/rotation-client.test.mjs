import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decryptTransfer, newTransfer, parseTransferLink } from '../src/envelope.mjs';
import { claimWriter, createWriterLink, enrollRotationKey, publishPublication, readWriterLink, rotatePublication } from '../src/publication.mjs';
import { createRotationKeyPair, openRotationAccess, sealRotationAccess } from '../src/rotation-client.mjs';

test('recovery binds the new key to a recipient, transfer and locator', async () => {
  const stableId = newTransfer().id;
  const access = newTransfer();
  const [member, removed] = await Promise.all([createRotationKeyPair(), createRotationKeyPair()]);
  const wrapper = await sealRotationAccess(stableId, access, member.publicKey);
  assert.deepEqual(Object.keys(member.publicKey).sort(), ['crv', 'kty', 'x', 'y']);
  assert(!wrapper.includes(access.secret));
  assert.deepEqual(await openRotationAccess(stableId, access.id, wrapper, member.privateKey), access);
  await assert.rejects(openRotationAccess(stableId, access.id, wrapper, removed.privateKey));
  await assert.rejects(openRotationAccess(newTransfer().id, access.id, wrapper, member.privateKey));
  await assert.rejects(openRotationAccess(stableId, newTransfer().id, wrapper, member.privateKey));
  await assert.rejects(sealRotationAccess(stableId, access, member.privateKey));
  const payload = JSON.parse(wrapper);
  payload.ciphertext = (payload.ciphertext.startsWith('0') ? '1' : '0') + payload.ciphertext.slice(1);
  await assert.rejects(openRotationAccess(stableId, access.id, JSON.stringify(payload), member.privateKey));
});

test('publication keeps its managed address and encrypts rotated updates for the new locator', async t => {
  const original = newTransfer();
  const replacement = newTransfer();
  const owner = newTransfer().secret;
  const member = await createRotationKeyPair();
  const wrapper = await sealRotationAccess(original.id, replacement, member.publicKey);
  const content = { text: 'Current text', files: [] };
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (path, request) => {
    calls.push([path, request]);
    return Response.json(path.endsWith('/reservations') ? { token: 'test' } : { version: 2, expiresAt: 42 });
  });
  const state = { access: original, stableId: original.id, owner, version: 1 };
  const recovery = [{ member: 'owner', wrapper }];
  const rotated = await rotatePublication(state, content, { access: replacement, member: 'removed-id', recovery });
  assert.deepEqual(rotated, { access: replacement, version: 2, expiresAt: 42 });
  const [reserve, upload] = calls;
  const body = JSON.parse(reserve[1].body);
  assert.deepEqual(body, {
    id: original.id, locator: original.id, version: 1, bytes: upload[1].body.size, hasFiles: false,
    rotation: { member: 'removed-id', locator: replacement.id, recovery },
  });
  assert.deepEqual(await decryptTransfer(replacement, upload[1].body), content);
  await assert.rejects(decryptTransfer(original, upload[1].body));

  calls.length = 0;
  await publishPublication({ ...state, ...rotated }, content);
  assert.equal(JSON.parse(calls[0][1].body).id, original.id);
  assert.equal(JSON.parse(calls[0][1].body).locator, replacement.id);
  assert.equal(JSON.parse(calls[0][1].body).rotation, undefined);
});

test('writer invitations retain the old URL format and carry the current locator after rotation', async t => {
  const old = newTransfer();
  const current = newTransfer();
  const owner = newTransfer().secret;
  const device = newTransfer().secret;
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (path, request) => {
    calls.push([path, JSON.parse(request.body)]);
    return Response.json({});
  });
  const page = 'https://example.test/hop/';
  const oldInvite = readWriterLink(await createWriterLink(page, old, owner));
  assert.equal(oldInvite.stableId, undefined);
  assert.deepEqual(parseTransferLink(oldInvite.url), old);
  assert.equal(calls[0][1].locator, undefined);
  const invite = readWriterLink(await createWriterLink(page, current, owner, old.id));
  assert.equal(invite.stableId, old.id);
  assert.deepEqual(parseTransferLink(invite.url), current);
  assert.equal(calls[1][0], '/api/v1/exchange/' + old.id + '/one-use');
  assert.equal(calls[1][1].locator, current.id);
  const { publicKey } = await createRotationKeyPair();
  await claimWriter(invite.stableId, invite.writer, device, current.id, publicKey);
  assert.equal(calls[2][0], '/api/v1/exchange/' + old.id + '/claim');
  assert.equal(calls[2][1].locator, current.id);
  assert.deepEqual(calls[2][1].key, publicKey);
  await enrollRotationKey(old.id, device, publicKey);
  assert.deepEqual(calls[3], ['/api/v1/exchange/' + old.id + '/member-key', { key: publicKey }]);
});
