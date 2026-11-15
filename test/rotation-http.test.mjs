import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { decryptTransfer, encryptTransfer, newTransfer } from '../src/envelope.mjs';
import { startServer } from '../src/server.mjs';

const fingerprint = value => createHash('sha256').update(value).digest('hex');
const memberKey = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

test('rotation replaces read and code access atomically and retains only authorized recovery packages', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-rotation-'));
  const owner = newTransfer().secret;
  const removed = newTransfer().secret;
  const retained = newTransfer().secret;
  const pending = newTransfer().secret;
  const newlyClaimed = newTransfer().secret;
  const access = newTransfer();
  const next = newTransfer();
  const stable = access.id;
  let app;
  try {
    const now = Date.now();
    const options = { now: () => now };
    app = await startServer(directory, options);
    const request = (path, body, secret) => fetch(app.origin + '/api/v1/' + path, body ? {
      method: 'POST', body: JSON.stringify(body),
      headers: { 'content-type': 'application/json', ...(secret && { authorization: 'Bearer ' + secret }) },
    } : { headers: secret ? { authorization: 'Bearer ' + secret } : undefined });
    const settings = (secret, action, body) => request('exchange/' + stable + (action ? '/' + action : ''), body, secret);
    const reserve = (credential, version, body, fields) =>
      request('reservations', { id: stable, version, bytes: body.size, ...fields }, credential);
    const upload = async (reservation, body) => {
      assert.equal(reservation.status, 201);
      const { token } = await reservation.json();
      return fetch(app.origin + '/api/v1/uploads/' + token, { method: 'PUT', body });
    };
    const oldBlob = await encryptTransfer(access, { text: 'Latest state' });
    assert.equal((await upload(await reserve(owner, 0, oldBlob), oldBlob)).status, 201);
    const nextBlob = await encryptTransfer(next, { text: 'Latest state' });

    const [keyPeriod] = await (await request('short-code/keys')).json();
    const oldIndex = newTransfer().id;
    const registerCode = locator => request('short-code/' + locator, {
      epoch: keyPeriod.epoch, lookup: locator === stable ? oldIndex : newTransfer().id,
      wrapper: '12'.repeat(92),
    }, owner);
    assert.equal((await registerCode(stable)).status, 201);
    assert.equal((await request('short-code/' + oldIndex)).status, 200);

    assert.equal((await settings(owner, 'mode', { mode: 'exchange' })).status, 200);
    for (const writer of [removed, retained]) {
      assert.equal((await settings(owner, 'invite', { fingerprint: fingerprint(writer) })).status, 200);
    }
    assert.equal((await settings(owner, 'one-use', { fingerprint: fingerprint(pending) })).status, 200);
    const ownerKey = memberKey();
    const response = await settings(owner, 'member-key', { key: ownerKey });
    assert.equal(response.status, 200);
    const before = await response.json();
    assert.deepEqual(before.ownerKey, ownerKey);
    const [removedMember, retainedMember] = before.members;
    const retainedKey = memberKey();
    const invalidKey = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'A'.repeat(43) };
    assert.equal((await settings(retained, 'member-key', { key: invalidKey })).status, 400);
    assert.equal((await settings(retained, 'member-key', { key: retainedKey })).status, 200);
    assert.equal((await settings(retained, 'member-key', { key: retainedKey })).status, 200);
    assert.equal((await settings(retained, 'member-key', { key: memberKey() })).status, 409);
    assert.deepEqual((await (await settings(owner)).json()).members[1].key, retainedKey);

    const rotation = {
      locator: next.id, member: removedMember.id,
      recovery: [{ member: 'owner', wrapper: 'owner envelope' }, { member: retainedMember.id, wrapper: 'retained envelope' }],
    };
    assert.equal((await reserve(retained, 1, nextBlob, { rotation })).status, 403);
    assert.equal((await reserve(owner, 1, nextBlob, { rotation: { ...rotation, recovery: rotation.recovery.slice(0, 1) } })).status, 409);
    const removedWrite = await reserve(removed, 1, oldBlob);
    const abortedRotation = await reserve(owner, 1, nextBlob, { rotation });
    const badBlob = new Blob([new Uint8Array(nextBlob.size + 1)]);
    assert.equal((await upload(abortedRotation, badBlob)).status, 413);
    assert.equal((await request('records/' + stable)).status, 200);
    assert.equal((await settings(removed)).status, 200);
    assert.equal((await request('records/' + next.id)).status, 404);

    const racedRotation = await reserve(owner, 1, nextBlob, { rotation });
    const claimKey = memberKey();
    const claim = { fingerprint: fingerprint(newlyClaimed), key: claimKey };
    assert.equal((await settings(pending, 'claim', { ...claim, key: invalidKey })).status, 400);
    assert.equal((await settings(newlyClaimed)).status, 403);
    assert.equal((await settings(pending, 'claim', claim)).status, 200);
    assert.equal((await settings(pending, 'claim', claim)).status, 200);
    assert.equal((await settings(pending, 'claim', { ...claim, key: memberKey() })).status, 409);
    assert.equal((await upload(racedRotation, nextBlob)).status, 409);
    const { members } = await (await settings(owner)).json();
    assert.deepEqual(members[2].key, claimKey);
    assert.equal((await settings(owner, 'revoke-write', { member: members[2].id })).status, 200);
    const anotherPending = newTransfer().secret;
    assert.equal((await settings(owner, 'one-use', { fingerprint: fingerprint(anotherPending) })).status, 200);

    const rotationReply = await upload(await reserve(owner, 1, nextBlob, { rotation }), nextBlob);
    assert.equal(rotationReply.status, 201);
    assert.deepEqual(await rotationReply.json(), { version: 2, contentVersion: 1, locator: next.id, expiresAt: before.expiresAt });
    assert.equal((await upload(removedWrite, oldBlob)).status, 409);
    assert.equal((await reserve(retained, 2, oldBlob)).status, 409);
    assert.equal((await settings(anotherPending, 'claim', { locator: next.id, fingerprint: fingerprint(newlyClaimed) })).status, 403);
    assert.equal((await settings(removed)).status, 403);
    assert.equal((await request('records/' + stable)).status, 404);
    assert.equal((await request('short-code/' + oldIndex)).status, 404);
    assert.equal((await registerCode(stable)).status, 404);
    assert.equal((await registerCode(next.id)).status, 201);
    assert.equal((await (await settings(retained)).json()).recovery, 'retained envelope');
    assert.equal((await (await settings(owner)).json()).recovery, 'owner envelope');
    await app.close();
    app = undefined;

    app = await startServer(directory, options);
    assert.equal((await request('records/' + stable)).status, 404);
    assert.equal((await request('short-code/' + oldIndex)).status, 404);
    assert.equal((await (await settings(retained)).json()).locator, next.id);
    const current = await request('records/' + next.id);
    assert.equal(current.status, 200);
    assert.equal(current.headers.get('x-hop-content-version'), '1');
    assert.equal((await decryptTransfer(next, await current.blob())).text, 'Latest state');
    const updated = await encryptTransfer(next, { text: 'Still exchanging' });
    assert.equal((await settings(owner, 'mode', { mode: 'read' })).status, 200);
    assert.equal((await reserve(retained, 2, updated, { locator: next.id })).status, 403);
    assert.equal((await settings(owner, 'mode', { mode: 'exchange' })).status, 200);
    const updatedReply = await upload(await reserve(retained, 2, updated, { locator: next.id }), updated);
    assert.equal(updatedReply.status, 201);
    assert.equal((await updatedReply.json()).contentVersion, 2);
  } finally {
    await app?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
