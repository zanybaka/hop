import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';
import { decryptTransfer, encryptTransfer, newTransfer } from '../src/envelope.mjs';
import { HOUR } from '../src/expiry.mjs';

function client(origin) {
  return {
    reserve(access, owner, version, bytes, flags = {}) {
      return fetch(origin + '/api/v1/reservations', {
        method: 'POST', headers: { authorization: 'Bearer ' + owner },
        body: JSON.stringify({ id: access.id, version, bytes, ...flags }),
      });
    },
    upload(token, body) {
      return fetch(origin + '/api/v1/uploads/' + token, { method: 'PUT', body });
    },
    read(access) { return fetch(origin + '/api/v1/records/' + access.id); },
    confirm(receipt) { return fetch(origin + '/api/v1/receipts/' + receipt, { method: 'POST' }); },
  };
}

test('HTTP publication persists without the sender, validates rights and versions, and expires', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-publication-'));
  let app;
  let now = 100_000;
  const access = newTransfer();
  const { secret: owner } = newTransfer();
  const options = { capacity: 65_536, diskHeadroom: 0, now: () => now };
  try {
    app = await startServer(directory, options);
    let api = client(app.origin);
    assert.equal((await api.read(access)).status, 404);
    const encrypted = await encryptTransfer(access, { text: 'Синтетический текст', files: [{ name: 'a.bin', blob: new Blob([Uint8Array.of(0, 255)]) }] });
    const limited = await api.reserve(access, owner, 0, 108_000_001);
    assert.equal(limited.status, 413);
    assert.equal((await api.reserve(access, owner, 0, 100_000)).status, 507);
    const reserved = await api.reserve(access, owner, 0, encrypted.size, { hasFiles: true });
    assert.equal(reserved.status, 201);
    const { token } = await reserved.json();
    assert.equal((await api.upload(token, new Blob([encrypted, 'excess']))).status, 413);
    const saved = await api.upload(token, encrypted);
    assert.equal(saved.status, 201);
    assert.equal((await saved.json()).version, 1);
    await app.close();
    app = undefined;

    now += HOUR / 2;
    app = await startServer(directory, options);
    api = client(app.origin);
    const result = await api.read(access);
    assert.equal(result.status, 200);
    assert.equal(result.headers.get('x-hop-version'), '1');
    const payload = await decryptTransfer(access, await result.blob());
    assert.equal(payload.text, 'Синтетический текст');
    assert.deepEqual(new Uint8Array(await payload.files[0].blob.arrayBuffer()), Uint8Array.of(0, 255));
    const receipt = result.headers.get('x-hop-receipt');
    assert(receipt);
    const proof = await api.confirm(receipt);
    assert.equal(proof.status, 200);
    assert.equal((await proof.json()).expiresAt, now + HOUR);
    assert.equal((await api.confirm(receipt)).status, 404);
    assert.equal((await api.reserve(access, newTransfer().secret, 1, encrypted.size)).status, 403);
    assert.equal((await api.reserve(access, owner, 0, encrypted.size)).status, 409);
    now += HOUR;
    assert.equal((await api.read(access)).status, 404);
  } finally {
    await app?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('two pair members save one immutable, read-only checkpoint', async () => {
  const { saveCheckpoint, readPublication } = await import('../src/publication.mjs');
  const directory = await mkdtemp(join(tmpdir(), 'hop-checkpoint-'));
  const app = await startServer(directory);
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = (path, options) => originalFetch(new URL(path, app.origin), options);
    const access = newTransfer();
    const content = { text: 'Confirmed snapshot', files: [] };
    const [left, right] = await Promise.all([saveCheckpoint(access, content), saveCheckpoint(access, content)]);
    assert.equal(left.version, 1);
    assert.equal(right.version, 1);
    assert.equal(Object.hasOwn(left, 'owner'), false);
    assert.equal(Object.hasOwn(right, 'owner'), false);
    assert.deepEqual((await readPublication(access)).content, content);
    assert.equal((await client(app.origin).reserve(access, newTransfer().secret, 1, 64)).status, 403);
  } finally {
    globalThis.fetch = originalFetch;
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('exchange grants persist, are scoped to one publication, and are checked again at commit', async () => {
  const { createHash } = await import('node:crypto');
  const directory = await mkdtemp(join(tmpdir(), 'hop-access-'));
  const access = newTransfer();
  const owner = newTransfer().secret;
  const writer = newTransfer().secret;
  let app;
  try {
    app = await startServer(directory);
    let api = client(app.origin);
    const encrypted = await encryptTransfer(access, { text: 'original' });
    const first = await api.reserve(access, owner, 0, encrypted.size);
    assert.equal((await api.upload((await first.json()).token, encrypted)).status, 201);
    const settings = (credential, action, payload) => fetch(app.origin + '/api/v1/exchange/' + access.id + (action ? '/' + action : ''), {
      method: action ? 'POST' : 'GET', headers: { authorization: 'Bearer ' + credential },
      body: action ? JSON.stringify(payload) : undefined,
    });
    const invite = token => settings(owner, 'invite', { fingerprint: createHash('sha256').update(token).digest('hex') });
    assert.equal((await settings(access.secret)).status, 403);
    assert.equal((await invite(writer)).status, 200);
    assert.equal((await settings(writer, 'mode', { mode: 'exchange' })).status, 403);
    assert.equal((await api.reserve(access, writer, 1, encrypted.size)).status, 403);
    assert.equal((await settings(owner, 'mode', { mode: 'exchange' })).status, 200);
    const invitation = newTransfer().secret;
    const device = newTransfer().secret;
    const fingerprint = secret => createHash('sha256').update(secret).digest('hex');
    assert.equal((await settings(owner, 'one-use', { fingerprint: fingerprint(invitation) })).status, 200);
    assert.equal((await settings(invitation, 'claim', { fingerprint: fingerprint(device) })).status, 200);
    assert.equal((await settings(invitation, 'claim', { fingerprint: fingerprint(device) })).status, 200);
    assert.equal((await settings(invitation, 'claim', { fingerprint: fingerprint(newTransfer().secret) })).status, 403);
    assert.equal((await api.reserve(access, invitation, 1, encrypted.size)).status, 403);
    for (let i = 0; i < 5; i++) assert.equal((await invite(newTransfer().secret)).status, 200);
    assert.equal((await invite(newTransfer().secret)).status, 507);
    await app.close();
    app = undefined;
    app = await startServer(directory);
    api = client(app.origin);
    assert.equal((await (await settings(writer)).json()).canWrite, true);
    assert.equal((await (await settings(owner)).json()).members.filter(member => member.present).length, 1);

    const next = await encryptTransfer(access, { text: 'uncommitted' });
    const reserved = await api.reserve(access, writer, 1, next.size);
    assert.equal(reserved.status, 201);
    assert.equal((await settings(owner, 'mode', { mode: 'read' })).status, 200);
    assert.equal((await api.upload((await reserved.json()).token, next)).status, 403);
    const old = await api.read(access);
    assert.equal((await decryptTransfer(access, await old.blob())).text, 'original');
    assert.equal((await settings(owner, 'mode', { mode: 'exchange' })).status, 200);
    const accepted = await api.reserve(access, writer, 1, next.size);
    assert.equal((await api.upload((await accepted.json()).token, next)).status, 201);
    // A guest write preserves the original owner.
    assert.equal((await settings(owner, 'mode', { mode: 'read' })).status, 200);
    assert.equal((await api.reserve(access, writer, 2, next.size)).status, 403);
    assert.equal((await settings(owner, 'mode', { mode: 'exchange' })).status, 200);
    const inFlight = await api.reserve(access, writer, 2, next.size);
    assert.equal(inFlight.status, 201);
    const { members } = await (await settings(owner)).json();
    const activeMember = members.find(member => member.present);
    assert(activeMember);
    assert.equal((await settings(writer, 'revoke-write', { member: activeMember.id })).status, 403);
    assert.equal((await settings(owner, 'revoke-write', { member: activeMember.id })).status, 200);
    assert.equal((await api.upload((await inFlight.json()).token, next)).status, 403);
    assert.equal((await settings(writer)).status, 403);
    assert.equal((await api.read(access)).status, 200);
  } finally {
    await app?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
