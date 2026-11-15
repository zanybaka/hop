import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';

test('explicit pair approval gates offer and answer at the HTTP boundary', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-pairing-http-'));
  const app = await startServer(directory);
  try {
    const call = (path, method = 'GET', token, body, origin = app.origin) => fetch(app.origin + '/api/v1/pairing/' + path, {
      method, headers: { origin, ...(token && { authorization: 'Bearer ' + token }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.equal((await call('offers', 'POST', undefined, undefined, 'https://other.test')).status, 403);
    const offer = await call('offers', 'POST');
    assert.equal(offer.status, 201);
    const { invitation, owner } = await offer.json();
    const join = await call('joins', 'POST', undefined, { invitation });
    assert.equal(join.status, 201);
    const { recipient } = await join.json();
    assert.equal((await call('joins', 'POST', undefined, { invitation })).status, 404);
    const description = { type: 'offer', sdp: 'synthetic offer' };
    assert.equal((await call('signal', 'POST', owner, description)).status, 409);
    assert.equal((await call('decision', 'POST', recipient, { state: 'approved' })).status, 403);
    assert.equal((await call('decision', 'POST', owner, { state: 'approved' })).status, 200);
    assert.equal((await call('signal', 'POST', owner, description)).status, 200);
    assert.deepEqual(await (await call('signal', 'GET', recipient)).json(), { signal: description });
    const answer = { type: 'answer', sdp: 'synthetic answer' };
    assert.equal((await call('signal', 'POST', recipient, answer)).status, 200);
    assert.deepEqual(await (await call('signal', 'GET', owner)).json(), { signal: answer });
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('pairing link retains the signal key and authenticates invitation and role', async () => {
  const { randomBytes } = await import('node:crypto');
  const { invitationLink, parseInvitationLink, signalCodec } = await import('../src/pairing-client.mjs');
  const access = { invitation: randomBytes(32).toString('hex'), secret: randomBytes(32).toString('hex') };
  const url = invitationLink('https://example.test/hop/', access.invitation, access.secret);
  assert.equal(new URL(url).pathname + new URL(url).search, '/hop/');
  assert.deepEqual(parseInvitationLink(url), access);
  const codec = await signalCodec(access);
  const description = { type: 'offer', sdp: 'synthetic SDP with transport fingerprint' };
  const protectedSignal = await codec.wrap(description);
  assert(!protectedSignal.sdp.includes(description.sdp));
  assert.deepEqual(await (await signalCodec(parseInvitationLink(url))).unwrap(protectedSignal), description);
  await assert.rejects(codec.unwrap({ ...protectedSignal, type: 'answer' }), { name: 'OperationError' });
  const other = await signalCodec({ ...access, invitation: randomBytes(32).toString('hex') });
  await assert.rejects(other.unwrap(protectedSignal), { name: 'OperationError' });
});

test('mounts assets and API under one page path and uses the configured browser origin', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-mount-http-'));
  const publicOrigin = 'https://example.test';
  const app = await startServer(directory, { basePath: '/hop', publicOrigin });
  try {
    const slash = await fetch(app.origin + '/hop', { redirect: 'manual' });
    assert.equal(slash.status, 308);
    assert.equal(slash.headers.get('location'), '/hop/');
    for (const path of ['/hop/', '/hop/app.mjs', '/hop/src/publication.mjs']) {
      assert.equal((await fetch(app.origin + path)).status, 200);
    }
    for (const path of ['/', '/app.mjs', '/hop-other/app.mjs', '/api/v1/short-code/keys']) {
      assert.equal((await fetch(app.origin + path)).status, 404);
    }
    const offer = origin => fetch(app.origin + '/hop/api/v1/pairing/offers', {
      method: 'POST', headers: { origin },
    });
    assert.equal((await offer(app.origin)).status, 403);
    assert.equal((await offer(publicOrigin)).status, 201);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
