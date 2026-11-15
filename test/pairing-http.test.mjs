import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';
import { encryptTransfer, newTransfer } from '../src/envelope.mjs';
import { deriveCode, newCode, PERIOD, unwrapAccess, wrapAccess } from '../src/short-code-crypto.mjs';

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

test('short pair invitations share the same one-time join with QR and the code limiter', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-pair-code-'));
  let time = PERIOD;
  const app = await startServer(directory, { now: () => time, codeLimits: { perSource: 4, total: 4 } });
  try {
    const api = app.origin + '/api/v1/';
    const get = path => fetch(api + path);
    const post = (path, value, owner) => fetch(api + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(owner && { authorization: 'Bearer ' + owner }) },
      body: JSON.stringify(value),
    });
    const offer = async () => (await post('pairing/offers', {})).json();
    const [config] = await (await get('short-code/keys')).json();
    const first = await offer();
    const access = { id: first.invitation, secret: newTransfer().secret };
    const code = newCode(config.epoch);
    const evaluate = (epoch, blinded) => post('short-code/evaluate', { epoch, blinded });
    const keysFor = input => deriveCode(input, config, async (epoch, blinded) => {
      const result = await evaluate(epoch, blinded);
      assert.equal(result.status, 200);
      return (await result.json()).signed;
    });
    const wrong = code.slice(0, -1) + (code.at(-1) === '2' ? '3' : '2');
    const keys = await keysFor(code);
    const unknown = await keysFor(wrong);
    assert.equal((await get('short-code/' + unknown.lookup)).status, 404);
    const registration = {
      epoch: config.epoch, lookup: keys.lookup, wrapper: await wrapAccess(keys, access),
    };
    assert.equal((await post('pairing/code', { ...registration, lookup: [] }, first.owner)).status, 400);
    assert.equal((await post('pairing/code', { ...registration, lookup: [keys.lookup] }, first.owner)).status, 400);
    assert.equal((await post('pairing/code', { ...registration, wrapper: [registration.wrapper] }, first.owner)).status, 400);
    assert.equal((await post('pairing/code', registration, newTransfer().secret)).status, 404);
    assert.equal((await post('pairing/code', registration, first.owner)).status, 201);
    const second = await offer();
    assert.equal((await post('pairing/code', registration, second.owner)).status, 409);
    const publication = newTransfer();
    const publisher = newTransfer().secret;
    const envelope = await encryptTransfer(publication, { text: 'test publication', files: [] });
    const res = await post('reservations', {
      id: publication.id, version: 0, bytes: envelope.size, hasFiles: false,
    }, publisher);
    assert.equal(res.status, 201);
    const { token } = await res.json();
    const stored = await fetch(api + 'uploads/' + token, {
      method: 'PUT', headers: { 'content-length': envelope.size }, body: envelope,
    });
    assert.equal(stored.status, 201);
    assert.equal((await post('short-code/' + publication.id, registration, publisher)).status, 409);
    const wrapped = await (await get('short-code/' + keys.lookup)).json();
    assert.equal(wrapped.kind, 'pair');
    const fromCode = await unwrapAccess(await keysFor(code), wrapped.wrapper);
    assert.deepEqual(fromCode, access);
    const results = await Promise.all([
      post('pairing/joins', { invitation: fromCode.id }),
      post('pairing/joins', { invitation: first.invitation }),
    ]);
    assert.deepEqual(results.map(res => res.status).sort(), [201, 404]);
    assert.equal((await get('short-code/' + keys.lookup)).status, 404);
    assert.equal((await post('pairing/decision', { state: 'declined' }, first.owner)).status, 200);
    assert.equal((await post('short-code/' + publication.id, registration, publisher)).status, 201);
    assert.equal((await post('pairing/code', registration, second.owner)).status, 409);
    const secondKeys = await keysFor(newCode(config.epoch));
    const secondRegistration = {
      epoch: config.epoch, lookup: secondKeys.lookup,
      wrapper: await wrapAccess(secondKeys, { id: second.invitation, secret: newTransfer().secret }),
    };
    assert.equal((await post('pairing/code', secondRegistration, second.owner)).status, 201);
    assert.equal((await evaluate(config.epoch, '0'.repeat(767) + '2')).status, 429);
    time += 300_000;
    assert.equal((await get('short-code/' + secondKeys.lookup)).status, 404);
    assert.equal((await post('pairing/joins', { invitation: second.invitation })).status, 404);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
