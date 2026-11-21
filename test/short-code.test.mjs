import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { constants, createPrivateKey, privateDecrypt } from 'node:crypto';
import { startServer } from '../src/server.mjs';
import { encryptTransfer, decryptTransfer, newTransfer } from '../src/envelope.mjs';
import { deriveCode, newCode, normalizeCode, PERIOD, unwrapAccess, wrapAccess } from '../src/short-code-crypto.mjs';

test('short code routes authenticate publication, survive rotation and restart, and isolate the full link', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-short-code-'));
  let app;
  let now = PERIOD - 30_000;
  const options = { now: () => now, codeLimits: { perSource: 3, total: 3 }, diskHeadroom: 0 };
  const access = newTransfer();
  const owner = newTransfer().secret;
  const codeApi = '/api/v1/short-code/';
  const request = (path, data, credential) => fetch(app.origin + path, data ? {
    method: 'POST', headers: { 'content-type': 'application/json', ...(credential && { authorization: 'Bearer ' + credential }) },
    body: JSON.stringify(data),
  } : undefined);
  const evaluate = async (epoch, blinded) => {
    const response = await request(codeApi + 'evaluate', { epoch, blinded });
    assert.equal(response.status, 200);
    return (await response.json()).signed;
  };
  try {
    app = await startServer(directory, options);
    const encrypted = await encryptTransfer(access, { text: 'Stored text', files: [] });
    const reservation = await request('/api/v1/reservations', { id: access.id, version: 0, bytes: encrypted.size }, owner);
    const { token } = await reservation.json();
    assert.equal((await fetch(app.origin + '/api/v1/uploads/' + token, { method: 'PUT', body: encrypted })).status, 201);
    const keysResponse = await request(codeApi + 'keys');
    assert.equal(keysResponse.headers.get('strict-transport-security'), 'max-age=31536000');
    assert.match(keysResponse.headers.get('content-security-policy'), /form-action 'self'/);
    assert.equal(keysResponse.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(keysResponse.headers.get('cross-origin-resource-policy'), 'same-origin');
    assert.match(keysResponse.headers.get('permissions-policy'), /camera=\(\).*microphone=\(\)/);
    const page = await fetch(app.origin + '/app.mjs');
    assert.equal(page.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.match(page.headers.get('permissions-policy'), /geolocation=\(\)/);
    const [first] = await keysResponse.json();
    const code = newCode(first.epoch);
    assert.equal(normalizeCode(code.slice(0, 4).toLowerCase() + '-' + code.slice(4)), code);
    assert.equal(normalizeCode('ſ2345678'), null);
    const derived = await deriveCode(code, first, evaluate);
    assert.equal((await request(codeApi + derived.lookup)).status, 404);
    const wrapper = await wrapAccess(derived, access);
    const registration = { epoch: first.epoch, lookup: derived.lookup, wrapper };
    assert.equal((await request(codeApi + access.id, registration, newTransfer().secret)).status, 403);
    assert.equal((await request(codeApi + access.id, registration, owner)).status, 201);
    assert.equal((await request(codeApi + access.id, registration, owner)).status, 201);
    assert.equal((await request(codeApi + access.id, { ...registration, lookup: newTransfer().id }, owner)).status, 409);
    const wrong = code.slice(0, 7) + (code[7] === '2' ? '3' : '2');
    const wrongKeys = await deriveCode(wrong, first, evaluate);
    assert.equal((await request(codeApi + wrongKeys.lookup)).status, 404);
    const invalid = await request(codeApi + 'evaluate', { epoch: first.epoch, blinded: '0'.repeat(768) });
    assert.equal(invalid.status, 400);
    const denied = await fetch(app.origin + codeApi + 'evaluate', { method: 'POST', body: '{}' });
    assert.equal(denied.status, 403);
    await app.close();
    app = undefined;
    app = await startServer(directory, options);
    const limited = await request(codeApi + 'evaluate', { epoch: first.epoch, blinded: '0'.repeat(767) + '2' });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
    const full = await request('/api/v1/records/' + access.id);
    assert.equal((await decryptTransfer(access, await full.blob())).text, 'Stored text');

    now = PERIOD;
    const [current, previous] = await (await request(codeApi + 'keys')).json();
    assert.equal(current.epoch, first.epoch + 1);
    assert.deepEqual(previous, first);
    const fresh = await deriveCode(code, previous, evaluate);
    const reply = await (await request(codeApi + fresh.lookup)).json();
    assert.deepEqual(await unwrapAccess(fresh, reply.wrapper), access);
    const tampered = (reply.wrapper[0] === '0' ? '1' : '0') + reply.wrapper.slice(1);
    await assert.rejects(unwrapAccess(fresh, tampered));
    const db = new DatabaseSync(join(directory, 'short-code.sqlite'));
    try {
      assert.deepEqual(db.prepare('SELECT name FROM sqlite_schema WHERE type = ? ORDER BY name').all('table')
        .map(({ name }) => name), ['codes', 'counters']);
    } finally { db.close(); }
    const keysDb = new DatabaseSync(join(directory, 'short-code-keys.sqlite'));
    try {
      const { material } = keysDb.prepare('SELECT material FROM keys WHERE epoch = ?').get(first.epoch);
      const key = createPrivateKey({ key: material, type: 'pkcs8', format: 'der' });
      const offline = await deriveCode(code, first, (_epoch, blinded) =>
        privateDecrypt({ key, padding: constants.RSA_NO_PADDING }, Buffer.from(blinded, 'hex')).toString('hex'));
      assert.equal(offline.lookup, fresh.lookup);
      assert.deepEqual(await unwrapAccess(offline, reply.wrapper), access);
    } finally { keysDb.close(); }
    now = 2 * PERIOD - 30_000;
    assert.equal((await request(codeApi + fresh.lookup)).status, 404);
    now = 2 * PERIOD;
    assert.equal((await (await request(codeApi + 'keys')).json()).some(({ epoch }) => epoch === first.epoch), false);
  } finally {
    await app?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('rate limits use the address set by an explicitly trusted loopback proxy', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-code-proxy-'));
  let app;
  try {
    await assert.rejects(startServer(directory, { host: '0.0.0.0', trustLoopbackProxy: true }), /requires loopback/);
    app = await startServer(directory, { trustLoopbackProxy: true, now: () => PERIOD, codeLimits: { perSource: 1, total: 2 } });
    const base = app.origin + '/api/v1/short-code/';
    const [config] = await (await fetch(base + 'keys')).json();
    const request = address => fetch(base + 'evaluate', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(address && { 'x-hop-client-ip': address }) },
      body: JSON.stringify({ epoch: config.epoch, blinded: '0'.repeat(767) + '2' }),
    });
    assert.equal((await request()).status, 403);
    assert.equal((await request('192.0.2.1, 192.0.2.2')).status, 403);
    assert.equal((await request('192.0.2.1')).status, 200);
    assert.equal((await request('192.0.2.1')).status, 429);
    assert.equal((await request('2001:db8::1')).status, 200);
    assert.equal((await request('192.0.2.2')).status, 429);
  } finally {
    await app?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
