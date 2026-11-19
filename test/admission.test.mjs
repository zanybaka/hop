import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { statfsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAdmission } from '../src/admission.mjs';
import { startServer } from '../src/server.mjs';
import { decryptTransfer, encryptTransfer, newTransfer } from '../src/envelope.mjs';

test('admission counters stay at their fixed size', () => {
  const admission = createAdmission({
    reservePerSource: 1, reserveGlobal: 10_000, reserveCountPerSource: 1, reserveCountGlobal: 32,
    reserveBytesPerSource: 100, pairPerSource: 1, pairGlobal: 10_000, pairLivePerSource: 1, pairLiveGlobal: 16,
  });
  let reserved = 0;
  let paired = 0;
  for (let index = 0; index < 5_000; index += 1) {
    const address = `198.51.100.${index}`;
    try {
      admission.claimReserve(address, 10);
      reserved += 1;
    } catch (error) {
      assert.equal(error.code, 'limited');
    }
    try {
      admission.claimPair(address);
      paired += 1;
    } catch (error) {
      assert.equal(error.code, 'limited');
    }
  }
  assert.equal(reserved, 32);
  assert.equal(paired, 16);
  const bounds = admission.bounds();
  assert.equal(bounds.buckets, 128);
  assert.equal(bounds.holds, 32);
  assert.equal(bounds.pairHolds, 16);
  assert.equal(JSON.stringify(bounds).includes('198.51'), false);
});

test('one source is limited before it can take the shared reserve, and another source completes a transfer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-admit-transfer-'));
  const block = statfsSync(directory).bsize;
  let now = 10_000_000;
  const app = await startServer(directory, {
    trustLoopbackProxy: true, now: () => now, capacity: block * 2, diskHeadroom: 0,
    admissionLimits: { reservePerSource: 1, reserveGlobal: 10, reserveCountPerSource: 4, reserveBytesPerSource: block * 4 },
  });
  const ownerFor = () => newTransfer().secret;
  const reserve = (address, owner, access, bytes) => fetch(app.origin + '/api/v1/reservations', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + owner,
      'content-type': 'application/json',
      'x-hop-client-ip': address,
      'x-forwarded-for': '203.0.113.50',
    },
    body: JSON.stringify({ id: access.id, version: 0, bytes }),
  });
  try {
    const first = newTransfer();
    const firstOwner = ownerFor();
    const opened = await reserve('192.0.2.1', firstOwner, first, block);
    assert.equal(opened.status, 201);
    const denied = await reserve('192.0.2.1', ownerFor(), newTransfer(), block);
    assert.equal(denied.status, 429);
    assert.equal(denied.headers.get('retry-after'), '20');
    assert.equal(await denied.json().then(body => body.error), 'limited');
    const second = newTransfer();
    const secondOwner = ownerFor();
    const allowed = await reserve('192.0.2.2', secondOwner, second, block);
    assert.equal(allowed.status, 201);
    const crowded = await reserve('192.0.2.3', ownerFor(), newTransfer(), block);
    assert.equal(crowded.status, 507);

    const transferDir = await mkdtemp(join(tmpdir(), 'hop-admit-copy-'));
    const copy = await startServer(transferDir, {
      trustLoopbackProxy: true,
      admissionLimits: { reservePerSource: 1, reserveGlobal: 10 },
    });
    try {
      const access = newTransfer();
      const owner = ownerFor();
      const encrypted = await encryptTransfer(access, { text: 'independent transfer', files: [] });
      const created = await fetch(copy.origin + '/api/v1/reservations', {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + owner, 'content-type': 'application/json', 'x-hop-client-ip': '192.0.2.8',
        },
        body: JSON.stringify({ id: access.id, version: 0, bytes: encrypted.size }),
      });
      assert.equal(created.status, 201);
      const { token } = await created.json();
      assert.equal((await fetch(copy.origin + '/api/v1/uploads/' + token, { method: 'PUT', body: encrypted })).status, 201);
      const again = await fetch(copy.origin + '/api/v1/reservations', {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + ownerFor(), 'content-type': 'application/json', 'x-hop-client-ip': '192.0.2.8',
        },
        body: JSON.stringify({ id: newTransfer().id, version: 0, bytes: encrypted.size }),
      });
      assert.equal(again.status, 429);
      const otherAccess = newTransfer();
      const otherOwner = ownerFor();
      const other = await encryptTransfer(otherAccess, { text: 'from the other source', files: [] });
      const otherReserve = await fetch(copy.origin + '/api/v1/reservations', {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + otherOwner, 'content-type': 'application/json', 'x-hop-client-ip': '192.0.2.9',
        },
        body: JSON.stringify({ id: otherAccess.id, version: 0, bytes: other.size }),
      });
      assert.equal(otherReserve.status, 201);
      const otherToken = (await otherReserve.json()).token;
      assert.equal((await fetch(copy.origin + '/api/v1/uploads/' + otherToken, { method: 'PUT', body: other })).status, 201);
      const stored = await fetch(copy.origin + '/api/v1/records/' + otherAccess.id);
      assert.equal((await decryptTransfer(otherAccess, await stored.blob())).text, 'from the other source');
      const original = await fetch(copy.origin + '/api/v1/records/' + access.id);
      assert.equal((await decryptTransfer(access, await original.blob())).text, 'independent transfer');
    } finally {
      await copy.close();
      await rm(transferDir, { recursive: true, force: true });
    }
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('external forwarding headers do not choose the source', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-admit-xff-'));
  const limited = { reservePerSource: 1, reserveGlobal: 10, pairPerSource: 1, pairGlobal: 10, pairLivePerSource: 4 };
  const reserve = (app, headers) => fetch(app.origin + '/api/v1/reservations', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + newTransfer().secret, 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ id: newTransfer().id, version: 0, bytes: 64 }),
  });
  const offer = (app, headers) => fetch(app.origin + '/api/v1/pairing/offers', { method: 'POST', headers });
  let direct;
  let trusted;
  try {
    direct = await startServer(directory, { admissionLimits: limited });
    assert.equal((await reserve(direct, { 'x-forwarded-for': '198.51.100.1', 'x-hop-client-ip': '192.0.2.1' })).status, 201);
    const spoofed = await reserve(direct, { 'x-forwarded-for': '198.51.100.2', 'x-hop-client-ip': '192.0.2.2' });
    assert.equal(spoofed.status, 429);
    assert.equal((await offer(direct, { 'x-forwarded-for': '198.51.100.3' })).status, 201);
    assert.equal((await offer(direct, { 'x-forwarded-for': '198.51.100.4', 'x-hop-client-ip': '192.0.2.4' })).status, 429);

    trusted = await startServer(await mkdtemp(join(tmpdir(), 'hop-admit-proxy-')), {
      trustLoopbackProxy: true, admissionLimits: limited,
    });
    assert.equal((await reserve(trusted, { 'x-forwarded-for': '198.51.100.8' })).status, 403);
    assert.equal((await reserve(trusted, { 'x-hop-client-ip': '192.0.2.1, 192.0.2.2' })).status, 403);
    assert.equal((await reserve(trusted, {
      'x-hop-client-ip': '192.0.2.1', 'x-forwarded-for': '198.51.100.9',
    })).status, 201);
    assert.equal((await reserve(trusted, {
      'x-hop-client-ip': '192.0.2.1', 'x-forwarded-for': '198.51.100.10',
    })).status, 429);
    assert.equal((await reserve(trusted, {
      'x-hop-client-ip': '2001:db8::2', 'x-forwarded-for': '192.0.2.1',
    })).status, 201);
  } finally {
    await direct?.close();
    await trusted?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('a released or expired reserve frees the source allowance, including several users behind one address', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-admit-release-'));
  let now = 10_000_000;
  const app = await startServer(directory, {
    trustLoopbackProxy: true, now: () => now, lease: 5_000,
    admissionLimits: {
      reservePerSource: 10, reserveGlobal: 10, reserveCountPerSource: 1, reserveBytesPerSource: 10_000,
    },
  });
  const reserve = (address, bytes = 64) => fetch(app.origin + '/api/v1/reservations', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + newTransfer().secret,
      'content-type': 'application/json',
      'x-hop-client-ip': address,
    },
    body: JSON.stringify({ id: newTransfer().id, version: 0, bytes }),
  });
  try {
    const held = await reserve('192.0.2.20');
    assert.equal(held.status, 201);
    const blocked = await reserve('192.0.2.20');
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('retry-after'), '5');
    const token = (await held.json()).token;
    assert.equal((await fetch(app.origin + '/api/v1/uploads/' + token, { method: 'DELETE' })).status, 200);
    assert.equal((await reserve('192.0.2.20')).status, 201);
    assert.equal((await reserve('192.0.2.20')).status, 429);
    now += 5_000;
    assert.equal((await reserve('192.0.2.20')).status, 201);

    const shared = await startServer(await mkdtemp(join(tmpdir(), 'hop-admit-nat-')), {
      trustLoopbackProxy: true,
      admissionLimits: { reservePerSource: 10, reserveCountPerSource: 2, reserveBytesPerSource: 10_000, reserveGlobal: 10 },
    });
    try {
      const nat = '192.0.2.30';
      const one = newTransfer();
      const two = newTransfer();
      const body = await encryptTransfer(one, { text: 'nat one', files: [] });
      const otherBody = await encryptTransfer(two, { text: 'nat two', files: [] });
      const post = (access, owner, bytes, address) => fetch(shared.origin + '/api/v1/reservations', {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + owner, 'content-type': 'application/json', 'x-hop-client-ip': address,
        },
        body: JSON.stringify({ id: access.id, version: 0, bytes }),
      });
      const first = await post(one, newTransfer().secret, body.size, nat);
      const second = await post(two, newTransfer().secret, otherBody.size, nat);
      assert.equal(first.status, 201);
      assert.equal(second.status, 201);
      assert.equal((await post(newTransfer(), newTransfer().secret, body.size, nat)).status, 429);
      assert.equal((await post(newTransfer(), newTransfer().secret, body.size, '192.0.2.31')).status, 201);
      const firstToken = (await first.json()).token;
      const secondToken = (await second.json()).token;
      assert.equal((await fetch(shared.origin + '/api/v1/uploads/' + firstToken, { method: 'PUT', body })).status, 201);
      assert.equal((await fetch(shared.origin + '/api/v1/uploads/' + secondToken, { method: 'PUT', body: otherBody })).status, 201);
      assert.equal((await post(newTransfer(), newTransfer().secret, body.size, nat)).status, 201);
    } finally {
      await shared.close();
    }
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('pairing offers are limited per source, expire, and still allow another source to connect', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-admit-pair-'));
  let now = 10_000_000;
  const app = await startServer(directory, {
    trustLoopbackProxy: true, now: () => now, offerLifetime: 5_000, maxOffers: 2,
    admissionLimits: { pairPerSource: 10, pairGlobal: 10, pairLivePerSource: 1, pairLiveGlobal: 8 },
  });
  const offer = address => fetch(app.origin + '/api/v1/pairing/offers', {
    method: 'POST', headers: { 'x-hop-client-ip': address, 'x-forwarded-for': '203.0.113.7' },
  });
  try {
    const first = await offer('192.0.2.40');
    assert.equal(first.status, 201);
    const denied = await offer('192.0.2.40');
    assert.equal(denied.status, 429);
    assert.equal(denied.headers.get('retry-after'), '5');
    const second = await offer('192.0.2.41');
    assert.equal(second.status, 201);
    const { invitation } = await second.json();
    const joined = await fetch(app.origin + '/api/v1/pairing/joins', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-hop-client-ip': '192.0.2.40' },
      body: JSON.stringify({ invitation }),
    });
    assert.equal(joined.status, 201);
    assert.equal((await offer('192.0.2.42')).status, 507);
    now += 5_000;
    assert.equal((await offer('192.0.2.40')).status, 201);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('limit responses do not echo credentials or links', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hop-admit-log-'));
  const app = await startServer(directory, {
    trustLoopbackProxy: true, admissionLimits: { reservePerSource: 1, reserveGlobal: 5 },
  });
  const lines = [];
  const methods = ['log', 'info', 'warn', 'error', 'debug'];
  const original = Object.fromEntries(methods.map(name => [name, console[name]]));
  for (const name of methods) console[name] = (...args) => lines.push(args.map(String).join(' '));
  const owner = newTransfer().secret;
  const link = 'https://example.test/private/' + owner;
  try {
    const headers = {
      authorization: 'Bearer ' + owner,
      'content-type': 'application/json',
      'x-hop-client-ip': '192.0.2.70',
    };
    const body = access => JSON.stringify({ id: access.id, version: 0, bytes: 64, note: link });
    assert.equal((await fetch(app.origin + '/api/v1/reservations', {
      method: 'POST', headers, body: body(newTransfer()),
    })).status, 201);
    const denied = await fetch(app.origin + '/api/v1/reservations', {
      method: 'POST', headers, body: body(newTransfer()),
    });
    assert.equal(denied.status, 429);
    assert.equal(await denied.text(), '{"error":"limited"}');
    const written = lines.join('\n');
    assert.equal(written.includes(owner), false);
    assert.equal(written.includes(link), false);
    assert.equal(written.includes('192.0.2.70'), false);
  } finally {
    for (const name of methods) console[name] = original[name];
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
