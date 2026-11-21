import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from '../src/server.mjs';

async function withServer(options, run) {
  const directory = await mkdtemp(join(tmpdir(), 'hop-head-http-'));
  const app = await startServer(directory, options);
  try { await run(app); }
  finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
}

// Служебные заголовки соединения Node выставляет сам, их в сравнение не берём.
const TRANSPORT = new Set(['connection', 'keep-alive', 'date', 'transfer-encoding']);
const headersOf = response => Object.fromEntries([...response.headers].filter(([name]) => !TRANSPORT.has(name)));

test('HEAD answers like GET for the page, a static file and a GET API method, without a body', async () => {
  await withServer({}, async app => {
    for (const path of ['/', '/app.mjs', '/api/v1/short-code/keys']) {
      const get = await fetch(app.origin + path);
      const head = await fetch(app.origin + path, { method: 'HEAD' });
      const body = await get.arrayBuffer();
      assert.equal(get.status, 200, path);
      assert.equal(head.status, get.status, path);
      assert.deepEqual(headersOf(head), headersOf(get), path);
      assert.equal(head.headers.get('content-length'), String(body.byteLength), path);
      assert.equal((await head.arrayBuffer()).byteLength, 0, path);
    }
  });
});

test('HEAD gives the same error as GET and other methods behave as before', async () => {
  await withServer({}, async app => {
    const get = await fetch(app.origin + '/missing');
    const head = await fetch(app.origin + '/missing', { method: 'HEAD' });
    assert.equal(head.status, 404);
    assert.deepEqual(headersOf(head), headersOf(get));
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    assert.equal((await fetch(app.origin + '/', { method: 'POST' })).status, 404);
    assert.equal((await fetch(app.origin + '/app.mjs', { method: 'DELETE' })).status, 404);
  });
});

test('HEAD to a mounted site redirects like GET', async () => {
  await withServer({ basePath: '/hop' }, async app => {
    const get = await fetch(app.origin + '/hop', { redirect: 'manual' });
    const head = await fetch(app.origin + '/hop', { method: 'HEAD', redirect: 'manual' });
    assert.equal(head.status, 308);
    assert.deepEqual(headersOf(head), headersOf(get));
    assert.equal((await fetch(app.origin + '/hop/app.mjs', { method: 'HEAD' })).status, 200);
    assert.equal((await fetch(app.origin + '/app.mjs', { method: 'HEAD' })).status, 404);
  });
});

test('HEAD on a relay does not take the frame', async () => {
  await withServer({}, async app => {
    const call = (path, method, token, body) => fetch(app.origin + '/api/v1/pairing/' + path, {
      method, headers: { ...(token && { authorization: 'Bearer ' + token }) }, body,
    });
    const { invitation, owner } = await (await call('offers', 'POST')).json();
    const joined = await (await call('joins', 'POST', undefined, JSON.stringify({ invitation }))).json();
    const recipient = joined.recipient;
    assert.equal((await call('decision', 'POST', owner, JSON.stringify({ state: 'approved' }))).status, 200);
    assert.equal((await call('relay', 'POST', owner, Buffer.from('frame'))).status, 201);
    const head = await call('relay', 'HEAD', recipient);
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), '5');
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    const get = await call('relay', 'GET', recipient);
    assert.equal(get.status, 200);
    assert.equal(Buffer.from(await get.arrayBuffer()).toString(), 'frame');
    assert.equal((await call('relay', 'HEAD', recipient)).status, 204);
  });
});
