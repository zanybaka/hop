import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { chmod } from 'node:fs/promises';
import { mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { PassThrough, Readable } from 'node:stream';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { HOUR } from '../src/expiry.mjs';
import { openCodeStore } from '../src/short-code-store.mjs';
import { MAX_ENVELOPE_BYTES, openStorage } from '../src/storage.mjs';

const id = 'a'.repeat(64);
const ownerHash = 'b'.repeat(64);
const initial = { id, ownerHash, version: 0, bytes: 5 };

async function fixture(t, options) {
  const directory = await mkdtemp(join(tmpdir(), 'hop-storage-test-'));
  let store = await openStorage(directory, options);
  t.after(async () => {
    await store.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    directory,
    get store() { return store; },
    async restart() {
      await store.close();
      store = await openStorage(directory, options);
    },
  };
}

function push(store, token, bytes) {
  return store.upload(token, Readable.from([Buffer.from(bytes)]));
}

async function read(record) {
  const chunks = [];
  for await (const chunk of record.stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function until(predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await predicate()) return;
    await delay(10);
  }
  assert.fail('storage did not reach the expected state');
}

test('quota includes published data, concurrent reservations, and pinned readers', async t => {
  const { store } = await fixture(t, { capacity: 12_288 });
  assert.deepEqual(store.usage(), { reserved: 0, allocated: 0 });
  assert.throws(() => store.openRead(id), { code: 'missing' });
  const { token } = store.reserve(initial);
  assert.throws(() => store.reserve({ ...initial, ownerHash: 'c'.repeat(64) }), { code: 'forbidden' });
  assert.equal((await push(store, token, 'first')).version, 1);
  const reader = store.openRead(id);
  assert.throws(() => store.reserve({ ...initial, version: 1, ownerHash: 'c'.repeat(64) }), { code: 'forbidden' });
  const make = newId => Promise.resolve().then(() => store.reserve({ ...initial, id: newId, bytes: 8192 }));
  const concurrent = await Promise.allSettled([make('d'.repeat(64)), make('e'.repeat(64))]);
  assert.deepEqual(concurrent.map(result => result.status), ['fulfilled', 'rejected']);
  assert.equal(concurrent[1].reason.code, 'full');
  assert.equal(store.cancel(concurrent[0].value.token), true);
  const replacement = store.reserve({ ...initial, version: 1, bytes: 6 });
  const stale = store.reserve({ ...initial, version: 1 });
  assert.equal((await push(store, replacement.token, 'second')).version, 2);
  await assert.rejects(push(store, stale.token, 'stale'), { code: 'conflict' });
  assert.throws(() => store.reserve({ ...initial, id: 'f'.repeat(64), bytes: 8192 }), { code: 'full' });
  const closed = once(reader.stream, 'close');
  assert.equal((await read(reader)).toString(), 'first');
  await closed;
  const canFit = store.reserve({ ...initial, id: 'f'.repeat(64), bytes: 8192 });
  assert.equal(store.cancel(canFit.token), true);
  assert.equal((await read(store.openRead(id))).toString(), 'second');
});

test('interrupted or malformed uploads free space and restart removes an orphan', async t => {
  const f = await fixture(t);
  const { token } = f.store.reserve(initial);
  await push(f.store, token, 'first');
  const before = f.store.usage();
  const short = f.store.reserve({ ...initial, version: 1 });
  await assert.rejects(push(f.store, short.token, 'tiny'), { code: 'size' });
  const long = f.store.reserve({ ...initial, version: 1 });
  await assert.rejects(push(f.store, long.token, 'longer'), { code: 'size' });
  const entry = f.store.reserve({ ...initial, version: 1, bytes: 1000 });
  const source = new PassThrough();
  const writing = assert.rejects(f.store.upload(entry.token, source), { code: 'interrupted' });
  source.write(Buffer.alloc(500));
  const partial = join(f.directory, 'blobs', entry.token);
  await until(async () => (await stat(partial).catch(() => null))?.size === 500);
  assert.equal(f.store.cancel(entry.token), true);
  await writing;
  assert.deepEqual(f.store.usage(), before);
  assert.deepEqual(await readdir(join(f.directory, 'blobs')), [token]);

  const orphan = randomUUID();
  await writeFile(join(f.directory, 'blobs', orphan), 'uncommitted');
  await assert.rejects(openStorage(f.directory), { code: 'ERR_SQLITE_ERROR' });
  await f.restart();
  assert.deepEqual(await readdir(join(f.directory, 'blobs')), [token]);
  assert.equal((await read(f.store.openRead(id))).toString(), 'first');
});

test('streams the maximum envelope, counts allocated blocks, and rejects one additional byte', async t => {
  const f = await fixture(t, { capacity: 110_000_000 });
  assert.throws(() => f.store.reserve({ ...initial, bytes: MAX_ENVELOPE_BYTES + 1 }), { code: 'size' });
  const { token } = f.store.reserve({ ...initial, bytes: MAX_ENVELOPE_BYTES });
  const chunk = Buffer.alloc(1_048_576, 0x5a);
  const expected = createHash('sha256');
  async function* generate() {
    let remaining = MAX_ENVELOPE_BYTES;
    while (remaining > 0) {
      const next = chunk.subarray(0, Math.min(remaining, chunk.length));
      expected.update(next);
      remaining -= next.length;
      yield next;
    }
  }
  await f.store.upload(token, Readable.from(generate()));
  const blocks = (await stat(join(f.directory, 'blobs', token))).blocks * 512;
  assert(f.store.usage().allocated >= blocks);
  assert.equal(f.store.usage().reserved, 0);
  const actual = createHash('sha256');
  for await (const data of f.store.openRead(id).stream) actual.update(data);
  assert.equal(actual.digest('hex'), expected.digest('hex'));
});

test('only complete current-version reads extend inactivity and absolute expiry survives restart', async t => {
  let time = 0;
  const f = await fixture(t, { now: () => time });
  const { token } = f.store.reserve({ ...initial, hasFiles: true, lifetime: 2 * HOUR });
  assert.equal((await push(f.store, token, 'first')).expiresAt, HOUR);
  // Keep a real upload timer margin while testing expiry with a fake clock.
  const margin = 1_000;
  time = HOUR - margin;
  const unopened = f.store.openRead(id);
  await assert.rejects(f.store.confirm(unopened.receipt), { code: 'conflict' });
  await read(unopened);
  const { token: next } = f.store.reserve({ ...initial, version: 1, hasFiles: true });
  assert.equal((await push(f.store, next, 'fresh')).expiresAt, HOUR);
  await assert.rejects(f.store.confirm(unopened.receipt), { code: 'missing' });
  const opened = f.store.openRead(id);
  await read(opened);
  assert.equal((await f.store.confirm(opened.receipt)).expiresAt, 2 * HOUR - margin);
  await assert.rejects(f.store.confirm(opened.receipt), { code: 'missing' });
  await f.restart();
  time = 2 * HOUR - margin - 5;
  const again = f.store.openRead(id);
  assert.equal(again.expiresAt, 2 * HOUR - margin);
  await read(again);
  assert.equal((await f.store.confirm(again.receipt)).expiresAt, 2 * HOUR);
  time = 2 * HOUR;
  assert.throws(() => f.store.openRead(id), { code: 'missing' });
  assert.deepEqual(f.store.usage(), { reserved: 0, allocated: 0 });
});

test('state directory, databases and the lock journal are readable only by the owner', async t => {
  const f = await fixture(t);
  const mode = async name => (await stat(join(f.directory, name))).mode & 0o777;
  assert.equal(await mode('.'), 0o700);
  assert.equal(await mode('blobs'), 0o700);
  for (const name of ['owner.sqlite', 'records.sqlite', 'exchange.sqlite', 'owner.sqlite-journal']) {
    assert.equal(await mode(name), 0o600, name);
  }
  await f.store.close();
  await chmod(join(f.directory, 'records.sqlite'), 0o644);
  await chmod(f.directory, 0o755);
  await f.restart();
  assert.equal(await mode('.'), 0o700);
  assert.equal(await mode('records.sqlite'), 0o600);
  const codes = openCodeStore(f.directory, () => ({ absoluteDeadline: 1 }));
  t.after(() => codes.close());
  assert.equal(await mode('short-code.sqlite'), 0o600);
  assert.equal(await mode('short-code-keys.sqlite'), 0o600);
});

test('expired data is cleaned from disk while storage is idle', async t => {
  let time = 0;
  const f = await fixture(t, { now: () => time, sweepInterval: 10 });
  const { token } = f.store.reserve({ ...initial, lifetime: 100 });
  await push(f.store, token, 'first');
  time = 100;
  const blobs = join(f.directory, 'blobs');
  await until(async () => (await readdir(blobs)).length === 0);
});
