import { createPublicKey, randomUUID, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, closeSync, fstatSync, fsyncSync, mkdirSync,
  openSync, readdirSync, statSync, statfsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { openExchangeAccess } from './exchange-access.mjs';
import { DAY, confirmActivity, expiresAt, isExpired } from './expiry.mjs';

// HOP1 header + maximum manifest + attachments + HOPG header and tag.
export const MAX_ENVELOPE_BYTES = 8 + 6_311_936 + 100_000_000 + 32;
const ID = /^[a-f0-9]{64}$/;
const BLOB = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const hexId = value => typeof value === 'string' && ID.test(value);
const memberId = value => value === 'owner' || typeof value === 'string' && BLOB.test(value);
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const sameOwner = (first, second) => timingSafeEqual(Buffer.from(first, 'hex'), Buffer.from(second, 'hex'));

export class StorageError extends Error {
  constructor(code, options) {
    super(code, options);
    this.name = 'StorageError';
    this.code = code;
  }
}

export async function openStorage(directory, {
  capacity = 3_000_000_000, now = Date.now, lease = 30_000, diskHeadroom = 1_048_576, sweepInterval = 30_000,
} = {}) {
  if (!integer(capacity, 1, Number.MAX_SAFE_INTEGER) || !integer(lease, 1, 2_147_483_647) ||
      !integer(diskHeadroom, 0, Number.MAX_SAFE_INTEGER) || !integer(sweepInterval, 1, 2_147_483_647) ||
      typeof now !== 'function') {
    throw new StorageError('invalid');
  }
  const blobs = join(directory, 'blobs');
  mkdirSync(blobs, { recursive: true, mode: 0o700 });
  const ownerLock = new DatabaseSync(join(directory, 'owner.sqlite'));
  let db;
  let rights;
  try {
    ownerLock.exec('PRAGMA busy_timeout=0; BEGIN EXCLUSIVE');
    db = new DatabaseSync(join(directory, 'records.sqlite'));
    rights = openExchangeAccess(db, join(directory, 'exchange.sqlite'));
    db.exec(`PRAGMA main.journal_mode=DELETE;
      PRAGMA main.synchronous=FULL;
      CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY, version INTEGER NOT NULL, blob TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL, ownerHash TEXT NOT NULL,
        createdAt INTEGER NOT NULL, absoluteDeadline INTEGER NOT NULL,
        lastActivityAt INTEGER NOT NULL, protected INTEGER NOT NULL, hasFiles INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS read_locators (
        locator TEXT PRIMARY KEY, id TEXT NOT NULL, current INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS read_locators_by_id ON read_locators(id);
      CREATE UNIQUE INDEX IF NOT EXISTS read_locators_current ON read_locators(id) WHERE current=1;
      CREATE TABLE IF NOT EXISTS rotation_keys (
        id TEXT NOT NULL, member TEXT NOT NULL, publicKey TEXT NOT NULL,
        PRIMARY KEY (id, member)
      );
      CREATE TABLE IF NOT EXISTS rotation_recoveries (
        id TEXT NOT NULL, member TEXT NOT NULL, wrapper TEXT NOT NULL,
        PRIMARY KEY (id, member)
      )`);
  } catch (error) {
    db?.close();
    ownerLock.close();
    throw error;
  }

  const records = db.prepare('SELECT * FROM records');
  const find = db.prepare('SELECT * FROM records WHERE id = ?');
  const remove = db.prepare('DELETE FROM records WHERE id = ?');
  const touch = db.prepare('UPDATE records SET lastActivityAt = ? WHERE id = ?');
  const publish = db.prepare(`INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET version=excluded.version, blob=excluded.blob,
    size=excluded.size, hasFiles=excluded.hasFiles`);
  const findLocator = db.prepare('SELECT id, current FROM read_locators WHERE locator=?');
  const currentLocator = db.prepare('SELECT locator FROM read_locators WHERE id=? AND current=1');
  const rotations = db.prepare('SELECT count(*) AS count FROM read_locators WHERE id=?');
  const addLocator = db.prepare('INSERT INTO read_locators VALUES (?, ?, 1)');
  const retireLocator = db.prepare('UPDATE read_locators SET current=0 WHERE id=? AND current=1');
  const clearLocators = db.prepare('DELETE FROM read_locators WHERE id=?');
  const getKey = db.prepare('SELECT publicKey FROM rotation_keys WHERE id=? AND member=?');
  const putKey = db.prepare('INSERT INTO rotation_keys VALUES (?, ?, ?)');
  const clearKeys = db.prepare('DELETE FROM rotation_keys WHERE id=?');
  const clearKey = db.prepare('DELETE FROM rotation_keys WHERE id=? AND member=?');
  const getRecovery = db.prepare('SELECT wrapper FROM rotation_recoveries WHERE id=? AND member=?');
  const putRecovery = db.prepare('INSERT INTO rotation_recoveries VALUES (?, ?, ?)');
  const clearRecoveries = db.prepare('DELETE FROM rotation_recoveries WHERE id=?');
  const clearRecovery = db.prepare('DELETE FROM rotation_recoveries WHERE id=? AND member=?');
  const block = statfsSync(blobs).bsize;
  const round = bytes => Math.ceil(bytes / block) * block;
  const reservations = new Map();
  const readers = new Map();
  const receipts = new Map();
  const transfers = new Set();
  let closing;

  function transaction(apply) {
    db.exec('BEGIN IMMEDIATE');
    try {
      apply();
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  function locatorFor(id) {
    return currentLocator.get(id)?.locator ?? id;
  }

  function contentVersion(id, version) {
    return version - rotations.get(id).count;
  }

  function recordAt(locator) {
    const mapped = findLocator.get(locator);
    if (mapped) return mapped.current ? find.get(mapped.id) : undefined;
    const row = find.get(locator);
    return row && locatorFor(row.id) === locator ? row : undefined;
  }

  function checkNewLocator(locator) {
    if (find.get(locator) || findLocator.get(locator) ||
        [...reservations.values()].some(entry => entry.id === locator)) throw new StorageError('conflict');
  }

  function sweep(timestamp = now()) {
    if (closing) throw new StorageError('interrupted');
    clean(timestamp);
  }

  function clean(timestamp) {
    const keep = new Set(readers.keys());
    for (const row of records.all()) {
      if (isExpired(row, timestamp)) {
        transaction(() => {
          rights.clear(row.id);
          clearLocators.run(row.id);
          clearKeys.run(row.id);
          clearRecoveries.run(row.id);
          remove.run(row.id);
        });
      }
      else keep.add(row.blob);
    }
    for (const [token, entry] of reservations) {
      if (entry.deadline <= timestamp || isExpired(entry.state, timestamp)) {
        if (entry.controller) entry.controller.abort();
        else reservations.delete(token);
      }
      if (reservations.has(token)) keep.add(token);
    }
    for (const [token, receipt] of receipts) if (receipt.deadline <= timestamp) receipts.delete(token);
    for (const name of readdirSync(blobs)) {
      if (BLOB.test(name) && !keep.has(name)) unlinkSync(join(blobs, name));
    }
  }

  function backgroundCleanup() {
    try { clean(now()); } catch {
      // Retry on the next tick. Synchronous operations run their own sweep
      // and surface filesystem errors before admitting further work.
    }
  }

  function measure() {
    let allocated = 0;
    let reserved = 0;
    let reservedOnDisk = 0;
    for (const entry of reservations.values()) reserved += round(entry.bytes);
    for (const name of readdirSync(blobs)) {
      if (!BLOB.test(name)) continue;
      const stat = statSync(join(blobs, name));
      const disk = stat.blocks * 512;
      const entry = reservations.get(name);
      if (entry) {
        reservedOnDisk += Math.min(round(entry.bytes), disk);
        reserved += Math.max(0, disk - round(entry.bytes));
      } else {
        allocated += Math.max(round(stat.size), disk);
      }
    }
    return { allocated, reserved, outstanding: reserved - reservedOnDisk };
  }

  function reserve({ id, locator = id, rotation, version, bytes, ownerHash, hasFiles = false,
    protected: guarded = false, lifetime = DAY } = {}) {
    if (!hexId(id) || !hexId(locator) || !hexId(ownerHash) || !integer(version, 0, Number.MAX_SAFE_INTEGER - 1) ||
        typeof hasFiles !== 'boolean' || typeof guarded !== 'boolean' || !integer(lifetime, 1, DAY)) {
      throw new StorageError('invalid');
    }
    if (!integer(bytes, 1, MAX_ENVELOPE_BYTES)) throw new StorageError('size');
    const timestamp = now();
    sweep(timestamp);
    const row = find.get(id);
    if (row) checkWrite(row, ownerHash);
    if (locator !== locatorFor(id) || (!row && findLocator.get(id))) throw new StorageError('conflict');
    if ((row?.version ?? 0) !== version) throw new StorageError('conflict');
    let accessChange;
    if (rotation !== undefined) {
      if (!row || !sameOwner(row.ownerHash, ownerHash)) throw new StorageError('forbidden');
      accessChange = parseRotation(rotation);
      checkRotation(id, accessChange);
    }
    if (!row && [...reservations.values()].some(entry => entry.id === id && !sameOwner(entry.ownerHash, ownerHash))) {
      throw new StorageError('forbidden');
    }
    const state = row ? { ...row, hasFiles } : {
      createdAt: timestamp, absoluteDeadline: timestamp + lifetime, lastActivityAt: timestamp, protected: guarded, hasFiles,
    };
    if (isExpired(state, timestamp)) throw new StorageError('expired');
    const { allocated, reserved, outstanding } = measure();
    const disk = statfsSync(blobs);
    if (round(bytes) > capacity - allocated - reserved ||
        round(bytes) > disk.bavail * disk.bsize - outstanding - diskHeadroom) throw new StorageError('full');
    const token = randomUUID();
    const deadline = Math.min(timestamp + lease, expiresAt(state));
    reservations.set(token, { id, locator, accessChange, version, bytes, ownerHash, state, deadline, previous: row?.blob });
    return { token, bytes };
  }

  async function write(token, entry, readable) {
    const path = join(blobs, token);
    let bytes = 0;
    const bounded = new Transform({ transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > entry.bytes) callback(new StorageError('size'));
      else callback(null, chunk);
    } });
    const timer = setTimeout(() => entry.controller.abort(), entry.deadline - now());
    timer.unref();
    try {
      await pipeline(readable, bounded, createWriteStream(path, { flags: 'wx', mode: 0o600, flush: true }), {
        signal: entry.controller.signal,
      });
      if (bytes !== entry.bytes) throw new StorageError('size');
      if (now() >= entry.deadline) throw new StorageError('expired');
      const timestamp = now();
      sweep(timestamp);
      const row = find.get(entry.id);
      if (row?.blob !== entry.previous || (row?.version ?? 0) !== entry.version) throw new StorageError('conflict');
      if (row) checkWrite(row, entry.ownerHash);
      if (locatorFor(entry.id) !== entry.locator || (!row && findLocator.get(entry.id))) throw new StorageError('conflict');
      const state = row ? { ...row, hasFiles: entry.state.hasFiles } : entry.state;
      if (isExpired(state, timestamp)) throw new StorageError('expired');
      if (statSync(path).blocks * 512 > round(entry.bytes)) throw new StorageError('full');
      const directoryFd = openSync(blobs, 'r');
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      const version = entry.version + 1;
      const publishRecord = () => publish.run(entry.id, version, token, bytes, entry.ownerHash, state.createdAt,
        state.absoluteDeadline, state.lastActivityAt, Number(state.protected), Number(state.hasFiles));
      if (entry.accessChange) {
        transaction(() => {
          commitRotation(entry.id, entry.accessChange);
          publishRecord();
        });
      } else publishRecord();
      const content = contentVersion(entry.id, version);
      return { version, expiresAt: expiresAt(state), ...(content !== version && { contentVersion: content }),
        ...(entry.accessChange && { locator: entry.accessChange.locator }) };
    } catch (error) {
      if (error instanceof StorageError) throw error;
      if (error.code === 'ENOSPC' || error.code === 'EDQUOT') throw new StorageError('full', { cause: error });
      if (error.code === 'ABORT_ERR' || error.code === 'ERR_STREAM_PREMATURE_CLOSE') {
        throw new StorageError(now() >= entry.deadline ? 'expired' : 'interrupted', { cause: error });
      }
      throw error;
    } finally {
      clearTimeout(timer);
      reservations.delete(token);
      backgroundCleanup();
    }
  }

  function upload(token, readable, declaredBytes) {
    sweep();
    const entry = reservations.get(token);
    if (!entry) throw new StorageError('missing');
    if (entry.controller) throw new StorageError('conflict');
    if (declaredBytes !== undefined && declaredBytes !== entry.bytes) throw new StorageError('size');
    entry.controller = new AbortController();
    const task = write(token, entry, readable);
    transfer(task);
    return task;
  }

  function transfer(task) {
    transfers.add(task);
    const done = () => transfers.delete(task);
    task.then(done, done);
  }

  function openRead(locator) {
    if (!hexId(locator)) throw new StorageError('invalid');
    const timestamp = now();
    sweep(timestamp);
    const row = recordAt(locator);
    if (!row) throw new StorageError('missing');
    const path = join(blobs, row.blob);
    const fd = openSync(path, 'r');
    try {
      if (fstatSync(fd).size !== row.size) throw new StorageError('interrupted');
    } catch (error) {
      closeSync(fd);
      throw error;
    }
    const stream = createReadStream(path, { fd });
    const held = readers.get(row.blob) ?? new Set();
    readers.set(row.blob, held);
    held.add(stream);
    const token = receipts.size < 4096 ? randomUUID() : null;
    let finish;
    const finished = new Promise(resolve => { finish = resolve; });
    const receipt = { id: row.id, version: row.version, blob: row.blob, complete: false, deadline: expiresAt(row), finished };
    if (token) receipts.set(token, receipt);
    stream.once('end', () => {
      receipt.complete = true;
      receipt.deadline = Math.min(receipt.deadline, now() + lease);
    });
    // Consumers handle errors on the stream; the close callback still releases disk accounting.
    stream.on('error', () => {});
    stream.once('close', () => {
      held.delete(stream);
      if (held.size === 0) readers.delete(row.blob);
      if (!receipt.complete) receipts.delete(token);
      backgroundCleanup();
      finish();
    });
    transfer(finished);
    return { stream, size: row.size, version: row.version, contentVersion: contentVersion(row.id, row.version),
      expiresAt: expiresAt(row), receipt: token };
  }

  async function confirm(token) {
    sweep();
    const receipt = receipts.get(token);
    if (!receipt) throw new StorageError('missing');
    // End marks file exhaustion synchronously. The network consumer may deliver
    // its request before the file descriptor's asynchronous close callback.
    if (!receipt.complete) throw new StorageError('conflict');
    await receipt.finished;
    const timestamp = now();
    sweep(timestamp);
    if (receipts.get(token) !== receipt) throw new StorageError('missing');
    receipts.delete(token);
    const row = find.get(receipt.id);
    if (!row || row.version !== receipt.version || row.blob !== receipt.blob) throw new StorageError('missing');
    const state = confirmActivity(row, timestamp);
    if (!state) throw new StorageError('expired');
    touch.run(state.lastActivityAt, row.id);
    return { expiresAt: expiresAt(state) };
  }

  function cancel(token) {
    sweep();
    const entry = reservations.get(token);
    if (!entry) return false;
    if (entry.controller) entry.controller.abort();
    else reservations.delete(token);
    return true;
  }

  function checkWrite(row, fingerprint) {
    if (sameOwner(row.ownerHash, fingerprint)) return;
    if (!rights.enabled(row.id) || !rights.find(row.id, fingerprint)) throw new StorageError('forbidden');
  }

  function normalizedKey(key) {
    if (key?.kty !== 'EC' || key.crv !== 'P-256' || Object.hasOwn(key, 'd') ||
        ![key.x, key.y].every(v => typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v))) {
      throw new StorageError('invalid');
    }
    const publicKey = { kty: 'EC', crv: 'P-256', x: key.x, y: key.y };
    try { createPublicKey({ key: publicKey, format: 'jwk' }); }
    catch { throw new StorageError('invalid'); }
    return JSON.stringify(publicKey);
  }

  function enrollKey(id, member, key) {
    const existing = getKey.get(id, member);
    if (existing && existing.publicKey !== key) throw new StorageError('conflict');
    if (!existing) putKey.run(id, member, key);
  }

  function parseRotation(rotation) {
    if (!hexId(rotation?.locator) || !memberId(rotation.member) || rotation.member === 'owner' ||
        !Array.isArray(rotation.recovery) || rotation.recovery.length > 7) throw new StorageError('invalid');
    const recovery = new Map();
    for (const entry of rotation.recovery) {
      if (!memberId(entry?.member) || typeof entry.wrapper !== 'string' || !entry.wrapper ||
          Buffer.byteLength(entry.wrapper) > 4096 || recovery.has(entry.member)) throw new StorageError('invalid');
      recovery.set(entry.member, entry.wrapper);
    }
    return { locator: rotation.locator, member: rotation.member, recovery };
  }

  function checkRotation(id, rotation) {
    checkNewLocator(rotation.locator);
    const others = ['owner'];
    let found = false;
    for (const member of rights.list(id)) {
      if (member.id === rotation.member) found = true;
      else others.push(member.id);
    }
    if (!found || rotation.recovery.size !== others.length ||
        others.some(member => !getKey.get(id, member) || !rotation.recovery.has(member))) {
      throw new StorageError('conflict');
    }
  }

  function commitRotation(id, rotation) {
    checkRotation(id, rotation);
    rights.revoke(id, rotation.member);
    rights.clearInvitations(id);
    clearKey.run(id, rotation.member);
    clearRecoveries.run(id);
    for (const [member, wrapper] of rotation.recovery) putRecovery.run(id, member, wrapper);
    retireLocator.run(id);
    addLocator.run(rotation.locator, id);
  }

  function exchange(id, fingerprint, action = 'status', value, locator = id) {
    if (!hexId(id) || !hexId(fingerprint)) throw new StorageError('invalid');
    const time = now();
    sweep(time);
    const row = find.get(id);
    if (!row) throw new StorageError('missing');
    const owner = sameOwner(row.ownerHash, fingerprint);
    const grant = owner ? null : rights.find(id, fingerprint);
    if (!owner && !grant) throw new StorageError('forbidden');
    if (action !== 'status' && action !== 'member-key' && !owner) throw new StorageError('forbidden');
    const member = owner ? 'owner' : grant.member;
    if (action === 'mode') {
      if (value !== 'read' && value !== 'exchange') throw new StorageError('invalid');
      rights.update(id, value === 'exchange');
    } else if (action === 'revoke-write') {
      if (typeof value !== 'string' || !BLOB.test(value)) throw new StorageError('invalid');
      transaction(() => {
        if (!rights.revoke(id, value)) throw new StorageError('missing');
        clearKey.run(id, value);
        clearRecovery.run(id, value);
      });
    } else if (action === 'invite' || action === 'one-use') {
      if (!hexId(value) || sameOwner(row.ownerHash, value)) throw new StorageError('invalid');
      if (locatorFor(id) !== locator) throw new StorageError('conflict');
      if (rights.find(id, value)) return {};
      if (rights.list(id).length + rights.pending(id) >= 7) throw new StorageError('full');
      if (action === 'invite') rights.add(id, value);
      else rights.invite(id, value);
      return {};
    } else if (action === 'member-key') {
      enrollKey(id, member, normalizedKey(value));
    }
    if (grant) rights.seen(id, grant.member, time);
    const enabled = rights.enabled(id);
    const recovery = getRecovery.get(id, member)?.wrapper;
    const ownerKey = owner && getKey.get(id, 'owner')?.publicKey;
    return {
      mode: enabled ? 'exchange' : 'read', version: row.version, expiresAt: expiresAt(row),
      canWrite: owner || enabled, locator: locatorFor(id),
      ...(recovery && { recovery }), ...(ownerKey && { ownerKey: JSON.parse(ownerKey) }),
      ...(owner && { members: rights.list(id).map(({ id: memberId, seenAt }) => ({
        id: memberId, present: seenAt !== null && seenAt > time - 60_000,
        key: JSON.parse(getKey.get(id, memberId)?.publicKey ?? 'null') ?? undefined,
      })) }),
    };
  }

  function claimWriter(id, invitationHash, deviceHash, locator = id, key) {
    if (![id, invitationHash, deviceHash].every(hexId) || invitationHash === deviceHash) throw new StorageError('invalid');
    sweep();
    const row = find.get(id);
    if (!row) throw new StorageError('missing');
    if (locatorFor(id) !== locator) throw new StorageError('forbidden');
    if (sameOwner(row.ownerHash, deviceHash)) throw new StorageError('forbidden');
    const normalized = key === undefined ? undefined : normalizedKey(key);
    transaction(() => {
      const member = rights.claim(id, invitationHash, deviceHash);
      if (!member) throw new StorageError('forbidden');
      if (normalized) enrollKey(id, member, normalized);
    });
  }

  try { clean(now()); } catch (error) {
    db.close();
    ownerLock.close();
    throw error;
  }
  const timer = setInterval(backgroundCleanup, sweepInterval);
  timer.unref();
  return {
    reserve, upload, openRead, confirm, cancel, exchange, claimWriter,
    codeRecord(locator, ownerHash) {
      if (!hexId(locator) || (ownerHash !== undefined && !hexId(ownerHash))) throw new StorageError('invalid');
      const row = recordAt(locator);
      if (!row || isExpired(row, now())) throw new StorageError('missing');
      if (ownerHash !== undefined && !sameOwner(row.ownerHash, ownerHash)) throw new StorageError('forbidden');
      return { absoluteDeadline: row.absoluteDeadline };
    },
    usage() {
      sweep();
      const { allocated, reserved } = measure();
      return { allocated, reserved };
    },
    close() {
      closing ??= (async () => {
        clearInterval(timer);
        for (const entry of reservations.values()) entry.controller?.abort();
        for (const group of readers.values()) for (const stream of group) stream.destroy();
        await Promise.allSettled(transfers);
        db.close();
        ownerLock.close();
      })();
      return closing;
    },
  };
}
