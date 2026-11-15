import { constants, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { closeSync, openSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { hex, integer, modpow, PERIOD, RSA_BYTES } from './short-code-crypto.mjs';

const HIT = /^[a-f0-9]{64}$/;
const WRAPPER = /^[a-f0-9]{184}$/;
const BLIND = /^[a-f0-9]{768}$/;
const WINDOW = 60_000;
const valid = (pattern, value) => typeof value === 'string' && pattern.test(value);

export class CodeError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function openCodeStore(directory, authorize, { now = Date.now, perSource = 30, total = 1800 } = {}) {
  if (![perSource, total].every(value => Number.isSafeInteger(value) && value > 0)) throw new CodeError('invalid');
  const file = join(directory, 'short-code.sqlite');
  closeSync(openSync(file, 'a', 0o600));
  const db = new DatabaseSync(file);
  let secrets;
  try {
    const keyFile = join(directory, 'short-code-keys.sqlite');
    closeSync(openSync(keyFile, 'a', 0o600));
    secrets = new DatabaseSync(keyFile);
    secrets.exec(`PRAGMA secure_delete=ON;
      CREATE TABLE IF NOT EXISTS keys (epoch INTEGER PRIMARY KEY, material BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS settings (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), secret BLOB NOT NULL);
      INSERT OR IGNORE INTO settings VALUES (1, randomblob(32))`);
    db.exec(`CREATE TABLE IF NOT EXISTS codes (lookup TEXT PRIMARY KEY, id TEXT UNIQUE NOT NULL,
        epoch INTEGER NOT NULL, wrapper TEXT NOT NULL, deadline INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS codes_by_deadline ON codes(deadline);
      CREATE TABLE IF NOT EXISTS counters (bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, uses INTEGER NOT NULL)`);
    const limiterSecret = secrets.prepare('SELECT secret FROM settings WHERE singleton = 1').get().secret;
    const getKey = secrets.prepare('SELECT material FROM keys WHERE epoch = ?');
    const putKey = secrets.prepare('INSERT INTO keys VALUES (?, ?)');
    const cleanKeys = secrets.prepare('DELETE FROM keys WHERE epoch < ?');
    const cleanCodes = db.prepare('DELETE FROM codes WHERE deadline <= ?');
    const cleanCounters = db.prepare('DELETE FROM counters WHERE window < ?');
    const find = db.prepare('SELECT * FROM codes WHERE lookup = ?');
    const forRecord = db.prepare('SELECT lookup, epoch FROM codes WHERE id = ?');
    const put = db.prepare('INSERT INTO codes VALUES (?, ?, ?, ?, ?)');
    const getCount = db.prepare('SELECT uses FROM counters WHERE bucket = ? AND window = ?');
    const use = db.prepare(`INSERT INTO counters VALUES (?, ?, 1) ON CONFLICT(bucket) DO UPDATE
      SET uses = CASE WHEN window = excluded.window THEN uses + 1 ELSE 1 END, window = excluded.window`);
    const cache = new Map();
    const epochAt = () => Math.floor(now() / PERIOD);

    function sweep() {
      const time = now();
      const previous = Math.floor(time / PERIOD) - 1;
      cleanKeys.run(previous);
      cleanCodes.run(time);
      cleanCounters.run(Math.floor(time / WINDOW));
      for (const epoch of cache.keys()) if (epoch < previous) cache.delete(epoch);
    }

    function get(epoch, create = false) {
      if (cache.has(epoch)) return cache.get(epoch);
      let row = getKey.get(epoch);
      if (!row && create) {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: RSA_BYTES * 8, publicExponent: 65537 });
        row = { material: privateKey.export({ format: 'der', type: 'pkcs8' }) };
        putKey.run(epoch, row.material);
      }
      if (!row) return null;
      const privateKey = createPrivateKey({ key: row.material, format: 'der', type: 'pkcs8' });
      const key = createPublicKey(privateKey).export({ format: 'jwk' });
      const modulus = integer(Buffer.from(key.n, 'base64url'));
      const config = { epoch, key, privateKey, modulus };
      cache.set(epoch, config);
      return config;
    }

    function limit(address) {
      const window = Math.floor(now() / WINDOW);
      const source = createHmac('sha256', limiterSecret).update(address).digest('hex');
      db.exec('BEGIN IMMEDIATE');
      try {
        if ((getCount.get('total', window)?.uses ?? 0) >= total ||
            (getCount.get(source, window)?.uses ?? 0) >= perSource) throw new CodeError('limited');
        use.run(source, window);
        use.run('total', window);
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    }

    function configs() {
      const epoch = epochAt();
      return [get(epoch, true), get(epoch - 1)].filter(Boolean).map(({ epoch, key }) => ({ epoch, key }));
    }

    function evaluate(address, { epoch, blinded } = {}) {
      if (!Number.isSafeInteger(epoch) || !valid(BLIND, blinded)) throw new CodeError('invalid');
      limit(address);
      const current = epochAt();
      const config = epoch === current || epoch === current - 1 ? get(epoch) : null;
      if (!config) throw new CodeError('missing');
      const request = Buffer.from(blinded, 'hex');
      const input = integer(request);
      if (input < 1n || input >= config.modulus) throw new CodeError('invalid');
      const signed = privateDecrypt({ key: config.privateKey, padding: constants.RSA_NO_PADDING }, request);
      if (modpow(integer(signed), 65537n, config.modulus) !== input) throw Error('Invalid RSA result');
      return { signed: hex(signed) };
    }

    function validateEpoch(epoch) {
      if (!Number.isSafeInteger(epoch)) throw new CodeError('invalid');
      const current = epochAt();
      if ((epoch !== current && epoch !== current - 1) || !get(epoch)) throw new CodeError('missing');
    }

    function register(id, owner, { epoch, lookup, wrapper } = {}) {
      if (!valid(HIT, lookup) || !valid(WRAPPER, wrapper)) throw new CodeError('invalid');
      sweep();
      const deadline = authorize(id, owner).absoluteDeadline;
      validateEpoch(epoch);
      const previous = forRecord.get(id);
      if (previous?.lookup === lookup && previous.epoch === epoch) return;
      if (previous) throw new CodeError('registered');
      if (find.get(lookup)) throw new CodeError('conflict');
      put.run(lookup, id, epoch, wrapper, Math.min(deadline, (epoch + 2) * PERIOD));
    }

    function read(lookup) {
      const entry = find.get(lookup);
      if (!entry || entry.deadline <= now()) throw new CodeError('missing');
      authorize(entry.id);
      return { wrapper: entry.wrapper };
    }

    return {
      configs, evaluate, register, read, sweep, validateEpoch,
      hasCode(lookup) { return valid(HIT, lookup) && (find.get(lookup)?.deadline ?? 0) > now(); },
      close() { db.close(); secrets.close(); },
    };
  } catch (error) {
    secrets?.close();
    db.close();
    throw error;
  }
}
