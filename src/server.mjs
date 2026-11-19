import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { openStorage, StorageError, MAX_ENVELOPE_BYTES } from './storage.mjs';
import { createPairing, PairingError } from './pairing.mjs';
import { CodeError, openCodeStore } from './short-code-store.mjs';
import { AdmissionError, clientAddress, createAdmission } from './admission.mjs';

const STATIC = new Map([
  ['/', ['../web/index.html', 'text/html; charset=utf-8']],
  ['/version.json', ['../web/version.json', 'application/json']],
  ['/style.css', ['../web/style.css', 'text/css']],
  ['/app.mjs', ['../web/app.mjs', 'text/javascript']],
  ['/pair.mjs', ['../web/pair.mjs', 'text/javascript']],
  ['/qr.mjs', ['../web/qr.mjs', 'text/javascript']],
  ...['publication', 'envelope', 'container', 'editor-state', 'direct-revision', 'local-channel',
    'pairing-client', 'short-code', 'short-code-crypto', 'rotation-client'].map(name => ['/src/' + name + '.mjs', [name + '.mjs', 'text/javascript']]),
  ...['400', '700'].map(weight => ['/fonts/pt-serif-' + weight + '.woff2', ['../web/fonts/pt-serif-' + weight + '.woff2', 'font/woff2']]),
  ['/typography.css', ['../web/typography.css', 'text/css']],
]);
const statuses = { invalid: 400, missing: 404, conflict: 409, size: 413, full: 507, forbidden: 403,
  expired: 404, interrupted: 400, limited: 429, registered: 409 };

async function jsonBody(req, limit = 4096) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > limit) throw new StorageError('size');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks)); }
  catch { throw new StorageError('invalid'); }
}

export async function startServer(directory, {
  host = '127.0.0.1', port = 0, codeLimits, basePath = '', publicOrigin, trustLoopbackProxy = false,
  admissionLimits, offerLifetime = 300_000, maxOffers = 1024, ...storageOptions
} = {}) {
  if (!/^(?:\/[a-zA-Z0-9_-]+)*$/.test(basePath)) throw new Error('Invalid base path');
  if (trustLoopbackProxy && host !== '127.0.0.1' && host !== '::1') throw new Error('Trusted proxy requires loopback');
  if (publicOrigin !== undefined) {
    const url = new URL(publicOrigin);
    if (url.origin !== publicOrigin || !['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid public origin');
  }
  const storage = await openStorage(directory, storageOptions);
  let codes;
  try { codes = openCodeStore(directory, storage.codeRecord, { ...codeLimits, now: storageOptions.now }); }
  catch (error) { await storage.close(); throw error; }
  let pairing;
  let admission;
  try {
    pairing = createPairing({ now: storageOptions.now, offerLifetime, maxOffers });
    admission = createAdmission({
      now: storageOptions.now, lease: storageOptions.lease ?? 30_000, offerLifetime, ...admissionLimits,
    });
  } catch (error) {
    codes.close();
    await storage.close();
    throw error;
  }
  const codeCleanup = setInterval(() => {
    try { codes.sweep(); } catch { /* Retry on the next cleanup or request. */ }
    try { admission.sweep(); } catch { /* Retry on the next cleanup or request. */ }
  }, storageOptions.sweepInterval ?? 30_000);
  codeCleanup.unref();
  const handlers = new Set();
  async function handle(req, res) {
    const mounted = req.url?.startsWith(basePath + '/');
    const path = mounted ? req.url.slice(basePath.length) : '';
    const method = req.method;
    const headers = {
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; img-src 'self' blob:; script-src 'self'",
    };
    const json = (status, value, extraHeaders) => {
      if (res.destroyed || res.headersSent) return;
      res.writeHead(status, { ...headers, 'content-type': 'application/json', ...extraHeaders });
      res.end(JSON.stringify(value));
    };
    try {
      if (basePath && method === 'GET' && req.url === basePath) {
        res.writeHead(308, { ...headers, location: basePath + '/' });
        res.end();
        return;
      }
      if (method === 'GET' && STATIC.has(path)) {
        const [file, type] = STATIC.get(path);
        const contents = await readFile(new URL(file.startsWith('../') ? file : './' + file, import.meta.url));
        res.writeHead(200, { ...headers, 'content-type': type });
        res.end(contents);
        return;
      }
      const bearer = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization ?? '')?.[1];
      if (method === 'GET' && path === '/api/v1/short-code/keys') return json(200, codes.configs());
      if (method === 'POST' && path === '/api/v1/short-code/evaluate') {
        if (req.headers['sec-fetch-site'] === 'cross-site' ||
            !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) {
          return json(403, { error: 'forbidden' });
        }
        const address = clientAddress(req, trustLoopbackProxy);
        if (address === null) return json(403, { error: 'forbidden' });
        return json(200, codes.evaluate(address, (await jsonBody(req)) ?? {}));
      }
      const codePath = /^\/api\/v1\/short-code\/([a-f0-9]{64})$/.exec(path)?.[1];
      if (codePath && method === 'GET') {
        const wrapper = pairing.readCode(codePath);
        return json(200, wrapper ? { wrapper, kind: 'pair' } : codes.read(codePath));
      }
      if (codePath && method === 'POST') {
        if (!bearer) return json(403, { error: 'forbidden' });
        const owner = createHash('sha256').update(bearer).digest('hex');
        const body = (await jsonBody(req)) ?? {};
        if (pairing.readCode(body.lookup)) throw new CodeError('conflict');
        codes.register(codePath, owner, body);
        return json(201, {});
      }
      const settings = /^\/api\/v1\/exchange\/([a-f0-9]{64})(?:\/(mode|invite|one-use|claim|share|claim-shared|revoke-write|member-key))?$/.exec(path);
      if (settings && ((method === 'GET' && !settings[2]) || (method === 'POST' && settings[2]))) {
        if (!bearer) return json(403, { error: 'forbidden' });
        const fingerprint = createHash('sha256').update(bearer).digest('hex');
        if (method === 'GET') return json(200, storage.exchange(settings[1], fingerprint));
        const body = await jsonBody(req);
        if (settings[2] === 'claim') {
          storage.claimWriter(settings[1], fingerprint, body?.fingerprint, body?.locator, body?.key);
          return json(200, {});
        }
        if (settings[2] === 'claim-shared') {
          return json(200, storage.claimShared(settings[1], fingerprint, body?.fingerprint, body?.key));
        }
        const inputField = { mode: 'mode', 'revoke-write': 'member', 'member-key': 'key' }[settings[2]] ?? 'fingerprint';
        return json(200, storage.exchange(settings[1], fingerprint, settings[2], body?.[inputField], body?.locator, body?.generation));
      }
      if (method === 'POST' && path === '/api/v1/reservations') {
        if (!bearer) return json(403, { error: 'forbidden' });
        const address = clientAddress(req, trustLoopbackProxy);
        if (address === null) return json(403, { error: 'forbidden' });
        const ownerHash = createHash('sha256').update(bearer).digest('hex');
        const body = await jsonBody(req, 40_000);
        if (!body || !Number.isSafeInteger(body.bytes) || body.bytes < 32) throw new StorageError('invalid');
        if (body.bytes > MAX_ENVELOPE_BYTES) throw new StorageError('size');
        const hold = admission.claimReserve(address, body.bytes);
        let created;
        try {
          const { id, locator, rotation, version, bytes, hasFiles, protected: guarded, lifetime } = body;
          created = storage.reserve({ id, locator, rotation, version, bytes, ownerHash, hasFiles, protected: guarded, lifetime });
        } catch (error) {
          admission.cancelReserve(hold);
          throw error;
        }
        admission.commitReserve(hold, created.token);
        return json(201, created);
      }
      const upload = /^\/api\/v1\/uploads\/([a-f0-9-]{36})$/.exec(path);
      if (upload && method === 'PUT') {
        const declared = req.headers['content-length'];
        if (declared === undefined) return json(411, { error: 'length-required' });
        const result = await storage.upload(upload[1], req, Number(declared));
        admission.releaseReserve(upload[1]);
        return json(201, result);
      }
      if (upload && method === 'DELETE') {
        admission.releaseReserve(upload[1]);
        storage.cancel(upload[1]);
        return json(200, {});
      }
      const record = /^\/api\/v1\/records\/([a-f0-9]{64})$/.exec(path);
      if (record && method === 'GET') {
        const result = storage.openRead(record[1]);
        res.writeHead(200, {
          ...headers, 'content-type': 'application/octet-stream', 'content-length': result.size,
          'x-hop-version': result.version, 'x-hop-expires-at': result.expiresAt,
          ...(result.contentVersion !== result.version && { 'x-hop-content-version': result.contentVersion }),
          ...(result.receipt && { 'x-hop-receipt': result.receipt }),
        });
        await pipeline(result.stream, res);
        return;
      }
      const receipt = /^\/api\/v1\/receipts\/([a-f0-9-]{36})$/.exec(path);
      if (receipt && method === 'POST') return json(200, await storage.confirm(receipt[1]));
      const route = /^\/api\/v1\/pairing\/(offers|joins|status|decision|cancel|signal|code)$/.exec(path)?.[1];
      if (route) {
        if (req.headers.origin && req.headers.origin !== (publicOrigin ?? `http://${req.headers.host}`)) {
          return json(403, { error: 'forbidden' });
        }
        if (route === 'offers' && method === 'POST') {
          const address = clientAddress(req, trustLoopbackProxy);
          if (address === null) return json(403, { error: 'forbidden' });
          const hold = admission.claimPair(address);
          let created;
          try { created = pairing.offer(); }
          catch (error) {
            admission.cancelPair(hold);
            throw error;
          }
          admission.commitPair(hold, created.expiresAt);
          return json(201, created);
        }
        if (route === 'joins' && method === 'POST') return json(201, pairing.join((await jsonBody(req))?.invitation));
        if (!bearer) return json(403, { error: 'forbidden' });
        if (route === 'code' && method === 'POST') {
          const body = (await jsonBody(req)) ?? {};
          codes.validateEpoch(body.epoch);
          if (codes.hasCode(body.lookup)) throw new CodeError('conflict');
          return json(201, pairing.registerCode(bearer, body));
        }
        if (route === 'status' && method === 'GET') return json(200, pairing.status(bearer));
        if (route === 'decision' && method === 'POST') return json(200, pairing.decide(bearer, (await jsonBody(req))?.state));
        if (route === 'cancel' && method === 'POST') return json(200, pairing.cancel(bearer));
        if (route === 'signal' && method === 'GET') return json(200, { signal: pairing.readSignal(bearer) });
        if (route === 'signal' && method === 'POST') return json(200, pairing.writeSignal(bearer, await jsonBody(req, 400_000)));
      }
      json(404, { error: 'missing' });
    } catch (error) {
      if (error instanceof StorageError || error instanceof PairingError || error instanceof CodeError ||
          error instanceof AdmissionError) {
        const retry = error.retryAfter ?? 60;
        json(statuses[error.code] ?? 500, { error: error.code }, error.code === 'limited' ? { 'retry-after': String(retry) } : undefined);
      }
      else if (error.code === 'ENOENT' && STATIC.has(path)) json(404, { error: 'missing' });
      else json(500, { error: 'server' });
    }
  }
  const server = createServer((req, res) => {
    const task = handle(req, res);
    handlers.add(task);
    task.then(() => handlers.delete(task), () => handlers.delete(task));
  });
  try {
    server.listen(port, host);
    await once(server, 'listening');
  } catch (error) {
    clearInterval(codeCleanup);
    codes.close();
    await storage.close();
    throw error;
  }
  return {
    origin: `http://${host.includes(':') ? '[' + host + ']' : host}:${server.address().port}`,
    async close() {
      clearInterval(codeCleanup);
      const closed = once(server, 'close');
      server.close();
      server.closeAllConnections();
      await closed;
      await Promise.allSettled(handlers);
      codes.close();
      await storage.close();
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [directory, port = '49185'] = process.argv.slice(2);
  if (!directory || !/^\d+$/.test(port)) {
    console.error('Usage: node src/server.mjs STATE_DIRECTORY [PORT]');
    process.exitCode = 1;
  } else {
    const basePath = process.env.HOP_BASE_PATH ?? '';
    const app = await startServer(directory, { port: Number(port), basePath,
      publicOrigin: process.env.HOP_PUBLIC_ORIGIN, trustLoopbackProxy: process.env.HOP_TRUST_LOOPBACK_PROXY === '1' });
    console.log(app.origin + basePath + '/');
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => app.close());
  }
}
