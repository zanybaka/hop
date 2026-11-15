import { codeSlot, deriveCode, newCode, unwrapAccess, wrapAccess } from './short-code-crypto.mjs';

const api = import.meta.url.startsWith('file:') ? '/api/v1/short-code/' : new URL('../api/v1/short-code/', import.meta.url).pathname;
const pairApi = import.meta.url.startsWith('file:') ? '/api/v1/pairing/' : new URL('../api/v1/pairing/', import.meta.url).pathname;

export class ShortCodeError extends Error {
  constructor(status, code) {
    super('Short code request failed');
    this.status = status;
    this.code = code;
  }
}

async function request(path, data, owner, base = api) {
  const response = await fetch(base + path, data ? {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(owner && { authorization: 'Bearer ' + owner }) },
    body: JSON.stringify(data),
  } : { cache: 'no-store' });
  const body = await response.json();
  if (!response.ok) throw new ShortCodeError(response.status, body.error);
  return body;
}

async function derive(code, config) {
  return deriveCode(code, config, async (epoch, blinded) =>
    (await request('evaluate', { epoch, blinded })).signed);
}

async function registerCode(access, write, pending, remember) {
  const configs = await request('keys');
  for (let attempt = 0; attempt < 4; ++attempt) {
    const previous = configs.find(entry => entry.epoch === pending?.epoch);
    const config = previous ?? configs[0];
    const code = previous ? pending.code : newCode(config.epoch);
    remember?.({ code, epoch: config.epoch });
    const keys = await derive(code, config);
    try {
      await write({ epoch: config.epoch, lookup: keys.lookup, wrapper: await wrapAccess(keys, access) });
      return code;
    } catch (error) {
      if (error.code !== 'conflict') throw error;
      pending = null;
    }
  }
  throw new ShortCodeError(503, 'busy');
}

export function registerShortCode(access, owner, pending, remember) {
  return registerCode(access, data => request(access.id, data, owner), pending, remember);
}

export function registerPairCode({ invitation, secret }, owner) {
  return registerCode({ id: invitation, secret }, data => request('code', data, owner, pairApi));
}

export async function resolveOpenCode(code) {
  const configs = await request('keys');
  const config = configs.find(entry => entry.epoch % 2 === codeSlot(code));
  if (!config) throw new ShortCodeError(404, 'missing');
  const keys = await derive(code, config);
  const { wrapper, kind } = await request(keys.lookup);
  const access = await unwrapAccess(keys, wrapper);
  return kind === 'pair' ? { invitation: { invitation: access.id, secret: access.secret } } : { access };
}

export async function resolveShortCode(code) {
  const { access } = await resolveOpenCode(code);
  if (!access) throw new ShortCodeError(404, 'missing');
  return access;
}
