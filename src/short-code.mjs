import { codeSlot, deriveCode, newCode, unwrapAccess, wrapAccess } from './short-code-crypto.mjs';

const api = import.meta.url.startsWith('file:') ? '/api/v1/short-code/' : new URL('../api/v1/short-code/', import.meta.url).pathname;

export class ShortCodeError extends Error {
  constructor(status, code) {
    super('Short code request failed');
    this.status = status;
    this.code = code;
  }
}

async function request(path, data, owner) {
  const response = await fetch(api + path, data ? {
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

export async function registerShortCode(access, owner, pending, remember) {
  const configs = await request('keys');
  for (let attempt = 0; attempt < 4; ++attempt) {
    const previous = configs.find(entry => entry.epoch === pending?.epoch);
    const config = previous ?? configs[0];
    const code = previous ? pending.code : newCode(config.epoch);
    remember({ code, epoch: config.epoch });
    const keys = await derive(code, config);
    try {
      await request(access.id, { epoch: config.epoch, lookup: keys.lookup, wrapper: await wrapAccess(keys, access) }, owner);
      return code;
    } catch (error) {
      if (error.code !== 'conflict') throw error;
      pending = null;
    }
  }
  throw new ShortCodeError(503, 'busy');
}

export async function resolveShortCode(code) {
  const configs = await request('keys');
  const config = configs.find(entry => entry.epoch % 2 === codeSlot(code));
  if (!config) throw new ShortCodeError(404, 'missing');
  const keys = await derive(code, config);
  return unwrapAccess(keys, (await request(keys.lookup)).wrapper);
}
