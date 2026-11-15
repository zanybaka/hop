import { decryptTransfer, encryptTransfer, newTransfer, transferLink } from './envelope.mjs';

const api = import.meta.url.startsWith('file:') ? '/api/v1' : new URL('../api/v1', import.meta.url).pathname;
const DAY = 86_400_000;

export class PublicationError extends Error {
  constructor(status) {
    super(`Publication request failed (${status})`);
    this.status = status;
  }
}

async function checked(response) {
  if (!response.ok) {
    await response.body?.cancel();
    throw new PublicationError(response.status);
  }
  return response;
}

async function send({ access, stableId = access.id, owner, version }, content, options = {}, envelopeAccess = access) {
  const envelope = await encryptTransfer(envelopeAccess, content);
  const reserve = await checked(await fetch(api + '/reservations', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + owner },
    body: JSON.stringify({
      id: stableId, version, bytes: envelope.size,
      ...(stableId !== access.id && { locator: access.id }),
      hasFiles: (content.files?.length ?? 0) > 0,
      ...options,
    }),
  }));
  const { token } = await reserve.json();
  try {
    const result = await checked(await fetch(api + '/uploads/' + token, { method: 'PUT', body: envelope }));
    return await result.json();
  } catch (error) {
    await fetch(api + '/uploads/' + token, { method: 'DELETE' }).catch(() => {});
    throw error;
  }
}

export async function createPublication(content = {}, options = {}) {
  const access = newTransfer();
  const { secret: owner } = newTransfer();
  const saved = await send({ access, owner, version: 0 }, content, {
    protected: options.protected === true, lifetime: options.lifetimeMs ?? DAY,
  });
  return { access, owner, ...saved };
}

export async function prepareContinuation(access, writer, onCreated) {
  const owner = newTransfer().secret;
  const saved = await send({ access, owner, version: 0 }, {});
  onCreated(owner);
  await enableContinuation(access, owner, writer);
  return { ...saved, owner };
}

export async function enableContinuation(access, owner, writer) {
  await grantWriter(access.id, owner, writer);
  await exchangeSettings(access.id, owner, 'mode', { mode: 'exchange' });
}

export async function saveContinuation(state, content) {
  try {
    return await publishPublication(state, content);
  } catch (error) {
    if (error.status !== 409) throw error;
    const snapshot = await readPublication(state.access, { confirm: false });
    if (snapshot.version <= state.version) throw error;
    return snapshot;
  }
}

// A checkpoint is a read-only continuation. The random write credential is
// discarded after creation and is never associated with either pair member.
export async function saveCheckpoint(access, content) {
  const { secret: owner } = newTransfer();
  try {
    return await send({ access, owner, version: 0 }, content);
  } catch (error) {
    if (error.status !== 403 && error.status !== 409) throw error;
    // The other browser may have completed its own save. Authenticate the
    // existing record before displaying it as a successful continuation.
    for (const delay of [0, 200, 500]) {
      if (delay) await new Promise(resolve => setTimeout(resolve, delay));
      try { return await readPublication(access, { confirm: false }); }
      catch (readError) { if (readError.status !== 404) throw readError; }
    }
    throw error;
  }
}

export function publishPublication(state, content) {
  return send(state, content);
}

export async function rotatePublication(state, content, { member, access, recovery }) {
  const saved = await send(state, content, {
    locator: state.access.id, rotation: { member, locator: access.id, recovery },
  }, access);
  return { ...saved, access };
}

export async function readPublication(access, { confirm = true } = {}) {
  if (!/^[a-f0-9]{64}$/.test(access.id ?? '')) throw new PublicationError(400);
  const response = await checked(await fetch(api + '/records/' + access.id, { cache: 'no-store' }));
  const content = await decryptTransfer(access, await response.blob());
  const version = Number(response.headers.get('x-hop-version'));
  const contentVersion = Number(response.headers.get('x-hop-content-version') ?? version);
  let expiresAt = Number(response.headers.get('x-hop-expires-at'));
  const receipt = response.headers.get('x-hop-receipt');
  if (receipt && confirm) {
    // A delivery can succeed even if the follow-up confirmation fails.
    try {
      const confirmed = await fetch(api + '/receipts/' + receipt, { method: 'POST' });
      if (confirmed.ok) ({ expiresAt } = await confirmed.json());
    } catch { /* The original deadline is still usable. */ }
  }
  return { content, version, contentVersion, expiresAt };
}

export async function exchangeSettings(id, credential, action, payload) {
  if (!/^[a-f0-9]{64}$/.test(id) || (action && !['mode', 'invite', 'one-use', 'claim', 'share', 'claim-shared', 'revoke-write', 'member-key'].includes(action))) {
    throw new PublicationError(400);
  }
  const response = await checked(await fetch(api + '/exchange/' + id + (action ? '/' + action : ''), {
    method: action ? 'POST' : 'GET',
    headers: { authorization: 'Bearer ' + credential, ...(action && { 'content-type': 'application/json' }) },
    body: action ? JSON.stringify(payload) : undefined,
  }));
  return response.json();
}

export function enrollRotationKey(stableId, credential, publicKey) {
  return exchangeSettings(stableId, credential, 'member-key', { key: publicKey });
}

export async function createWriterLink(page, access, owner, stableId = access.id) {
  const { secret: writer } = newTransfer();
  await exchangeSettings(stableId, owner, 'one-use', {
    fingerprint: await fingerprintOf(writer), ...(stableId !== access.id && { locator: access.id }),
  });
  const url = new URL(transferLink(page, access));
  url.hash += '/write/' + writer;
  if (stableId !== access.id) url.hash += '/group/' + stableId;
  return url.href;
}

async function fingerprintOf(secret) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function grantWriter(id, owner, writer) {
  await exchangeSettings(id, owner, 'invite', { fingerprint: await fingerprintOf(writer) });
}

export async function claimWriter(id, invite, device, locator = id, publicKey) {
  await exchangeSettings(id, invite, 'claim', {
    fingerprint: await fingerprintOf(device), ...(locator !== id && { locator }),
    ...(publicKey && { key: publicKey }),
  });
}

export async function prepareShare(access, owner, group, settings) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(owner), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const message = new TextEncoder().encode('hop/share/v1/' + access.id + '/' + settings.shareGeneration);
  const bytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const invite = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  await exchangeSettings(group, owner, 'share', {
    fingerprint: await fingerprintOf(invite), locator: access.id, generation: settings.shareGeneration,
  });
  return { ...access, invite };
}

export function sharedLink(page, access) {
  const url = new URL(transferLink(page, access));
  if (access.invite) url.hash += '/join/' + access.invite;
  return url.href;
}

export function claimShared(locator, invite, device, publicKey) {
  return fingerprintOf(device).then(fingerprint => exchangeSettings(locator, invite, 'claim-shared', { fingerprint, key: publicKey }));
}

export function readWriterLink(page) {
  const url = new URL(page);
  const share = /^(#v1\/[a-f0-9]{64}\/[a-f0-9]{64})\/join\/([a-f0-9]{64})$/.exec(url.hash);
  if (share) {
    url.hash = share[1];
    return { url, shared: share[2] };
  }
  const match = /^(#v1\/[a-f0-9]{64}\/[a-f0-9]{64})\/write\/([a-f0-9]{64})(?:\/group\/([a-f0-9]{64}))?$/.exec(url.hash);
  if (!match) return { url };
  url.hash = match[1];
  return { url, writer: match[2], ...(match[3] && { stableId: match[3] }) };
}
