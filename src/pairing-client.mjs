/* ADR/002-approved-direct-pair.md */
const route = import.meta.url.startsWith('file:') ? '/api/v1/pairing/' : new URL('../api/v1/pairing/', import.meta.url).pathname;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const token = /^[a-f0-9]{64}$/;

async function call(path, { method = 'GET', capability, payload, signal } = {}) {
  const response = await fetch(route + path, {
    method, signal, headers: {
      ...(capability && { authorization: 'Bearer ' + capability }),
      ...(payload !== undefined && { 'content-type': 'application/json' }),
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  if (!response.ok) throw Error(`Pairing request failed (${response.status})`);
  return response.json();
}

export function offerPair() { return call('offers', { method: 'POST' }); }
export function joinPair(invitation) { return call('joins', { method: 'POST', payload: { invitation } }); }
export function decidePair(capability, approved) {
  return call('decision', { capability, method: 'POST', payload: { state: approved ? 'approved' : 'declined' } });
}
export function cancelPair(capability) { return call('cancel', { capability, method: 'POST' }); }
export function pairStatus(capability, signal) { return call('status', { capability, signal }); }

export async function writeRelay(capability, bytes, signal) {
  const response = await fetch(route + 'relay', {
    method: 'POST', signal,
    headers: { authorization: 'Bearer ' + capability, 'content-type': 'application/octet-stream' },
    body: bytes,
  });
  if (response.status === 507) return false;
  if (!response.ok) throw Error(`Pairing request failed (${response.status})`);
  return true;
}

export async function readRelay(capability, signal) {
  const response = await fetch(route + 'relay', {
    signal, headers: { authorization: 'Bearer ' + capability },
  });
  if (response.status === 204) return null;
  if (response.status === 410) return 'closed';
  if (!response.ok) throw Error(`Pairing request failed (${response.status})`);
  return new Uint8Array(await response.arrayBuffer());
}

export function leaveRelay(capability) {
  return fetch(route + 'leave', {
    method: 'POST', headers: { authorization: 'Bearer ' + capability },
  }).then(response => { if (!response.ok) throw Error(`Pairing request failed (${response.status})`); });
}

export function invitationLink(page, invitation, secret) {
  if (!token.test(invitation) || !token.test(secret)) throw Error('Invalid pair invitation');
  const url = new URL(page);
  url.hash = `pair/${invitation}/${secret}`;
  return url.href;
}

export function parseInvitationLink(page) {
  const match = /^#pair\/([a-f0-9]{64})\/([a-f0-9]{64})$/.exec(new URL(page).hash);
  if (!match) throw Error('Invalid pair invitation');
  return { invitation: match[1], secret: match[2] };
}

function fromHex(value) { return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16)); }
const toHex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');

async function continuationAccess({ id, secret }, offer, answer) {
  if (!token.test(id) || !token.test(secret)) throw Error('Invalid pair invitation');
  const key = await crypto.subtle.importKey('raw', fromHex(secret), 'HKDF', false, ['deriveBits']);
  const transcript = await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify([id, offer, answer])));
  const derive = label => crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: transcript, info: encoder.encode('hop/continuation/v1/' + label),
  }, key, 256).then(toHex);
  const [address, readSecret, writer] = await Promise.all([derive('address'), derive('content'), derive('write')]);
  return { access: { id: address, secret: readSecret }, writer };
}
const aad = (invitation, type) => encoder.encode(`hop/pair-signal/v1/${invitation}/${type}`);
export async function signalCodec({ invitation, secret }) {
  if (!token.test(invitation) || !token.test(secret)) throw Error('Invalid pair invitation');
  const material = await crypto.subtle.importKey('raw', fromHex(secret), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: fromHex(invitation), info: encoder.encode('hop/pair-signal/v1') },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return {
    async wrap({ type, sdp }) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(invitation, type) }, key, encoder.encode(sdp)));
      const envelope = new Uint8Array(iv.length + encrypted.length);
      envelope.set(iv);
      envelope.set(encrypted, iv.length);
      return { type, sdp: btoa(Array.from(envelope, byte => String.fromCharCode(byte)).join('')) };
    },
    async unwrap({ type, sdp }) {
      const bytes = Uint8Array.from(atob(sdp), char => char.charCodeAt(0));
      if (bytes.length < 28) throw Error('Invalid signal envelope');
      const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: aad(invitation, type) }, key, bytes.subarray(12));
      return { type, sdp: decoder.decode(clear) };
    },
  };
}

export async function pairSignals(capability, access) {
  const codec = await signalCodec(access);
  const descriptions = {};
  let sent;
  return {
    async sendSignal(description, { signal } = {}) {
      if (!sent || sent.type !== description.type || sent.sdp !== description.sdp) {
        sent = { ...description, payload: await codec.wrap(description) };
      }
      await call('signal', { method: 'POST', capability, signal, payload: sent.payload });
      descriptions[description.type] = description.sdp;
    },
    async readSignal({ signal } = {}) {
      const response = await call('signal', { capability, signal });
      if (!response.signal) return null;
      const description = await codec.unwrap(response.signal);
      descriptions[description.type] = description.sdp;
      return description;
    },
    continuation() {
      if (!descriptions.offer || !descriptions.answer) throw Error('Incomplete pair negotiation');
      return continuationAccess({ id: access.invitation, secret: access.secret }, descriptions.offer, descriptions.answer);
    },
  };
}
