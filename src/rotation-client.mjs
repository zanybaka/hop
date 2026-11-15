const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const IDENTIFIER = /^[a-f0-9]{64}$/;
const COORDINATE = /^[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g), byte => Number.parseInt(byte, 16));

function context(stableId, locator) {
  if (!IDENTIFIER.test(stableId ?? '') || !IDENTIFIER.test(locator ?? '')) throw Error('Invalid rotation address');
  return encoder.encode(`hop/rotation/v1/${stableId}/${locator}`);
}

function publicJwk(key) {
  if (key?.kty !== 'EC' || key.crv !== 'P-256' || !COORDINATE.test(key.x ?? '') || !COORDINATE.test(key.y ?? '') ||
      Object.hasOwn(key, 'd')) throw Error('Invalid rotation public key');
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y };
}

async function wrappingKey(privateKey, peerKey, additionalData, usage) {
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk(peerKey), CURVE, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const secret = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: additionalData,
  }, secret, { name: 'AES-GCM', length: 256 }, false, [usage]);
}

export async function createRotationKeyPair() {
  const pair = await crypto.subtle.generateKey(CURVE, true, ['deriveBits']);
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.exportKey('jwk', pair.publicKey),
    crypto.subtle.exportKey('jwk', pair.privateKey),
  ]);
  return { publicKey: publicJwk(publicKey), privateKey };
}

export async function sealRotationAccess(stableId, access, recipientPublicKey) {
  const additionalData = context(stableId, access.id);
  if (!IDENTIFIER.test(access.secret ?? '')) throw Error('Invalid rotation key');
  const ephemeral = await crypto.subtle.generateKey(CURVE, false, ['deriveBits']);
  const key = await wrappingKey(ephemeral.privateKey, recipientPublicKey, additionalData, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, unhex(access.secret));
  const ephemeralKey = publicJwk(await crypto.subtle.exportKey('jwk', ephemeral.publicKey));
  return JSON.stringify({ version: 1, ephemeralKey, iv: hex(iv), ciphertext: hex(new Uint8Array(encrypted)) });
}

export async function openRotationAccess(stableId, locator, wrapper, privateJwk) {
  const additionalData = context(stableId, locator);
  if (typeof wrapper !== 'string' || wrapper.length > 4096) throw Error('Invalid recovery package');
  const data = JSON.parse(wrapper);
  if (data?.version !== 1 || !/^[a-f0-9]{24}$/.test(data.iv ?? '') || !/^[a-f0-9]{96}$/.test(data.ciphertext ?? '')) {
    throw Error('Invalid recovery package');
  }
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, CURVE, false, ['deriveBits']);
  const key = await wrappingKey(privateKey, data.ephemeralKey, additionalData, 'decrypt');
  const clear = await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: unhex(data.iv), additionalData,
  }, key, unhex(data.ciphertext));
  return { id: locator, secret: hex(new Uint8Array(clear)) };
}
