// ADR/004-single-server-short-code.md describes the trust boundary.
const utf8 = new TextEncoder();
const random = length => crypto.getRandomValues(new Uint8Array(length));
export const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export const PERIOD = 86_400_000;
export const RSA_BYTES = 384;
export const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
export const unhex = value => Uint8Array.from(value.match(/../g), byte => Number.parseInt(byte, 16));
export const integer = bytes => BigInt('0x' + hex(bytes));
export const octets = (number, length) => unhex(number.toString(16).padStart(length * 2, '0'));
const digest = async data => new Uint8Array(await crypto.subtle.digest('SHA-384', data));

export function normalizeCode(value) {
  const input = value.trim();
  if (!/^[a-z0-9 -]+$/i.test(input)) return null;
  const code = input.replace(/[ -]/g, '').toUpperCase();
  return code.length === 8 && [...code].every(char => ALPHABET.includes(char)) ? code : null;
}

export function codeSlot(code) {
  return ALPHABET.indexOf(code[0]) >> 4;
}

export function newCode(epoch) {
  return [...random(8)].map((byte, i) => ALPHABET[i === 0 ? (byte & 15) + 16 * (epoch % 2) : byte & 31]).join('');
}

export function modpow(value, exponent, modulus) {
  let result = 1n;
  for (; exponent; exponent >>= 1n, value = value * value % modulus) {
    if (exponent & 1n) result = result * value % modulus;
  }
  return result;
}

function inverse(value, modulus) {
  let [r, next, t, u] = [modulus, value, 0n, 1n];
  while (next) {
    const q = r / next;
    [r, next, t, u] = [next, r - q * next, u, t - q * u];
  }
  return r === 1n ? (t + modulus) % modulus : null;
}

async function encodePss(message) {
  // EMSA-PSS with SHA-384, zero salt and a 3071-bit encoded message.
  const input = new Uint8Array(56);
  input.set(await digest(message), 8);
  const hash = await digest(input);
  const dbSize = RSA_BYTES - hash.length - 1;
  const seed = new Uint8Array(hash.length + 4);
  seed.set(hash);
  const mask = await Promise.all(Array.from({ length: Math.ceil(dbSize / hash.length) }, (_, i) => {
    const counter = seed.slice();
    new DataView(counter.buffer).setUint32(hash.length, i);
    return digest(counter);
  }));
  const encoded = new Uint8Array(RSA_BYTES);
  for (let i = 0; i < dbSize; ++i) encoded[i] = mask[Math.floor(i / hash.length)][i % hash.length];
  encoded[0] &= 0x7f;
  encoded[dbSize - 1] ^= 1;
  encoded.set(hash, dbSize);
  encoded[encoded.length - 1] = 0xbc;
  return encoded;
}

export async function deriveCode(code, config, evaluate) {
  const { epoch, key } = config;
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch % 2 !== codeSlot(code) ||
      key?.kty !== 'RSA' || key.e !== 'AQAB' || !/^[a-zA-Z0-9_-]{512}$/.test(key.n ?? '')) throw Error('Invalid code key');
  const modulus = integer(Uint8Array.from(atob(key.n.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)));
  if (modulus < 2n ** 3071n || !(modulus & 1n)) throw Error('Invalid code key');
  const message = utf8.encode(`hop/short-code/v1/${epoch}/${key.n}/${code}`);
  const m = integer(await encodePss(message));
  if (m >= modulus || inverse(m, modulus) === null) throw Error('Invalid code input');
  let r, inv;
  do {
    r = integer(random(RSA_BYTES));
    inv = r > 0n && r < modulus ? inverse(r, modulus) : null;
  } while (inv === null);
  const blinded = hex(octets(m * modpow(r, 65537n, modulus) % modulus, RSA_BYTES));
  const signed = await evaluate(epoch, blinded);
  if (typeof signed !== 'string' || !/^[a-f0-9]{768}$/.test(signed) || BigInt('0x' + signed) >= modulus) throw Error('Invalid code response');
  const signature = octets(BigInt('0x' + signed) * inv % modulus, RSA_BYTES);
  const publicKey = await crypto.subtle.importKey('jwk', key, { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']);
  if (!await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 0 }, publicKey, signature, message)) throw Error('Invalid code signature');
  const seed = new Uint8Array(message.length + signature.length);
  seed.set(message);
  seed.set(signature, message.length);
  const hkdf = await crypto.subtle.importKey('raw', await digest(seed), 'HKDF', false, ['deriveBits']);
  const bytes = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-384', salt: new Uint8Array(0), info: utf8.encode('hop/short-code/v1/wrapper'),
  }, hkdf, 64 * 8));
  return { lookup: hex(bytes.subarray(0, 32)), key: bytes.subarray(32) };
}

export async function wrapAccess({ lookup, key }, access) {
  const secret = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const iv = random(12);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: unhex(lookup) },
    secret, unhex(access.id + access.secret));
  return hex(iv) + hex(new Uint8Array(encrypted));
}

export async function unwrapAccess({ lookup, key }, wrapper) {
  if (typeof wrapper !== 'string' || !/^[a-f0-9]{184}$/.test(wrapper)) throw Error('Invalid code wrapper');
  const secret = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const clear = new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: unhex(wrapper.slice(0, 24)), additionalData: unhex(lookup),
  }, secret, unhex(wrapper.slice(24))));
  return { id: hex(clear.subarray(0, 32)), secret: hex(clear.subarray(32)) };
}
