// ADR/001-client-encryption.md defines the trust boundary and full-link contract.
import { pack, unpack } from './container.mjs';

const PREFIX = new TextEncoder().encode('HOPG');
const NONCE_SIZE = 12;
const HEADER_SIZE = PREFIX.length + NONCE_SIZE;
const TAG_SIZE = 16;
const TOKEN = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const random = length => crypto.getRandomValues(new Uint8Array(length));

function parameters({ id, secret }, context = '') {
  if (!TOKEN.test(id ?? '') || !TOKEN.test(secret ?? '')) throw new Error('Invalid transfer link');
  return {
    raw: Uint8Array.from(secret.match(/../g), byte => Number.parseInt(byte, 16)),
    additionalData: encoder.encode('hop/HOPG/' + id + context),
  };
}

export function newTransfer() {
  return { id: hex(random(32)), secret: hex(random(32)) };
}

export function transferLink(page, access) {
  parameters(access);
  const url = new URL(page);
  url.hash = `v1/${access.id}/${access.secret}`;
  return url.href;
}

export function parseTransferLink(page) {
  const match = /^#v1\/([a-f0-9]{64})\/([a-f0-9]{64})$/.exec(new URL(page).hash);
  if (!match) throw new Error('Invalid transfer link');
  return { id: match[1], secret: match[2] };
}

export async function encryptTransfer(access, content, context) {
  const { raw, additionalData } = parameters(access, context);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const iv = random(NONCE_SIZE);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, await pack(content).arrayBuffer());
  return new Blob([PREFIX, iv, encrypted]);
}

export async function decryptTransfer(access, blob, context) {
  if (!(blob instanceof Blob) || blob.size < HEADER_SIZE + TAG_SIZE) throw new Error('Invalid encrypted transfer');
  const header = new Uint8Array(await blob.slice(0, HEADER_SIZE).arrayBuffer());
  if (PREFIX.some((byte, i) => header[i] !== byte)) throw new Error('Unknown envelope version');
  const { raw, additionalData } = parameters(access, context);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const clear = await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: header.subarray(PREFIX.length), additionalData,
  }, key, await blob.slice(HEADER_SIZE).arrayBuffer());
  return unpack(new Blob([clear]));
}
