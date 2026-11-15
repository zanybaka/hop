import { decryptTransfer, encryptTransfer } from './envelope.mjs';

const headerSize = 9;
export const DIRECT_HEADER_BYTES = headerSize;

function context({ clock, role }) {
  if (!Number.isSafeInteger(clock) || clock < 1 || (role !== 'owner' && role !== 'recipient')) {
    throw Error('Invalid direct revision');
  }
  return `/direct-v1/${clock}/${role}`;
}

export function compareRevision(a, b) {
  return a.clock - b.clock || Number(a.role === 'owner') - Number(b.role === 'owner');
}

export async function sealRevision(access, revision, content) {
  const envelope = await encryptTransfer(access, content, context(revision));
  const header = new Uint8Array(headerSize);
  new DataView(header.buffer).setBigUint64(0, BigInt(revision.clock));
  header[8] = revision.role === 'owner' ? 1 : 0;
  return new Blob([header, envelope]);
}

export async function openRevision(access, blob, sender) {
  const header = new Uint8Array(await blob.slice(0, headerSize).arrayBuffer());
  if (header.length !== headerSize || header[8] > 1) throw Error('Invalid direct revision');
  const revision = {
    clock: Number(new DataView(header.buffer).getBigUint64(0)),
    role: header[8] ? 'owner' : 'recipient',
  };
  if (revision.role !== sender) throw Error('Invalid direct sender');
  return { revision, content: await decryptTransfer(access, blob.slice(headerSize), context(revision)) };
}
