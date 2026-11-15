const MAGIC = new Uint8Array([72, 79, 80, 49]);
const HEADER_SIZE = 8;
const MAX_TEXT = 1_048_576;
const MAX_MANIFEST = 6_311_936;
const MAX_FILES = 10;
const MAX_FILE_BYTES = 100_000_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function validate({ text, files }) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_TEXT) {
    throw new Error('Invalid text');
  }
  if (!Array.isArray(files) || files.length > MAX_FILES) throw new Error('Invalid files');
  let total = 0;
  for (const file of files) {
    if (!file || typeof file.name !== 'string' || encoder.encode(file.name).length > 255 ||
        !Number.isSafeInteger(file.size) || file.size < 0) {
      throw new Error('Invalid file metadata');
    }
    if (file.size > MAX_FILE_BYTES - total) throw new Error('File limit exceeded');
    total += file.size;
  }
  return total;
}

export function pack({ text = '', files = [] } = {}) {
  if (!Array.isArray(files)) throw new Error('Invalid files');
  const manifest = { text, files: files.map(({ name, blob }) => {
    if (!(blob instanceof Blob)) throw new Error('Invalid attachment');
    return { name, size: blob.size };
  }) };
  validate(manifest);
  const metadata = encoder.encode(JSON.stringify(manifest));
  if (metadata.length > MAX_MANIFEST) throw new Error('Manifest limit exceeded');
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC);
  new DataView(header.buffer).setUint32(MAGIC.length, metadata.length);
  return new Blob([header, metadata, ...files.map(file => file.blob)]);
}

// Call after the encrypted envelope has passed authentication.
export async function unpack(blob) {
  if (!(blob instanceof Blob) || blob.size < HEADER_SIZE) throw new Error('Invalid container');
  const header = new Uint8Array(await blob.slice(0, HEADER_SIZE).arrayBuffer());
  if (MAGIC.some((byte, index) => header[index] !== byte)) throw new Error('Unknown container version');
  const length = new DataView(header.buffer).getUint32(MAGIC.length);
  let offset = HEADER_SIZE + length;
  if (length > MAX_MANIFEST || offset > blob.size) throw new Error('Invalid manifest length');
  const manifest = JSON.parse(decoder.decode(await blob.slice(HEADER_SIZE, offset).arrayBuffer()));
  if (!manifest || typeof manifest !== 'object') throw new Error('Invalid manifest');
  const total = validate(manifest);
  if (offset + total !== blob.size) throw new Error('Invalid container length');
  const files = manifest.files.map(({ name, size }) => {
    const part = blob.slice(offset, offset + size);
    offset += size;
    return { name, blob: part };
  });
  return { text: manifest.text, files };
}
