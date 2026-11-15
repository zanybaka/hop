// ISO/IEC 18004, QR Model 2 version 10-L, byte mode.
// This version fits the full hop link without sending it to a QR service.
const VERSION = 10;
const SIDE = 4 * VERSION + 17;
const DATA_BYTES = 274;
const ECC_BYTES = 18;
const BLOCK_SIZES = [68, 68, 69, 69];
const MAX_INPUT = DATA_BYTES - 3;

function encodeBytes(input) {
  const data = new Uint8Array(DATA_BYTES);
  let offset = 0;
  const append = (value, bits) => {
    for (let i = bits - 1; i >= 0; i--, offset++) {
      data[offset >> 3] |= ((value >> i) & 1) << (7 - (offset % 8));
    }
  };
  append(4, 4); // Byte mode
  append(input.length, 16);
  for (const byte of input) append(byte, 8);
  append(0, 4); // Terminator completes the final byte.
  for (let i = offset >> 3, pad = 0; i < data.length; i++, pad++) {
    data[i] = pad % 2 === 0 ? 0xec : 0x11;
  }
  return data;
}

function multiply(a, b) {
  let product = 0;
  for (; b; b >>= 1) {
    if (b & 1) product ^= a;
    a <<= 1;
    if (a & 0x100) a ^= 0x11d;
  }
  return product;
}

function correctionWords(data) {
  // The generator is the product of (x + 2^i) over GF(256).
  let generator = [1];
  let root = 1;
  for (let i = 0; i < ECC_BYTES; i++, root = multiply(root, 2)) {
    const next = new Uint8Array(generator.length + 1);
    generator.forEach((coefficient, j) => {
      next[j] ^= coefficient;
      next[j + 1] ^= multiply(coefficient, root);
    });
    generator = next;
  }
  const blocks = [];
  let offset = 0;
  for (const size of BLOCK_SIZES) {
    const block = data.subarray(offset, offset + size);
    offset += size;
    const scratch = new Uint8Array(size + ECC_BYTES);
    scratch.set(block);
    for (let i = 0; i < size; i++) {
      const coefficient = scratch[i];
      for (let j = 0; j < generator.length; j++) {
        scratch[i + j] ^= multiply(generator[j], coefficient);
      }
    }
    blocks.push({ block, ecc: scratch.subarray(size) });
  }

  const words = [];
  for (let i = 0; i < Math.max(...BLOCK_SIZES); i++) {
    for (const { block } of blocks) if (i < block.length) words.push(block[i]);
  }
  for (let i = 0; i < ECC_BYTES; i++) {
    for (const { ecc } of blocks) words.push(ecc[i]);
  }
  return words;
}

function bch(value, width, polynomial) {
  let remainder = value << width;
  for (let bit = 31 - Math.clz32(remainder); bit >= width; bit--) {
    if (remainder & (1 << bit)) remainder ^= polynomial << (bit - width);
  }
  return (value << width) | remainder;
}

function format(matrix, mask) {
  const bits = bch(8 | mask, 10, 0x537) ^ 0x5412; // Error correction L.
  const bit = index => (bits >> index) & 1;
  for (let i = 0; i < 6; i++) matrix[i][8] = bit(i);
  matrix[7][8] = bit(6);
  matrix[8][8] = bit(7);
  matrix[8][7] = bit(8);
  for (let i = 9; i < 15; i++) matrix[8][14 - i] = bit(i);
  for (let i = 0; i < 8; i++) matrix[8][SIDE - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) matrix[SIDE - 15 + i][8] = bit(i);
  matrix[SIDE - 8][8] = 1;
}

function patterns() {
  const matrix = Array.from({ length: SIDE }, () => new Int8Array(SIDE).fill(-1));
  for (let i = 0; i < SIDE; i++) matrix[i][6] = matrix[6][i] = 1 - (i % 2);
  for (const [x, y] of [[3, 3], [SIDE - 4, 3], [3, SIDE - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        if (matrix[y + dy]?.[x + dx] !== undefined) {
          matrix[y + dy][x + dx] = Number(distance !== 2 && distance !== 4);
        }
      }
    }
  }
  for (const y of [6, 28, 50]) {
    for (const x of [6, 28, 50]) {
      if ((x === 6 && (y === 6 || y === 50)) || (x === 50 && y === 6)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          matrix[y + dy][x + dx] = Number(Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }
  const version = bch(VERSION, 12, 0x1f25);
  for (let i = 0; i < 18; i++) {
    const x = SIDE - 11 + (i % 3);
    const y = Math.floor(i / 3);
    matrix[y][x] = matrix[x][y] = (version >> i) & 1;
  }
  format(matrix, 0);
  return matrix;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  x => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
];

function linePenalty(line) {
  let score = 0;
  let run = 0;
  let last = -1;
  let pattern = 0;
  // Include the light quiet zone when matching finder-like runs.
  for (let i = -4; i < line.length + 4; i++) {
    const bit = line[i] ?? 0;
    if (i >= 0 && i < line.length) {
      run = bit === last ? run + 1 : 1;
      if (run >= 5) score += run === 5 ? 3 : 1;
      last = bit;
    }
    pattern = ((pattern << 1) | bit) & 0x7ff;
    if (i >= 6 && (pattern === 0x05d || pattern === 0x5d0)) score += 40;
  }
  return score;
}

function penalty(matrix) {
  let score = 0;
  let dark = 0;
  for (let y = 0; y < SIDE; y++) {
    score += linePenalty(matrix[y]) + linePenalty(matrix.map(row => row[y]));
    for (let x = 0; x < SIDE; x++) {
      const value = matrix[y][x];
      dark += value;
      if (x && y && value === matrix[y][x - 1] &&
          value === matrix[y - 1][x] && value === matrix[y - 1][x - 1]) score += 3;
    }
  }
  return score + 10 * Math.floor(Math.abs(20 * dark / (SIDE * SIDE) - 10));
}

function qrMatrix(input) {
  const words = correctionWords(encodeBytes(input));
  const base = patterns();
  const cells = [];
  let up = true;
  for (let right = SIDE - 1; right >= 1; right -= 2, up = !up) {
    if (right === 6) right = 5;
    for (let row = 0; row < SIDE; row++) {
      const y = up ? SIDE - 1 - row : row;
      for (let x = right; x >= right - 1; x--) {
        if (base[y][x] === -1) cells.push([x, y]);
      }
    }
  }
  if (cells.length !== words.length * 8) throw new Error('Invalid QR layout');

  let best;
  let lowest = Infinity;
  MASKS.forEach((mask, index) => {
    const matrix = base.map(row => row.slice());
    cells.forEach(([x, y], i) => {
      matrix[y][x] = ((words[i >> 3] >> (7 - (i % 8))) & 1) ^ Number(mask(x, y));
    });
    format(matrix, index);
    const score = penalty(matrix);
    if (score < lowest) {
      best = matrix;
      lowest = score;
    }
  });
  return best;
}

export async function qrImage(url) {
  const link = new URL(url);
  if (!['http:', 'https:'].includes(link.protocol)) throw new Error('Unsupported QR URL');
  const input = new TextEncoder().encode(link.href);
  if (input.length > MAX_INPUT) throw new Error('URL is too long for the QR code');
  const matrix = qrMatrix(input);

  const quietZone = 4;
  const scale = 6;
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = (SIDE + 2 * quietZone) * scale;
  const context = canvas.getContext('2d');
  if (!context) throw new Error('QR canvas unavailable');
  context.fillStyle = '#fff';
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = '#000';
  for (let y = 0; y < SIDE; y++) {
    for (let x = 0; x < SIDE; x++) {
      if (matrix[y][x]) context.fillRect((x + quietZone) * scale, (y + quietZone) * scale, scale, scale);
    }
  }
  return new Promise((resolve, reject) => {
    canvas.toBlob(blob => {
      if (blob) resolve(blob);
      else reject(new Error('Could not render QR image'));
    }, 'image/png');
  });
}
