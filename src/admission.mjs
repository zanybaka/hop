import { createHmac, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { MAX_ENVELOPE_BYTES } from './storage.mjs';

const WINDOW = 60_000;
const MAX_BUCKETS = 256;
const MAX_RESERVE_HOLDS = 256;
const MAX_PAIR_HOLDS = 1024;

export class AdmissionError extends Error {
  constructor(code, retryAfter = 60) {
    super(code);
    this.name = 'AdmissionError';
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

export function clientAddress(request, trustLoopbackProxy) {
  if (!trustLoopbackProxy) return request.socket.remoteAddress || '';
  const forwarded = request.headers['x-hop-client-ip'];
  if (typeof forwarded !== 'string' || !isIP(forwarded)) return null;
  return forwarded;
}

function positive(value, max) {
  return Number.isSafeInteger(value) && value > 0 && value <= max;
}

function secondsUntil(time, deadline) {
  if (!Number.isFinite(deadline)) return 60;
  return Math.min(300, Math.max(1, Math.ceil((deadline - time) / 1000)));
}

export function createAdmission({
  now = Date.now,
  lease = 30_000,
  offerLifetime = 300_000,
  buckets: bucketCount = 128,
  reservePerSource = 30,
  reserveGlobal = 300,
  reserveBytesPerSource = 4 * MAX_ENVELOPE_BYTES,
  reserveCountPerSource = 8,
  reserveCountGlobal = 48,
  pairPerSource = 20,
  pairGlobal = 120,
  pairLivePerSource = 8,
  pairLiveGlobal = 1024,
} = {}) {
  if (typeof now !== 'function' ||
      ![lease, offerLifetime, bucketCount, reservePerSource, reserveGlobal, reserveBytesPerSource,
        reserveCountPerSource, reserveCountGlobal, pairPerSource, pairGlobal, pairLivePerSource, pairLiveGlobal]
        .every(value => positive(value, Number.MAX_SAFE_INTEGER)) ||
      bucketCount > MAX_BUCKETS || reserveCountGlobal > MAX_RESERVE_HOLDS || pairLiveGlobal > MAX_PAIR_HOLDS ||
      reserveCountPerSource > reserveCountGlobal || pairLivePerSource > pairLiveGlobal) {
    throw new AdmissionError('invalid');
  }
  const secret = randomBytes(32);
  const buckets = Array.from({ length: bucketCount }, () => ({
    window: -1, reserveCreates: 0, pairCreates: 0, reservedBytes: 0, reserveCount: 0, pairLive: 0,
  }));
  const global = {
    window: -1, reserveCreates: 0, pairCreates: 0, reserveCount: 0, pairLive: 0,
  };
  const holds = new Map();
  const byToken = new Map();
  const pairHolds = new Map();
  let nextId = 0;

  function indexFor(address) {
    const digest = createHmac('sha256', secret).update(String(address)).digest();
    return digest.readUInt32BE(0) % buckets.length;
  }

  function windowEnd(time) {
    return (Math.floor(time / WINDOW) + 1) * WINDOW;
  }

  function earliest(collection, index) {
    let best = Infinity;
    for (const hold of collection.values()) {
      if (index === undefined || hold.index === index) best = Math.min(best, hold.deadline);
    }
    return best;
  }

  function releaseReserveHold(id) {
    const hold = holds.get(id);
    if (!hold) return;
    const bucket = buckets[hold.index];
    bucket.reservedBytes -= hold.bytes;
    bucket.reserveCount -= 1;
    global.reserveCount -= 1;
    holds.delete(id);
    if (hold.token) byToken.delete(hold.token);
  }

  function releasePairHold(id) {
    const hold = pairHolds.get(id);
    if (!hold) return;
    buckets[hold.index].pairLive -= 1;
    global.pairLive -= 1;
    pairHolds.delete(id);
  }

  function sweep(time = now()) {
    const window = Math.floor(time / WINDOW);
    if (global.window !== window) {
      global.window = window;
      global.reserveCreates = 0;
      global.pairCreates = 0;
    }
    for (const bucket of buckets) {
      if (bucket.window === window) continue;
      bucket.window = window;
      bucket.reserveCreates = 0;
      bucket.pairCreates = 0;
    }
    for (const [id, hold] of holds) if (hold.deadline <= time) releaseReserveHold(id);
    for (const [id, hold] of pairHolds) if (hold.deadline <= time) releasePairHold(id);
    return time;
  }

  function claimReserve(address, bytes) {
    const time = sweep();
    if (!Number.isSafeInteger(bytes) || bytes < 1) throw new AdmissionError('invalid');
    const index = indexFor(address);
    const bucket = buckets[index];
    const overRate = bucket.reserveCreates >= reservePerSource || global.reserveCreates >= reserveGlobal;
    const overBytes = bucket.reservedBytes + bytes > reserveBytesPerSource;
    const overCount = bucket.reserveCount >= reserveCountPerSource || global.reserveCount >= reserveCountGlobal;
    if (overRate || overBytes || overCount) {
      const rateAt = overRate ? windowEnd(time) : Infinity;
      const holdAt = overBytes || overCount
        ? earliest(holds, global.reserveCount >= reserveCountGlobal ? undefined : index)
        : Infinity;
      throw new AdmissionError('limited', secondsUntil(time, Math.min(rateAt, holdAt)));
    }
    bucket.reserveCreates += 1;
    global.reserveCreates += 1;
    bucket.reservedBytes += bytes;
    bucket.reserveCount += 1;
    global.reserveCount += 1;
    const id = ++nextId;
    holds.set(id, { index, bytes, deadline: time + lease, token: null });
    return id;
  }

  function claimPair(address) {
    const time = sweep();
    const index = indexFor(address);
    const bucket = buckets[index];
    const overRate = bucket.pairCreates >= pairPerSource || global.pairCreates >= pairGlobal;
    const overLive = bucket.pairLive >= pairLivePerSource || global.pairLive >= pairLiveGlobal;
    if (overRate || overLive) {
      const rateAt = overRate ? windowEnd(time) : Infinity;
      const holdAt = overLive
        ? earliest(pairHolds, global.pairLive >= pairLiveGlobal ? undefined : index)
        : Infinity;
      throw new AdmissionError('limited', secondsUntil(time, Math.min(rateAt, holdAt)));
    }
    bucket.pairCreates += 1;
    global.pairCreates += 1;
    bucket.pairLive += 1;
    global.pairLive += 1;
    const id = ++nextId;
    pairHolds.set(id, { index, deadline: time + offerLifetime });
    return id;
  }

  return {
    claimReserve,
    commitReserve(id, token) {
      const hold = holds.get(id);
      if (!hold) return;
      hold.token = token;
      byToken.set(token, id);
    },
    cancelReserve(id) { releaseReserveHold(id); },
    releaseReserve(token) {
      const id = byToken.get(token);
      if (id !== undefined) releaseReserveHold(id);
    },
    claimPair,
    commitPair(id, expiresAt) {
      const hold = pairHolds.get(id);
      if (hold && Number.isSafeInteger(expiresAt)) hold.deadline = expiresAt;
    },
    cancelPair(id) { releasePairHold(id); },
    sweep,
    bounds() {
      return { buckets: buckets.length, holds: holds.size, pairHolds: pairHolds.size };
    },
  };
}
