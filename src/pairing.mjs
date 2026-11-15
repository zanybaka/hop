import { createHash, randomBytes } from 'node:crypto';

const capability = /^[a-f0-9]{64}$/;
export const MAX_SIGNAL_BYTES = 65_536;
const digest = token => createHash('sha256').update(token).digest('hex');
const issue = () => randomBytes(32).toString('hex');

export class PairingError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PairingError';
    this.code = code;
  }
}

export function createPairing({ now = Date.now, offerLifetime = 300_000, maxOffers = 1024 } = {}) {
  if (typeof now !== 'function' || !Number.isSafeInteger(offerLifetime) || offerLifetime < 1 ||
      !Number.isSafeInteger(maxOffers) || maxOffers < 1) throw new PairingError('invalid');

  const offers = new Set();
  const invitations = new Map();
  const holders = new Map();

  function sweep() {
    const time = now();
    for (const entry of offers) {
      if (entry.expiresAt > time) continue;
      offers.delete(entry);
      invitations.delete(entry.invitation);
      holders.delete(entry.owner);
      if (entry.recipient) holders.delete(entry.recipient);
    }
    return time;
  }

  function checkedDigest(token) {
    if (typeof token !== 'string' || !capability.test(token)) throw new PairingError('invalid');
    return digest(token);
  }

  function lookup(token) {
    sweep();
    const holder = holders.get(checkedDigest(token));
    if (!holder) throw new PairingError('missing');
    return holder;
  }

  function owned(token) {
    const { entry, role } = lookup(token);
    if (role !== 'owner') throw new PairingError('forbidden');
    return entry;
  }

  function snapshot({ entry, role }) {
    return { state: entry.state, role, expiresAt: entry.expiresAt };
  }

  function approved(token) {
    const holder = lookup(token);
    if (holder.entry.state !== 'approved') throw new PairingError('conflict');
    return holder;
  }

  return {
    offer() {
      const time = sweep();
      if (offers.size >= maxOffers) throw new PairingError('full');
      const invitation = issue();
      const owner = issue();
      const entry = { invitation: digest(invitation), owner: digest(owner), expiresAt: time + offerLifetime, state: 'offered' };
      offers.add(entry);
      invitations.set(entry.invitation, entry);
      holders.set(entry.owner, { entry, role: 'owner' });
      return { invitation, owner, expiresAt: entry.expiresAt };
    },
    join(invitation) {
      sweep();
      const entry = invitations.get(checkedDigest(invitation));
      if (!entry) throw new PairingError('missing');
      invitations.delete(entry.invitation);
      const recipient = issue();
      entry.recipient = digest(recipient);
      entry.state = 'joined';
      holders.set(entry.recipient, { entry, role: 'recipient' });
      return { recipient, expiresAt: entry.expiresAt };
    },
    status(token) { return snapshot(lookup(token)); },
    decide(owner, state) {
      if (state !== 'approved' && state !== 'declined') throw new PairingError('invalid');
      const entry = owned(owner);
      if (entry.state !== 'joined') throw new PairingError('conflict');
      entry.state = state;
      return snapshot({ entry, role: 'owner' });
    },
    cancel(owner) {
      const entry = owned(owner);
      if (entry.state !== 'offered' && entry.state !== 'joined') throw new PairingError('conflict');
      invitations.delete(entry.invitation);
      entry.state = 'cancelled';
      return snapshot({ entry, role: 'owner' });
    },
    writeSignal(token, signal) {
      const { entry, role } = approved(token);
      if (!signal || typeof signal !== 'object' || Array.isArray(signal) || Object.keys(signal).length !== 2 ||
          !Object.hasOwn(signal, 'type') || !Object.hasOwn(signal, 'sdp')) throw new PairingError('invalid');
      const { type, sdp } = signal;
      if ((type !== 'offer' && type !== 'answer') || typeof sdp !== 'string' || sdp.length === 0 ||
          Buffer.byteLength(sdp, 'utf8') > MAX_SIGNAL_BYTES) throw new PairingError('invalid');
      if (type !== (role === 'owner' ? 'offer' : 'answer')) throw new PairingError('forbidden');
      if (type === 'answer' && entry.offer === undefined) throw new PairingError('conflict');
      if (entry[type] !== undefined && entry[type] !== sdp) throw new PairingError('conflict');
      entry[type] = sdp;
      return { type };
    },
    readSignal(token) {
      const { entry, role } = approved(token);
      const type = role === 'owner' ? 'answer' : 'offer';
      return entry[type] === undefined ? null : { type, sdp: entry[type] };
    },
  };
}
