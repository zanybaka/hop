import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const tokenFormat = /^[a-f0-9]{64}$/;
const validToken = value => typeof value === 'string' && tokenFormat.test(value);
const digest = value => createHash('sha256').update(value).digest('hex');
const equal = (first, second) => timingSafeEqual(Buffer.from(first, 'hex'), Buffer.from(second, 'hex'));
const validMode = mode => mode === 'read' || mode === 'exchange';

export class ParticipantError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ParticipantError';
    this.code = code;
  }
}

// The caller supplies a trusted owner fingerprint and checks invitations before join.
export function createParticipants({ now = Date.now, idleMs = 60_000, maxParticipants = 8, maxTransfers = 1024 } = {}) {
  if (typeof now !== 'function' || !Number.isSafeInteger(idleMs) || idleMs < 1 ||
      !Number.isSafeInteger(maxParticipants) || maxParticipants < 1 || maxParticipants > 8 ||
      !Number.isSafeInteger(maxTransfers) || maxTransfers < 1) throw new ParticipantError('invalid');
  const transfers = new Map();

  function sweep(time) {
    for (const [id, entry] of transfers) if (entry.expiresAt <= time) transfers.delete(id);
  }

  function transfer(id) {
    if (!validToken(id)) throw new ParticipantError('invalid');
    sweep(now());
    const entry = transfers.get(id);
    if (!entry) throw new ParticipantError('missing');
    return entry;
  }

  function owner(entry, ownerHash) {
    if (!validToken(ownerHash) || !equal(entry.ownerHash, ownerHash)) throw new ParticipantError('forbidden');
    return entry.owner;
  }

  function member(entry, credential) {
    if (validToken(credential?.ownerHash) && credential.token === undefined) return owner(entry, credential.ownerHash);
    if (!validToken(credential?.token) || credential.ownerHash !== undefined) throw new ParticipantError('forbidden');
    const person = entry.members.get(digest(credential.token));
    if (!person) throw new ParticipantError('forbidden');
    return person;
  }

  function grant(person) { return { role: person.role, memberId: person.memberId }; }

  return {
    register({ id, ownerHash, expiresAt, mode = 'read' } = {}) {
      const time = now();
      if (!validToken(id) || !validToken(ownerHash) || !Number.isSafeInteger(expiresAt) || expiresAt <= time ||
          !validMode(mode)) throw new ParticipantError('invalid');
      sweep(time);
      if (transfers.has(id)) throw new ParticipantError('conflict');
      if (transfers.size >= maxTransfers) throw new ParticipantError('full');
      const creator = { role: 'owner', memberId: randomUUID(), name: '', lastSeen: time };
      transfers.set(id, { ownerHash, owner: creator, mode, expiresAt, members: new Map() });
      return grant(creator);
    },
    join(id, { name = '' } = {}) {
      const entry = transfer(id);
      if (typeof name !== 'string' || Buffer.byteLength(name, 'utf8') > 128) throw new ParticipantError('invalid');
      if (entry.members.size + 1 >= maxParticipants) throw new ParticipantError('full');
      const token = randomBytes(32).toString('hex');
      const person = { role: 'recipient', memberId: randomUUID(), name, lastSeen: now() };
      entry.members.set(digest(token), person);
      return { token, memberId: person.memberId };
    },
    authorize(id, credential, action) {
      if (action !== 'read' && action !== 'write' && action !== 'manage') throw new ParticipantError('invalid');
      const entry = transfer(id);
      const person = member(entry, credential);
      if (person.role === 'recipient' && (action === 'manage' || (action === 'write' && entry.mode !== 'exchange'))) {
        throw new ParticipantError('forbidden');
      }
      return grant(person);
    },
    heartbeat(id, credential) {
      const person = member(transfer(id), credential);
      person.lastSeen = now();
      return grant(person);
    },
    setMode(id, ownerHash, mode) {
      const entry = transfer(id);
      owner(entry, ownerHash);
      if (!validMode(mode)) throw new ParticipantError('invalid');
      entry.mode = mode;
      return { mode };
    },
    presence(id, ownerHash) {
      const entry = transfer(id);
      owner(entry, ownerHash);
      const time = now();
      const members = [entry.owner, ...entry.members.values()].map(person => ({
        ...grant(person), name: person.name, present: time < person.lastSeen + idleMs,
      }));
      return { mode: entry.mode, members };
    },
    leave(id, token) {
      const entry = transfer(id);
      if (!validToken(token) || !entry.members.delete(digest(token))) throw new ParticipantError('forbidden');
    },
  };
}
