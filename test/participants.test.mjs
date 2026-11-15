import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createParticipants } from '../src/participants.mjs';

const id = 'a'.repeat(64);
const ownerHash = 'b'.repeat(64);
const wrongOwner = 'c'.repeat(64);
const setup = options => {
  const rights = createParticipants(options);
  const owner = rights.register({ id, ownerHash, expiresAt: options?.expiresAt ?? Date.now() + 60_000 });
  return { rights, owner };
};

test('server checks current write mode and management uses the same owner fingerprint after reconnection', () => {
  const { rights, owner } = setup();
  const first = rights.join(id, { name: 'Phone' });
  const recipient = { token: first.token };
  assert.equal(rights.authorize(id, recipient, 'read').memberId, first.memberId);
  assert.throws(() => rights.authorize(id, recipient, 'write'), { code: 'forbidden' });
  assert.throws(() => rights.authorize(id, recipient, 'manage'), { code: 'forbidden' });
  assert.throws(() => rights.setMode(id, first.token, 'exchange'), { code: 'forbidden' });
  assert.throws(() => rights.presence(id, wrongOwner), { code: 'forbidden' });
  assert.deepEqual(rights.authorize(id, { ownerHash }, 'write'), owner);
  assert.deepEqual(rights.authorize(id, { ownerHash }, 'manage'), owner);
  assert.throws(() => rights.authorize(id, {}, 'manage'), { code: 'forbidden' });
  rights.setMode(id, ownerHash, 'exchange');
  assert.equal(rights.authorize(id, recipient, 'write').memberId, first.memberId);
  rights.setMode(id, ownerHash, 'read');
  assert.throws(() => rights.authorize(id, recipient, 'write'), { code: 'forbidden' });
  const listed = rights.presence(id, ownerHash);
  assert.deepEqual(listed.members[1], { memberId: first.memberId, role: 'recipient', name: 'Phone', present: true });
  assert(!JSON.stringify(listed).includes(first.token));
  assert(!JSON.stringify(listed).includes(ownerHash));
});

test('eight grants include owner, idle grants resume, and leave makes room', () => {
  let time = 0;
  const { rights, owner } = setup({ now: () => time, idleMs: 10, expiresAt: 100 });
  const recipients = Array.from({ length: 7 }, () => rights.join(id));
  assert.throws(() => rights.join(id), { code: 'full' });
  assert.equal(rights.presence(id, ownerHash).members.filter(entry => entry.present).length, 8);
  time = 10;
  assert.equal(rights.presence(id, ownerHash).members.filter(entry => entry.present).length, 0);
  assert.throws(() => rights.join(id), { code: 'full' });
  assert.deepEqual(rights.heartbeat(id, { ownerHash }), owner);
  const { token, memberId } = recipients[0];
  assert.equal(rights.heartbeat(id, { token }).memberId, memberId);
  assert.equal(rights.presence(id, ownerHash).members.filter(entry => entry.present).length, 2);
  rights.leave(id, token);
  assert.throws(() => rights.authorize(id, { token }, 'read'), { code: 'forbidden' });
  assert.notEqual(rights.join(id).memberId, memberId);
  assert.equal(rights.presence(id, ownerHash).members.length, 8);
});

test('presence does not prolong transfer lifetime or overwrite ownership', () => {
  let time = 0;
  const { rights } = setup({ now: () => time, expiresAt: 100, maxTransfers: 1 });
  const { token } = rights.join(id);
  const another = { id: 'd'.repeat(64), expiresAt: 200, ownerHash };
  assert.throws(() => rights.register({ ...another, id, ownerHash: wrongOwner }), { code: 'conflict' });
  assert.throws(() => rights.register(another), { code: 'full' });
  time = 99;
  rights.heartbeat(id, { token });
  rights.heartbeat(id, { ownerHash });
  time = 100;
  assert.throws(() => rights.authorize(id, { token }, 'read'), { code: 'missing' });
  assert.doesNotThrow(() => rights.register(another));
});
