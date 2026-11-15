import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPairing } from '../src/pairing.mjs';

const opaque = /^[a-f0-9]{64}$/;

test('invitation is single-use and only its creator can approve a join', () => {
  const pairing = createPairing();
  const { invitation, owner, expiresAt } = pairing.offer();
  assert.match(invitation, opaque);
  assert.match(owner, opaque);
  assert.notEqual(invitation, owner);
  assert.deepEqual(pairing.status(owner), { state: 'offered', role: 'owner', expiresAt });
  assert.throws(() => pairing.status(invitation), { code: 'missing' });
  assert.throws(() => pairing.decide(owner, 'approved'), { code: 'conflict' });
  assert.throws(() => pairing.join(owner), { code: 'missing' });
  const { recipient } = pairing.join(invitation);
  assert.match(recipient, opaque);
  assert.notEqual(recipient, invitation);
  assert.notEqual(recipient, owner);
  assert.throws(() => pairing.join(invitation), { code: 'missing' });
  assert.throws(() => pairing.decide(recipient, 'approved'), { code: 'forbidden' });
  assert.throws(() => pairing.cancel(recipient), { code: 'forbidden' });
  assert.equal(pairing.status(owner).state, 'joined');
  assert.deepEqual(pairing.decide(owner, 'approved'), { state: 'approved', role: 'owner', expiresAt });
  assert.deepEqual(pairing.status(recipient), { state: 'approved', role: 'recipient', expiresAt });
  assert.throws(() => pairing.decide(owner, 'declined'), { code: 'conflict' });
  assert.throws(() => pairing.cancel(owner), { code: 'conflict' });
});

test('decline and cancellation are terminal, and owner actions stay scoped to one offer', () => {
  const pairing = createPairing();
  const cancelled = pairing.offer();
  const declined = pairing.offer();
  const joined = pairing.join(declined.invitation);
  assert.equal(pairing.cancel(cancelled.owner).state, 'cancelled');
  assert.throws(() => pairing.join(cancelled.invitation), { code: 'missing' });
  assert.equal(pairing.status(joined.recipient).state, 'joined');
  assert.equal(pairing.decide(declined.owner, 'declined').state, 'declined');
  assert.equal(pairing.status(joined.recipient).state, 'declined');
  assert.throws(() => pairing.decide(declined.owner, 'approved'), { code: 'conflict' });
  const last = pairing.offer();
  const recipient = pairing.join(last.invitation).recipient;
  pairing.cancel(last.owner);
  assert.equal(pairing.status(recipient).state, 'cancelled');
  assert.throws(() => pairing.decide(last.owner, 'approved'), { code: 'conflict' });
});

test('unused and joined offers expire at their fixed deadline, freeing memory slots', () => {
  let time = 0;
  const pairing = createPairing({ now: () => time, offerLifetime: 10, maxOffers: 2 });
  const { invitation: unused } = pairing.offer();
  const joined = pairing.offer();
  assert.throws(() => pairing.offer(), { code: 'full' });
  time = 9;
  const { recipient, expiresAt } = pairing.join(joined.invitation);
  assert.equal(expiresAt, 10);
  assert.equal(pairing.status(recipient).expiresAt, 10);
  assert.equal(pairing.decide(joined.owner, 'approved').expiresAt, 10);
  assert.equal(pairing.status(joined.owner).expiresAt, 10);
  time = 10;
  assert.throws(() => pairing.join(unused), { code: 'missing' });
  assert.throws(() => pairing.status(recipient), { code: 'missing' });
  assert.throws(() => pairing.status(joined.owner), { code: 'missing' });
  assert.equal(pairing.offer().expiresAt, 20);
});

test('only the approved pair exchanges an immutable offer followed by an answer', () => {
  let time = 0;
  const pairing = createPairing({ now: () => time, offerLifetime: 10 });
  const { invitation, owner } = pairing.offer();
  const { recipient } = pairing.join(invitation);
  const offer = { type: 'offer', sdp: 'v=0\r\n' };
  const answer = { type: 'answer', sdp: 'v=0\r\na=sendrecv\r\n' };
  assert.throws(() => pairing.writeSignal(owner, offer), { code: 'conflict' });
  assert.throws(() => pairing.readSignal(recipient), { code: 'conflict' });
  pairing.decide(owner, 'approved');
  assert.equal(pairing.readSignal(owner), null);
  assert.equal(pairing.readSignal(recipient), null);
  assert.throws(() => pairing.writeSignal(recipient, answer), { code: 'conflict' });
  assert.throws(() => pairing.writeSignal(recipient, offer), { code: 'forbidden' });
  assert.throws(() => pairing.writeSignal(owner, answer), { code: 'forbidden' });
  assert.deepEqual(pairing.writeSignal(owner, offer), { type: 'offer' });
  assert.deepEqual(pairing.writeSignal(owner, offer), { type: 'offer' });
  assert.throws(() => pairing.writeSignal(owner, { ...offer, sdp: 'different' }), { code: 'conflict' });
  assert.equal(pairing.readSignal(owner), null);
  assert.deepEqual(pairing.readSignal(recipient), offer);
  assert.deepEqual(pairing.writeSignal(recipient, answer), { type: 'answer' });
  assert.deepEqual(pairing.readSignal(owner), answer);
  const other = pairing.offer();
  const otherRecipient = pairing.join(other.invitation).recipient;
  pairing.decide(other.owner, 'approved');
  assert.equal(pairing.readSignal(otherRecipient), null);
  time = 10;
  assert.throws(() => pairing.readSignal(recipient), { code: 'missing' });
  assert.throws(() => pairing.writeSignal(owner, offer), { code: 'missing' });
});

test('signal accepts only the two specified fields and bounds UTF-8 size', () => {
  const pairing = createPairing();
  const { invitation, owner } = pairing.offer();
  const { recipient } = pairing.join(invitation);
  pairing.decide(owner, 'approved');
  for (const signal of [null, { type: 'offer', sdp: '' }, { type: 'offer', sdp: 'a', key: 'forbidden' },
    { type: 'candidate', sdp: 'a' }, { type: 'offer', sdp: 'я'.repeat(32769) }]) {
    assert.throws(() => pairing.writeSignal(owner, signal), { code: 'invalid' });
  }
  assert.equal(pairing.readSignal(recipient), null);
  const max = { type: 'offer', sdp: 'я'.repeat(32768) };
  assert.deepEqual(pairing.writeSignal(owner, max), { type: 'offer' });
  assert.deepEqual(pairing.readSignal(recipient), max);
});
