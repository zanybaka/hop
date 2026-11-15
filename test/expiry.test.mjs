import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DAY, HOUR, confirmActivity, expiresAt, isExpired } from '../src/expiry.mjs';

const ordinary = { createdAt: 0, absoluteDeadline: DAY };
test('normal text expires at its absolute deadline and missing state stays missing', () => {
  assert.equal(expiresAt(ordinary), DAY);
  assert.equal(isExpired(ordinary, DAY - 1), false);
  assert.equal(isExpired(ordinary, DAY), true);
  assert.equal(expiresAt(null), null);
  assert.equal(confirmActivity(undefined, 0), null);
});

test('protected or file transfers renew only before expiry and within the absolute cap', () => {
  for (const flags of [{ protected: true }, { hasFiles: true }]) {
    const state = { ...ordinary, ...flags };
    assert.equal(expiresAt(state), HOUR);
    assert.equal(expiresAt(confirmActivity(state, HOUR - 1)), 2 * HOUR - 1);
    assert.equal(confirmActivity(state, HOUR), null);
    const active = { ...state, lastActivityAt: DAY - HOUR / 2 };
    assert.equal(expiresAt(confirmActivity(active, DAY - 1)), DAY);
    assert.equal(expiresAt(confirmActivity(active, DAY - HOUR)), DAY);
  }
});
