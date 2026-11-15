import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEditorState, editDraft, prepareSend, receiveVersion } from '../src/editor-state.mjs';

test('a clean recipient and the next reply send in one action', () => {
  const initial = createEditorState(0, { text: '', files: [] });
  const refreshed = receiveVersion(initial, 1, { text: 'incoming', files: [] });
  assert.equal(refreshed.draft.text, 'incoming');
  const reply = { text: 'reply', files: [] };
  assert.deepEqual(prepareSend(editDraft(refreshed, reply)).request, { version: 1, content: reply });
});

test('a newer publication preserves local attachments and resets earlier confirmation', () => {
  const local = { text: 'draft', files: [{ name: 'fixture.txt', blob: new Blob(['fixture']) }] };
  const edited = editDraft(createEditorState(1, { text: 'published', files: [] }), local);
  const updated = receiveVersion(edited, 2, { text: 'new', files: [] });
  assert.equal(updated.draft, local);
  const first = prepareSend(updated);
  assert.equal(first.request, null);
  assert.deepEqual(prepareSend(first.state).request, { version: 2, content: local });
  const refreshed = receiveVersion(first.state, 3, { text: 'newer', files: [] });
  assert.equal(prepareSend(refreshed).request, null);
  assert.equal(receiveVersion(refreshed, 2, { text: 'stale', files: [] }), refreshed);
});
